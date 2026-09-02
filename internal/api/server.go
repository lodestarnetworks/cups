package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lodestarnetworks/cups/internal/telemetry"
)

type SnapshotProvider interface {
	Snapshot() telemetry.Snapshot
}

type Config struct {
	AllowedOrigins []string
}

func NewHandler(provider SnapshotProvider, config Config) http.Handler {
	if provider == nil {
		panic("api: nil snapshot provider")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthHandler(provider))
	mux.HandleFunc("GET /api/v1/dashboard", dashboardHandler(provider))
	mux.HandleFunc("GET /api/v1/sgwc", sgwcHandler(provider))
	mux.HandleFunc("GET /api/v1/sgwu", sgwuHandler(provider))
	mux.HandleFunc("GET /api/v1/events", eventsHandler(provider))
	mux.HandleFunc("GET /metrics", metricsHandler(provider))
	mux.HandleFunc("OPTIONS /", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return securityHeaders(cors(config.AllowedOrigins, mux))
}

func dashboardHandler(provider SnapshotProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, provider.Snapshot())
	}
}

func sgwcHandler(provider SnapshotProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		snapshot := provider.Snapshot()
		writeJSON(w, http.StatusOK, struct {
			GeneratedAt time.Time      `json:"generatedAt"`
			Mode        string         `json:"mode"`
			Component   telemetry.SGWC `json:"component"`
		}{snapshot.GeneratedAt, snapshot.Mode, snapshot.SGWC})
	}
}

func sgwuHandler(provider SnapshotProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		snapshot := provider.Snapshot()
		writeJSON(w, http.StatusOK, struct {
			GeneratedAt time.Time      `json:"generatedAt"`
			Mode        string         `json:"mode"`
			Component   telemetry.SGWU `json:"component"`
		}{snapshot.GeneratedAt, snapshot.Mode, snapshot.SGWU})
	}
}

func eventsHandler(provider SnapshotProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snapshot := provider.Snapshot()
		limit := 20
		if raw := r.URL.Query().Get("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 1 || parsed > 200 {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be between 1 and 200"})
				return
			}
			limit = parsed
		}
		if len(snapshot.Events) > limit {
			snapshot.Events = snapshot.Events[:limit]
		}
		writeJSON(w, http.StatusOK, struct {
			GeneratedAt time.Time         `json:"generatedAt"`
			Mode        string            `json:"mode"`
			Events      []telemetry.Event `json:"events"`
		}{snapshot.GeneratedAt, snapshot.Mode, snapshot.Events})
	}
}

func healthHandler(provider SnapshotProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		snapshot := provider.Snapshot()
		components := healthComponents(snapshot)
		status := healthState(components)
		code := http.StatusOK
		if status == "down" {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, map[string]any{
			"status":      status,
			"generatedAt": snapshot.GeneratedAt,
			"mode":        snapshot.Mode,
			"components":  components,
		})
	}
}

func healthComponents(snapshot telemetry.Snapshot) map[string]telemetry.State {
	if snapshot.Mode == "live-sgwu" {
		return map[string]telemetry.State{"sgw-u": snapshot.SGWU.State}
	}
	return map[string]telemetry.State{
		"sgw-c": snapshot.SGWC.State,
		"sgw-u": snapshot.SGWU.State,
	}
}

func healthState(components map[string]telemetry.State) string {
	for _, state := range components {
		if state == telemetry.StateDown {
			return "down"
		}
	}
	for _, state := range components {
		if state != telemetry.StateHealthy {
			return "degraded"
		}
	}
	return "healthy"
}

func metricsHandler(provider SnapshotProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		snapshot := provider.Snapshot()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		writeMetric(w, "sgw_next_sgwc_active_sessions", "Current SGW-C session contexts.", float64(snapshot.SGWC.ActiveSessions))
		writeMetric(w, "sgw_next_sgwc_active_bearers", "Current SGW-C EPS bearer contexts.", float64(snapshot.SGWC.ActiveBearers))
		writeMetric(w, "sgw_next_sgwc_active_transactions", "Current in-flight GTPv2-C transactions.", float64(snapshot.SGWC.ActiveTransactions))
		writeMetric(w, "sgw_next_sgwc_retransmissions_total", "Observed GTPv2-C retransmissions.", float64(snapshot.SGWC.Retransmissions))
		writeMetric(w, "sgw_next_sgwc_control_socket_drops_total", "Packets dropped by SGW-C GTPv2-C or PFCP kernel receive queues.", float64(snapshot.SGWC.ControlSocketDrops))
		writeMetric(w, "sgw_next_sgwc_peer_restarts_total", "MME or PGW GTPv2-C restart-counter changes observed by SGW-C.", float64(snapshot.SGWC.PeerRestarts))
		writeMetric(w, "sgw_next_sgwc_peer_restart_purge_failures_total", "Peer-restart cleanup attempts that could not durably purge every stale control and user-plane session.", float64(snapshot.SGWC.PeerRestartPurgeFailures))
		durableState := 0.0
		if snapshot.SGWC.DurableStateEnabled {
			durableState = 1
		}
		tailRecovered := 0.0
		if snapshot.SGWC.StateTailRecovered {
			tailRecovered = 1
		}
		writeMetric(w, "sgw_next_sgwc_control_state_durable", "Durable SGW-C session ownership enabled (1 enabled, 0 volatile).", durableState)
		writeMetric(w, "sgw_next_sgwc_control_state_wal_bytes", "SGW-C durable journal size in bytes.", float64(snapshot.SGWC.StateWALBytes))
		writeMetric(w, "sgw_next_sgwc_control_state_wal_records_total", "SGW-C durable session transitions appended or recovered.", float64(snapshot.SGWC.StateWALRecords))
		writeMetric(w, "sgw_next_sgwc_control_state_starts_total", "SGW-C starts recorded in the durable journal.", float64(snapshot.SGWC.StateStarts))
		writeMetric(w, "sgw_next_sgwc_control_state_compactions_total", "Atomic SGW-C durable journal compactions completed by this process.", float64(snapshot.SGWC.StateCompactions))
		writeMetric(w, "sgw_next_sgwc_control_state_recovered_sessions", "SGW-C sessions recovered at this process start.", float64(snapshot.SGWC.RecoveredSessions))
		writeMetric(w, "sgw_next_sgwc_control_state_tail_recovered", "A partial final SGW-C journal record was safely truncated at this start.", tailRecovered)
		writeMetric(w, "sgw_next_sgwc_recovery_counter", "Current SGW-C GTPv2 recovery counter.", float64(snapshot.SGWC.RecoveryCounter))
		admissionDraining := 0.0
		if snapshot.SGWC.AdmissionDraining {
			admissionDraining = 1
		}
		writeMetric(w, "sgw_next_sgwc_admission_draining", "SGW-C admission state (1 draining, 0 ready).", admissionDraining)
		writeMetric(w, "sgw_next_sgwc_admission_transitions_total", "SGW-C admission ready/draining transitions.", float64(snapshot.SGWC.AdmissionTransitions))
		writeMetric(w, "sgw_next_sgwc_admission_check_errors_total", "SGW-C drain-file checks that failed closed.", float64(snapshot.SGWC.AdmissionCheckErrors))
		writeMetric(w, "sgw_next_sgwc_create_session_admission_rejections_total", "Create Session requests rejected while SGW-C was draining.", float64(snapshot.SGWC.AdmissionRejected))
		writeMetric(w, "sgw_next_sgwc_delete_session_context_not_found_reconciliations_total", "Delete Session procedures completed after the downstream PGW context was already absent.", float64(snapshot.SGWC.DeleteContextNotFound))
		usageDurable := 0.0
		if snapshot.SGWC.PFCPUsageDurable {
			usageDurable = 1
		}
		usageTailRecovered := 0.0
		if snapshot.SGWC.PFCPUsageWALTailRecovered {
			usageTailRecovered = 1
		}
		writeMetric(w, "sgw_next_sgwc_pfcp_usage_ledger_durable", "Durable SGW-C PFCP usage-report reconciliation enabled.", usageDurable)
		writeMetric(w, "sgw_next_sgwc_pfcp_usage_checkpoints", "Current duplicate-detection checkpoints in the SGW-C usage ledger.", float64(snapshot.SGWC.PFCPUsageCheckpoints))
		writeMetric(w, "sgw_next_sgwc_pfcp_usage_reports_accepted_total", "PFCP usage reports durably accepted by SGW-C.", float64(snapshot.SGWC.PFCPUsageAccepted))
		writeMetric(w, "sgw_next_sgwc_pfcp_usage_reports_duplicate_total", "Duplicate PFCP usage reports safely acknowledged by SGW-C.", float64(snapshot.SGWC.PFCPUsageDuplicates))
		writeMetric(w, "sgw_next_sgwc_pfcp_usage_sequence_gaps_total", "Out-of-order PFCP usage reports rejected by SGW-C.", float64(snapshot.SGWC.PFCPUsageSequenceGaps))
		writeMetric(w, "sgw_next_sgwc_pfcp_usage_sequence_conflicts_total", "Altered duplicate PFCP usage reports rejected by SGW-C.", float64(snapshot.SGWC.PFCPUsageConflicts))
		writeMetric(w, "sgw_next_sgwc_pfcp_usage_uplink_packets_total", "Uplink packets reported by SGW-U and accepted by SGW-C.", float64(snapshot.SGWC.PFCPUsageUplinkPackets))
		writeMetric(w, "sgw_next_sgwc_pfcp_usage_downlink_packets_total", "Downlink packets reported by SGW-U and accepted by SGW-C.", float64(snapshot.SGWC.PFCPUsageDownlinkPackets))
		writeMetric(w, "sgw_next_sgwc_pfcp_usage_uplink_bytes_total", "Uplink bytes reported by SGW-U and accepted by SGW-C.", float64(snapshot.SGWC.PFCPUsageUplinkBytes))
		writeMetric(w, "sgw_next_sgwc_pfcp_usage_downlink_bytes_total", "Downlink bytes reported by SGW-U and accepted by SGW-C.", float64(snapshot.SGWC.PFCPUsageDownlinkBytes))
		writeMetric(w, "sgw_next_sgwc_pfcp_usage_ledger_wal_bytes", "Current SGW-C PFCP usage-ledger journal size.", float64(snapshot.SGWC.PFCPUsageWALBytes))
		writeMetric(w, "sgw_next_sgwc_pfcp_usage_ledger_wal_records_total", "Durable SGW-C PFCP usage-ledger records.", float64(snapshot.SGWC.PFCPUsageWALRecords))
		writeMetric(w, "sgw_next_sgwc_pfcp_usage_ledger_compactions_total", "Atomic SGW-C PFCP usage-ledger compactions.", float64(snapshot.SGWC.PFCPUsageWALCompactions))
		writeMetric(w, "sgw_next_sgwc_pfcp_usage_ledger_tail_recovered", "Whether a partial SGW-C usage-ledger tail was safely recovered at startup.", usageTailRecovered)
		writeMetric(w, "sgw_next_sgwc_pfcp_usage_checkpoint_remove_failures_total", "Usage checkpoint tombstones that could not be persisted after session deletion.", float64(snapshot.SGWC.PFCPUsageRemoveFailures))
		writeMetric(w, "sgw_next_sgwc_pending_paging", "Current accepted DDNs awaiting a successful Modify Bearer.", float64(snapshot.SGWC.PendingPaging))
		writeDDNPagingHistograms(w, snapshot.SGWC.DDNPagingHistograms)
		fmt.Fprintf(w, "# HELP pfcp_association_state One-hot SGW-U PFCP association state.\n")
		fmt.Fprintf(w, "# TYPE pfcp_association_state gauge\n")
		for _, state := range []string{"associated", "grace", "reconciling", "unavailable"} {
			value := 0
			if snapshot.SGWU.PFCPAssociationPhase == state {
				value = 1
			}
			fmt.Fprintf(w, "pfcp_association_state{node=\"sgw-u\",state=\"%s\"} %d\n", state, value)
		}
		writeMetric(w, "pfcp_grace_seconds_remaining", "Seconds remaining before SGW-U PFCP grace expiry.", snapshot.SGWU.PFCPGraceSecondsRemaining)
		writeMetric(w, "sgw_next_sgwu_pfcp_grace_entries_total", "SGW-U PFCP grace entries.", float64(snapshot.SGWU.PFCPGraceEntries))
		writeMetric(w, "sgw_next_sgwu_pfcp_grace_expirations_total", "SGW-U PFCP grace expirations.", float64(snapshot.SGWU.PFCPGraceExpirations))
		writeMetric(w, "sgw_next_sgwu_pfcp_reconciliations_total", "Completed SGW-U PFCP reconciliations.", float64(snapshot.SGWU.PFCPReconciliations))
		writeMetric(w, "sgw_next_sgwu_pfcp_socket_drops_total", "Packets dropped by the SGW-U PFCP kernel receive queue.", float64(snapshot.SGWU.PFCPSocketDrops))
		writeMetric(w, "sgw_next_sgwu_pfcp_messages_received_total", "PFCP messages received by SGW-U.", float64(snapshot.SGWU.PFCPMessagesRX))
		writeMetric(w, "sgw_next_sgwu_pfcp_messages_sent_total", "PFCP messages sent by SGW-U.", float64(snapshot.SGWU.PFCPMessagesTX))
		writeMetric(w, "sgw_next_sgwu_pfcp_errors_total", "Malformed, timed-out, queue-dropped, or socket-dropped SGW-U PFCP messages.", float64(snapshot.SGWU.PFCPErrors))
		writeMetric(w, "sgw_next_sgwu_pfcp_sessions", "Current SGW-U PFCP sessions.", float64(snapshot.SGWU.PFCPSessions))
		writeMetric(w, "sgw_next_sgwu_sessions_installed_total", "SGW-U sessions installed in this process.", float64(snapshot.SGWU.SessionsInstalledTotal))
		writeMetric(w, "sgw_next_sgwu_sessions_removed_total", "SGW-U sessions removed in this process.", float64(snapshot.SGWU.SessionsRemovedTotal))
		writeMetric(w, "sgw_next_sgwu_pdrs", "Installed SGW-U packet detection rules.", float64(snapshot.SGWU.PDRs))
		writeMetric(w, "sgw_next_sgwu_fars", "Installed SGW-U forwarding action rules.", float64(snapshot.SGWU.FARs))
		fmt.Fprintf(w, "# HELP sgw_next_sgwu_gtpu_bits_per_second Current GTP-U bit rate by direction.\n")
		fmt.Fprintf(w, "# TYPE sgw_next_sgwu_gtpu_bits_per_second gauge\n")
		fmt.Fprintf(w, "sgw_next_sgwu_gtpu_bits_per_second{direction=\"uplink\"} %d\n", snapshot.SGWU.UplinkBitsPerSecond)
		fmt.Fprintf(w, "sgw_next_sgwu_gtpu_bits_per_second{direction=\"downlink\"} %d\n", snapshot.SGWU.DownlinkBitsPerSecond)
		writeMetric(w, "sgw_next_sgwu_packets_per_second", "Current SGW-U packet forwarding rate.", float64(snapshot.SGWU.PacketsPerSecond))
		writeMetric(w, "sgw_next_sgwu_forwarded_packets_total", "GTP-U packets successfully forwarded by SGW-U in this process.", float64(snapshot.SGWU.ForwardedPackets))
		writeMetric(w, "sgw_next_sgwu_forwarded_bytes_total", "Inner GTP-U bytes successfully forwarded by SGW-U in this process.", float64(snapshot.SGWU.ForwardedBytes))
		lastTrafficTimestamp := float64(0)
		if snapshot.SGWU.LastTrafficAt != nil {
			lastTrafficTimestamp = float64(snapshot.SGWU.LastTrafficAt.Unix())
		}
		writeMetric(w, "sgw_next_sgwu_last_forwarded_packet_timestamp_seconds", "Unix timestamp of the most recently observed successfully forwarded GTP-U packet, or zero before first traffic.", lastTrafficTimestamp)
		writeDirectionalPacketMetrics(w, snapshot.SGWU)
		writeLatencyHistogram(w, "sgw_next_sgwu_processing_latency_seconds", "Internal SGW-U processing latency from ingress to successful egress.", snapshot.SGWU.LatencyHistogram)
		writeMetric(w, "sgw_next_sgwu_processing_latency_seconds_p50", "Approximate p50 internal SGW-U processing latency.", snapshot.SGWU.P50LatencyMillis/1_000)
		writeMetric(w, "sgw_next_sgwu_processing_latency_seconds_p99", "Approximate p99 internal SGW-U processing latency.", snapshot.SGWU.P99LatencyMillis/1_000)
		writeMetric(w, "sgw_next_sgwu_processing_latency_seconds_p999", "Approximate p99.9 internal SGW-U processing latency.", snapshot.SGWU.P999LatencyMillis/1_000)
		writeMetric(w, "sgw_next_sgwu_processing_latency_seconds_max", "Maximum observed internal SGW-U processing latency.", snapshot.SGWU.MaxLatencyMillis/1_000)
		writeMetric(w, "sgw_next_sgwu_forwarding_p95_milliseconds", "Approximate p95 SGW-U forwarding-handler latency for the active dataplane backend.", snapshot.SGWU.P95LatencyMillis)
		writeMetric(w, "sgw_next_sgwu_access_socket_drops_total", "Packets dropped by the SGW-U S1-U kernel receive queue.", float64(snapshot.SGWU.AccessSocketDrops))
		writeMetric(w, "sgw_next_sgwu_core_socket_drops_total", "Packets dropped by the SGW-U S5-U kernel receive queue.", float64(snapshot.SGWU.CoreSocketDrops))
		writeMetric(w, "sgw_next_sgwu_unknown_teids_total", "GTP-U packets received with an unknown TEID.", float64(snapshot.SGWU.UnknownTEIDs))
		writeMetric(w, "sgw_next_sgwu_drop_no_session_total", "GTP-U packets dropped because no PFCP session matched the TEID.", float64(snapshot.SGWU.UnknownTEIDs))
		writeMetric(w, "sgw_next_sgwu_drop_malformed_total", "Malformed GTP-U packets dropped by SGW-U.", float64(snapshot.SGWU.MalformedPackets))
		writeMetric(w, "sgw_next_sgwu_drop_queue_full_total", "Packets dropped by bounded SGW-U internal or transmit queues.", float64(snapshot.SGWU.QueueFullDrops))
		writeMetric(w, "sgw_next_sgwu_unauthorized_peers_total", "GTP-U packets dropped from non-allowlisted peer addresses.", float64(snapshot.SGWU.UnauthorizedPeers))
		writeMetric(w, "sgw_next_sgwu_downlink_reports_total", "Idle-downlink PFCP report triggers queued by the user plane.", float64(snapshot.SGWU.DownlinkReports))
		writeMetric(w, "sgw_next_sgwu_buffered_packets", "Packets currently retained for idle LTE bearers.", float64(snapshot.SGWU.BufferedPackets))
		writeMetric(w, "sgw_next_sgwu_buffered_bytes", "Bytes currently retained for idle LTE bearers.", float64(snapshot.SGWU.BufferedBytes))
		writeMetric(w, "sgw_next_sgwu_buffer_enqueued_total", "Downlink packets accepted into bounded bearer buffers.", float64(snapshot.SGWU.BufferEnqueued))
		writeMetric(w, "sgw_next_sgwu_buffer_flushed_total", "Buffered downlink packets released after access activation.", float64(snapshot.SGWU.BufferFlushed))
		writeMetric(w, "sgw_next_sgwu_buffer_expired_total", "Buffered downlink packets discarded after their hold time.", float64(snapshot.SGWU.BufferExpired))
		writeMetric(w, "sgw_next_sgwu_buffer_overflow_drops_total", "Downlink packets discarded by per-bearer or per-QCI buffer limits.", float64(snapshot.SGWU.BufferOverflowDrops))
		writeMetric(w, "sgw_next_sgwu_buffer_purged_total", "Buffered packets discarded when PFCP sessions were deleted.", float64(snapshot.SGWU.BufferPurged))
		writeMetric(w, "sgw_next_sgwu_fast_path_fallback_packets_total", "GTP-U packets deliberately passed from TCX to the portable SGW-U path.", float64(snapshot.SGWU.FastPathFallbacks))
		writeMetric(w, "sgw_next_sgwu_fast_path_forwarded_packets_total", "GTP-U packets forwarded by the TCX fast path.", float64(snapshot.SGWU.FastPathForwardedPackets))
		writeMetric(w, "sgw_next_sgwu_qer_gate_drops_total", "GTP-U packets rejected by a closed PFCP QER gate.", float64(snapshot.SGWU.QERGateDrops))
		writeMetric(w, "sgw_next_sgwu_qer_rate_drops_total", "GTP-U packets rejected by PFCP QER maximum-bitrate policing.", float64(snapshot.SGWU.QERRateDrops))
		writeMetric(w, "sgw_next_sgwu_urr_metered_packets_total", "Post-QER packets observed by PFCP usage reporting rules; telemetry only.", float64(snapshot.SGWU.URRMeteredPackets))
		writeMetric(w, "sgw_next_sgwu_urr_metered_bytes_total", "Post-QER bytes observed by PFCP usage reporting rules; telemetry only.", float64(snapshot.SGWU.URRMeteredBytes))
		writeMetric(w, "sgw_next_sgwu_urr_threshold_events_total", "Telemetry reporting thresholds crossed by PFCP usage reporting rules.", float64(snapshot.SGWU.URRThresholdEvents))
		writeMetric(w, "sgw_next_sgwu_urr_active_meters", "Active PFCP usage meters that have observed traffic.", float64(snapshot.SGWU.URRActiveMeters))
		writeMetric(w, "sgw_next_sgwu_pfcp_usage_reports_generated_total", "PFCP usage reports generated by SGW-U.", float64(snapshot.SGWU.UsageReportsGenerated))
		writeMetric(w, "sgw_next_sgwu_pfcp_usage_reports_sent_total", "PFCP usage reports acknowledged by SGW-C.", float64(snapshot.SGWU.UsageReportsSent))
		writeMetric(w, "sgw_next_sgwu_pfcp_usage_reports_retried_total", "PFCP usage-report delivery retries by SGW-U.", float64(snapshot.SGWU.UsageReportsRetried))
		writeMetric(w, "sgw_next_sgwu_pfcp_usage_reports_failed_total", "PFCP usage-report delivery attempts that failed.", float64(snapshot.SGWU.UsageReportsFailed))
		writeMetric(w, "sgw_next_sgwu_pfcp_usage_reports_pending", "PFCP usage reports awaiting acknowledgement.", float64(snapshot.SGWU.UsageReportsPending))
		writeMetric(w, "sgw_next_sgwu_pfcp_usage_report_queue_full_total", "PFCP usage reports delayed by a full delivery queue.", float64(snapshot.SGWU.UsageReportQueueFull))
		writeMetric(w, "sgw_next_sgwu_pfcp_usage_counter_resets_total", "PFCP usage meters whose cumulative counters moved backwards.", float64(snapshot.SGWU.UsageCounterResets))
		writeMetric(w, "sgw_next_sgwu_pfcp_usage_tracked_urrs", "PFCP usage-reporting rules tracked by the report emitter.", float64(snapshot.SGWU.UsageTrackedURRs))
		writeMetric(w, "sgw_next_sgwu_fast_path_forwarded_bytes_total", "Inner GTP-U bytes forwarded by the TCX fast path.", float64(snapshot.SGWU.FastPathForwardedBytes))
		writeMetric(w, "sgw_next_sgwu_fast_path_sync_failures_total", "PFCP session changes that could not be installed in the TCX maps and remained on the portable path.", float64(snapshot.SGWU.FastPathSyncFailures))
		writeMetric(w, "sgw_next_sgwu_fast_path_rewrite_errors_total", "TCX packets dropped after a checksum or packet rewrite helper failed.", float64(snapshot.SGWU.FastPathRewriteErrors))
		writeMetric(w, "sgw_next_sgwu_fast_path_p95_milliseconds", "Sampled p95 TCX program parse, map lookup, and rewrite latency.", snapshot.SGWU.FastPathP95LatencyMillis)
		writeMetric(w, "sgw_next_sgwu_runtime_heap_objects_bytes", "Bytes occupied by live and unswept Go heap objects.", float64(snapshot.SGWU.RuntimeHeapObjectsBytes))
		writeMetric(w, "sgw_next_sgwu_runtime_goroutines", "Current Go goroutine count.", float64(snapshot.SGWU.RuntimeGoroutines))
		writeMetric(w, "sgw_next_sgwu_runtime_gc_pause_seconds_p99", "Approximate cumulative p99 Go GC stop-the-world pause.", snapshot.SGWU.RuntimeGCPauseP99Millis/1_000)
		writeMetric(w, "sgw_next_sgwu_runtime_gc_pause_seconds_max", "Largest observed Go GC stop-the-world pause bucket.", snapshot.SGWU.RuntimeGCPauseMaxMillis/1_000)
		writeLatencyHistogram(w, "sgw_next_sgwu_runtime_gc_pause_seconds", "Go GC stop-the-world pause distribution.", snapshot.SGWU.RuntimeGCPauseHistogram)
		fmt.Fprintf(w, "# HELP sgw_next_sgwu_buffer_class_packets Current buffered packets by QCI pool; qci=0 is the default pool.\n")
		fmt.Fprintf(w, "# TYPE sgw_next_sgwu_buffer_class_packets gauge\n")
		fmt.Fprintf(w, "# HELP sgw_next_sgwu_buffer_class_bytes Current buffered bytes by QCI pool; qci=0 is the default pool.\n")
		fmt.Fprintf(w, "# TYPE sgw_next_sgwu_buffer_class_bytes gauge\n")
		for _, class := range snapshot.SGWU.BufferClasses {
			fmt.Fprintf(w, "sgw_next_sgwu_buffer_class_packets{qci=\"%d\"} %d\n", class.QCI, class.CurrentPackets)
			fmt.Fprintf(w, "sgw_next_sgwu_buffer_class_bytes{qci=\"%d\"} %d\n", class.QCI, class.CurrentBytes)
		}
	}
}

func writeDirectionalPacketMetrics(w http.ResponseWriter, snapshot telemetry.SGWU) {
	fmt.Fprintln(w, "# HELP sgw_next_sgwu_packets_total SGW-U packets by direction and ingress/egress stage.")
	fmt.Fprintln(w, "# TYPE sgw_next_sgwu_packets_total counter")
	fmt.Fprintf(w, "sgw_next_sgwu_packets_total{direction=\"uplink\",stage=\"rx\"} %d\n", snapshot.UplinkRXPackets)
	fmt.Fprintf(w, "sgw_next_sgwu_packets_total{direction=\"uplink\",stage=\"tx\"} %d\n", snapshot.UplinkTXPackets)
	fmt.Fprintf(w, "sgw_next_sgwu_packets_total{direction=\"downlink\",stage=\"rx\"} %d\n", snapshot.DownlinkRXPackets)
	fmt.Fprintf(w, "sgw_next_sgwu_packets_total{direction=\"downlink\",stage=\"tx\"} %d\n", snapshot.DownlinkTXPackets)
	fmt.Fprintln(w, "# HELP sgw_next_sgwu_bytes_total SGW-U wire bytes by direction and ingress/egress stage.")
	fmt.Fprintln(w, "# TYPE sgw_next_sgwu_bytes_total counter")
	fmt.Fprintf(w, "sgw_next_sgwu_bytes_total{direction=\"uplink\",stage=\"rx\"} %d\n", snapshot.UplinkRXBytes)
	fmt.Fprintf(w, "sgw_next_sgwu_bytes_total{direction=\"uplink\",stage=\"tx\"} %d\n", snapshot.UplinkTXBytes)
	fmt.Fprintf(w, "sgw_next_sgwu_bytes_total{direction=\"downlink\",stage=\"rx\"} %d\n", snapshot.DownlinkRXBytes)
	fmt.Fprintf(w, "sgw_next_sgwu_bytes_total{direction=\"downlink\",stage=\"tx\"} %d\n", snapshot.DownlinkTXBytes)
}

func writeLatencyHistogram(w http.ResponseWriter, name, help string, buckets []telemetry.HistogramBucket) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s histogram\n", name)
	if len(buckets) == 0 {
		fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} 0\n%s_count 0\n", name, name)
		return
	}
	for index, bucket := range buckets {
		if index == len(buckets)-1 {
			fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, bucket.Count)
			continue
		}
		fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", name, bucket.UpperBoundSeconds, bucket.Count)
	}
	fmt.Fprintf(w, "%s_count %d\n", name, buckets[len(buckets)-1].Count)
}

func writeDDNPagingHistograms(w http.ResponseWriter, histograms []telemetry.DDNPagingHistogram) {
	fmt.Fprintln(w, "# HELP ddn_to_paging_response_seconds Time from SGW-C DDN dispatch to successful S11 Modify Bearer completion.")
	fmt.Fprintln(w, "# TYPE ddn_to_paging_response_seconds histogram")
	for _, histogram := range histograms {
		labels := fmt.Sprintf("qci=\"%d\",enb=\"%s\"", histogram.QCI, escapeMetricLabel(histogram.ENB))
		for _, bucket := range histogram.Buckets {
			le := strconv.FormatFloat(bucket.UpperBoundSeconds, 'g', -1, 64)
			fmt.Fprintf(w, "ddn_to_paging_response_seconds_bucket{%s,le=\"%s\"} %d\n", labels, le, bucket.Count)
		}
		fmt.Fprintf(w, "ddn_to_paging_response_seconds_bucket{%s,le=\"+Inf\"} %d\n", labels, histogram.Count)
		fmt.Fprintf(w, "ddn_to_paging_response_seconds_sum{%s} %g\n", labels, histogram.SumSeconds)
		fmt.Fprintf(w, "ddn_to_paging_response_seconds_count{%s} %d\n", labels, histogram.Count)
	}
}

func escapeMetricLabel(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return strings.ReplaceAll(value, "\"", "\\\"")
}

func writeMetric(w http.ResponseWriter, name, help string, value float64) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s gauge\n", name)
	fmt.Fprintf(w, "%s %g\n", name, value)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func cors(allowedOrigins []string, next http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		allowed[strings.TrimRight(origin, "/")] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimRight(r.Header.Get("Origin"), "/")
		if origin != "" {
			if _, ok := allowed[origin]; ok {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type")
				w.Header().Set("Vary", "Origin")
			}
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
