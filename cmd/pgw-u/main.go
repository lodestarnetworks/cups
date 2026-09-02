package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/lodestarnetworks/cups/internal/config"
	"github.com/lodestarnetworks/cups/internal/debugserver"
	pfcpassociation "github.com/lodestarnetworks/cups/internal/pfcp/association"
	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	"github.com/lodestarnetworks/cups/internal/pfcp/usagereport"
	"github.com/lodestarnetworks/cups/internal/pgwapi"
	"github.com/lodestarnetworks/cups/internal/pgwu/dataplane"
	"github.com/lodestarnetworks/cups/internal/pgwu/pfcpserver"
	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
	"github.com/lodestarnetworks/cups/internal/runtimeobs"
)

var version = "dev"

type runtimeConfig struct {
	value              config.PGWU
	retransmit         time.Duration
	associationTimeout time.Duration
	graceWindow        time.Duration
	qerBurstDuration   time.Duration
}

func main() {
	configPath := flag.String("config", "configs/pgw-u.lab.yaml", "path to strict YAML configuration")
	checkConfig := flag.Bool("check-config", false, "validate configuration and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	runtime, err := parseConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *checkConfig {
		fmt.Println("PGW-U configuration is valid")
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, runtime, logger); err != nil {
		logger.Error("PGW-U stopped", "error", err)
		os.Exit(1)
	}
}

func parseConfig(path string) (runtimeConfig, error) {
	value, err := config.LoadPGWU(path)
	if err != nil {
		return runtimeConfig{}, err
	}
	retransmit, err := config.Duration(value.RetransmitTimeout, "retransmit_timeout")
	if err != nil {
		return runtimeConfig{}, err
	}
	if _, err := config.AddrPort(value.ManagementListen, "management_listen"); err != nil {
		return runtimeConfig{}, err
	}
	associationTimeout, err := config.Duration(value.AssociationTimeout, "association_timeout")
	if err != nil {
		return runtimeConfig{}, err
	}
	graceWindow, err := config.Duration(value.GraceWindow, "association_grace_window")
	if err != nil {
		return runtimeConfig{}, err
	}
	qerBurstDuration, err := config.Duration(value.QERBurstDuration, "qer_burst_duration")
	if err != nil {
		return runtimeConfig{}, err
	}
	return runtimeConfig{value: value, retransmit: retransmit, associationTimeout: associationTimeout, graceWindow: graceWindow, qerBurstDuration: qerBurstDuration}, nil
}

func run(parent context.Context, runtime runtimeConfig, logger *slog.Logger) error {
	value := runtime.value
	debug, err := debugserver.New(value.DebugListen)
	if err != nil {
		return err
	}
	runtimeSampler := runtimeobs.NewSampler()
	pfcpListen, _ := config.AddrPort(value.PFCPListen, "pfcp_listen")
	pfcpAdvertise, _ := config.Addr(value.PFCPAdvertise, "pfcp_advertise")
	allowedPGWC, _ := config.Addrs(value.AllowedPGWC, "allowed_pgwc")
	s5, _ := config.AddrPort(value.S5GTPUListen, "s5_gtpu_listen")
	qci1S5, _ := config.AddrPort(value.QCI1S5GTPUListen, "qci1_s5_gtpu_listen")
	allowedSGWU, _ := config.Addrs(value.AllowedSGWU, "allowed_sgwu")
	started := time.Now().UTC()
	transport := pfcptransport.DefaultConfig()
	transport.RetransmitTimeout = runtime.retransmit
	transport.MaxRetransmits = value.MaxRetransmits
	var ruleStore *rules.Store
	var backend dataplane.Backend
	var stateWAL *rules.WAL
	var recovered []rules.Session
	if value.StateFile != "" {
		stateWAL, recovered, err = rules.OpenWAL(value.StateFile, value.StateWALMaxBytes)
		if err != nil {
			return err
		}
	}
	closeStateOnError := func(cause error) error {
		if stateWAL != nil {
			return errors.Join(cause, stateWAL.Close())
		}
		return cause
	}
	var statePersister rules.Persister
	if stateWAL != nil {
		statePersister = stateWAL
	}
	apnSessions, err := newPGWUAPNSessionTracker(value)
	if err != nil {
		return closeStateOnError(err)
	}
	switch value.DatapathBackend {
	case "kernel-gtp":
		uePools, poolErr := buildUEPools(value)
		if poolErr != nil {
			return closeStateOnError(poolErr)
		}
		kernel, openErr := dataplane.OpenKernel(dataplane.KernelConfig{
			S5: s5, AllowedSGWPeers: allowedSGWU, TunnelName: value.TunnelName,
			OwnershipFile: value.KernelGTPOwnerFile,
			QCI1S5:        qci1S5, QCI1TunnelName: value.QCI1TunnelName,
			QCI1OwnershipFile: value.QCI1KernelGTPOwnerFile,
			QCI1RouteTable:    value.QCI1RouteTable, QCI1RulePriority: value.QCI1RulePriority,
			QCI1FirewallMark: value.QCI1FirewallMark, QCI1FirewallMask: value.QCI1FirewallMask,
			UEPools:  uePools,
			HashSize: value.KernelGTPHashSize, MTU: value.KernelGTPMTU,
			SocketBufferBytes: value.SocketBufferBytes, MaxSessions: value.MaxSessions,
			MaxPolicyFilters: value.MaxPolicyFilters, QERBurstDuration: runtime.qerBurstDuration,
		})
		if openErr != nil {
			return closeStateOnError(openErr)
		}
		backend = kernel
		ruleStore = rules.NewStoreWithParticipants(value.MaxSessions, kernel, statePersister)
		if err := ruleStore.Restore(recovered); err != nil {
			_ = backend.Close()
			return closeStateOnError(fmt.Errorf("restore durable PGW-U sessions: %w", err))
		}
	case "userspace-development":
		ruleStore = rules.NewStoreWithParticipants(value.MaxSessions, nil, statePersister)
		if err := ruleStore.Restore(recovered); err != nil {
			return closeStateOnError(fmt.Errorf("restore durable PGW-U sessions: %w", err))
		}
		backend, err = dataplane.Listen(dataplane.Config{
			S5: s5, AllowedSGWPeers: allowedSGWU, TunnelName: value.TunnelName,
			SocketBufferBytes: value.SocketBufferBytes, MaxPacketSize: value.MaxPacketSize,
			QERBurstDuration: runtime.qerBurstDuration,
		}, ruleStore)
		if err != nil {
			return closeStateOnError(err)
		}
	default:
		return closeStateOnError(fmt.Errorf("unsupported PGW-U datapath backend %q", value.DatapathBackend))
	}
	observers := pgwuObserverSet{apnSessions}
	if portable, ok := backend.(*dataplane.Forwarder); ok {
		observers = append(observers, portable)
	}
	ruleStore.SetObserver(observers)
	if kernel, ok := backend.(*dataplane.KernelForwarder); ok {
		recovery := kernel.RecoveryReport()
		if recovery.LinkRemoved || recovery.PeerFilterRemoved || recovery.PolicyRuleRemoved {
			logger.Warn("recovered stale PGW-U kernel resources after an unclean stop",
				"gtp_link_removed", recovery.LinkRemoved, "peer_filter_removed", recovery.PeerFilterRemoved,
				"policy_rule_removed", recovery.PolicyRuleRemoved)
		}
	}
	server, err := pfcpserver.New(pfcpserver.Config{
		Listen: pfcpListen, Advertise: pfcpAdvertise, UserIP: s5.Addr(), DedicatedUserIP: qci1S5.Addr(),
		AllowedCP: allowedPGWC, StartedAt: started, AssociationTimeout: runtime.associationTimeout,
		GraceWindow: runtime.graceWindow, EnterpriseID: value.PFCPEnterpriseID, Transport: transport,
		OnError: func(event pfcpserver.ErrorEvent) {
			logger.Warn("PGW-U PFCP operation rejected", "procedure", event.Procedure, "peer", event.Peer, "reason", boundedError(event.Err))
		},
	}, ruleStore)
	if err != nil {
		_ = backend.Close()
		return closeStateOnError(err)
	}
	if err := server.SetUsageSource(func() []usagereport.Measurement {
		current := backend.Usage()
		out := make([]usagereport.Measurement, 0, len(current))
		for _, measurement := range current {
			out = append(out, usagereport.Measurement{
				UPSEID: measurement.UPSEID, URRID: measurement.URRID,
				UplinkPackets: measurement.UplinkPackets, DownlinkPackets: measurement.DownlinkPackets,
				UplinkBytes: measurement.UplinkBytes, DownlinkBytes: measurement.DownlinkBytes,
				ThresholdEvents: measurement.ThresholdEvents,
				FirstPacket:     measurement.FirstPacket, LastPacket: measurement.LastPacket,
			})
		}
		return out
	}); err != nil {
		_ = server.Close()
		_ = backend.Close()
		return closeStateOnError(err)
	}
	handler := pgwapi.NewHandler(func() pgwapi.Snapshot {
		associated, status, associationMetrics := pfcpMetrics(server, value.AllowedPGWC[0])
		packet := backend.Counters()
		pfcpCounters := server.Counters()
		pfcpTransportCounters := server.TransportCounters()
		lifecycle := ruleStore.LifecycleCounters()
		runtimeSnapshot := runtimeSampler.Snapshot()
		apnMetrics, trackedSessions, unmatchedSessions := apnSessions.Metrics()
		metrics := append(associationMetrics, apnMetrics...)
		metrics = append(metrics, []pgwapi.Metric{
			{Name: "lodestar_pgwu_apn_session_tracking_drift", Help: "Absolute difference between the PGW-U rule store and APN telemetry tracker; must remain zero.", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: float64(absoluteDifference(uint64(ruleStore.Count()), uint64(trackedSessions)))},
			{Name: "lodestar_pgwu_sessions_unmatched_pool", Help: "Committed PGW-U sessions outside every configured APN address pool; must remain zero.", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: float64(unmatchedSessions)},
			{Name: "lodestar_pgwu_sessions_installed_total", Help: "PGW-U sessions installed or restored in this process.", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(lifecycle.Installed)},
			{Name: "lodestar_pgwu_sessions_removed_total", Help: "PGW-U sessions removed in this process.", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(lifecycle.Removed)},
			{Name: "lodestar_pgwu_pfcp_messages_received_total", Help: "PFCP messages received by PGW-U.", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(pfcpTransportCounters.Received)},
			{Name: "lodestar_pgwu_pfcp_messages_sent_total", Help: "PFCP messages sent by PGW-U.", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(pfcpTransportCounters.Sent)},
			{Name: "lodestar_pgwu_pfcp_errors_total", Help: "Malformed, timed-out, queue-dropped, or socket-dropped PGW-U PFCP messages.", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(pfcpTransportCounters.Malformed + pfcpTransportCounters.TimedOut + pfcpTransportCounters.WorkerDrops + pfcpTransportCounters.SocketDrops)},
			{Name: "lodestar_pgwu_pfcp_grace_entries_total", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(pfcpCounters.GraceEntries)},
			{Name: "lodestar_pgwu_pfcp_grace_expirations_total", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(pfcpCounters.GraceExpirations)},
			{Name: "lodestar_pgwu_pfcp_reconciliations_total", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(pfcpCounters.Reconciliations)},
			{Name: "lodestar_pgwu_pfcp_socket_drops_total", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(pfcpTransportCounters.SocketDrops)},
			{Name: "lodestar_pgwu_kernel_recoveries_total", Help: "Owned stale kernel resources recovered after an unclean PGW-U stop.", Type: "counter", Labels: map[string]string{"node": "pgw-u", "resource": "gtp_link"}, Value: float64(packet.RecoveredGTPLinks)},
			{Name: "lodestar_pgwu_kernel_recoveries_total", Help: "Owned stale kernel resources recovered after an unclean PGW-U stop.", Type: "counter", Labels: map[string]string{"node": "pgw-u", "resource": "peer_firewall"}, Value: float64(packet.RecoveredFirewalls)},
			{Name: "lodestar_pgwu_kernel_recoveries_total", Help: "Owned stale kernel resources recovered after an unclean PGW-U stop.", Type: "counter", Labels: map[string]string{"node": "pgw-u", "resource": "policy_rule"}, Value: float64(packet.RecoveredPolicyRules)},
		}...)
		metrics = append(metrics,
			[]pgwapi.Metric{
				{Name: "lodestar_pgwu_forwarded_packets_total", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.ForwardedPackets)},
				{Name: "lodestar_pgwu_packets_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "direction": "uplink", "stage": "rx"}, Value: float64(packet.UplinkRXPackets)},
				{Name: "lodestar_pgwu_packets_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "direction": "uplink", "stage": "tx"}, Value: float64(packet.UplinkTXPackets)},
				{Name: "lodestar_pgwu_packets_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "direction": "downlink", "stage": "rx"}, Value: float64(packet.DownlinkRXPackets)},
				{Name: "lodestar_pgwu_packets_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "direction": "downlink", "stage": "tx"}, Value: float64(packet.DownlinkTXPackets)},
				{Name: "lodestar_pgwu_bytes_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "direction": "uplink", "stage": "rx"}, Value: float64(packet.UplinkRXBytes)},
				{Name: "lodestar_pgwu_bytes_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "direction": "uplink", "stage": "tx"}, Value: float64(packet.UplinkTXBytes)},
				{Name: "lodestar_pgwu_bytes_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "direction": "downlink", "stage": "rx"}, Value: float64(packet.DownlinkRXBytes)},
				{Name: "lodestar_pgwu_bytes_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "direction": "downlink", "stage": "tx"}, Value: float64(packet.DownlinkTXBytes)},
				{Name: "lodestar_pgwu_uplink_bytes_total", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.UplinkBytes)},
				{Name: "lodestar_pgwu_downlink_bytes_total", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.DownlinkBytes)},
				{Name: "lodestar_pgwu_forwarding_latency_milliseconds", Type: "gauge", Labels: map[string]string{"node": "pgw-u", "quantile": "0.95"}, Value: float64(packet.P95LatencyMicros) / 1000},
				{Name: "lodestar_pgwu_processing_latency_quantile_seconds", Type: "gauge", Labels: map[string]string{"node": "pgw-u", "quantile": "0.50"}, Value: float64(packet.P50LatencyMicros) / 1_000_000},
				{Name: "lodestar_pgwu_processing_latency_quantile_seconds", Type: "gauge", Labels: map[string]string{"node": "pgw-u", "quantile": "0.99"}, Value: float64(packet.P99LatencyMicros) / 1_000_000},
				{Name: "lodestar_pgwu_processing_latency_quantile_seconds", Type: "gauge", Labels: map[string]string{"node": "pgw-u", "quantile": "0.999"}, Value: float64(packet.P999LatencyMicros) / 1_000_000},
				{Name: "lodestar_pgwu_processing_latency_seconds_max", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.MaxLatencyMicros) / 1_000_000},
				{Name: "lodestar_pgwu_dropped_packets_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "reason": "unknown_teid"}, Value: float64(packet.UnknownTEIDs)},
				{Name: "lodestar_pgwu_dropped_packets_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "reason": "tft_unmatched"}, Value: float64(packet.TFTUnmatched)},
				{Name: "lodestar_pgwu_dropped_packets_total", Help: "Non-initial IPv4 fragments dropped because no current first-fragment bearer decision existed.", Type: "counter", Labels: map[string]string{"node": "pgw-u", "reason": "fragment_without_decision"}, Value: float64(packet.FragmentDrops)},
				{Name: "lodestar_pgwu_dropped_packets_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "reason": "unknown_ue_address"}, Value: float64(packet.UnknownUEAddresses)},
				{Name: "lodestar_pgwu_dropped_packets_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "reason": "unauthorized_peer"}, Value: float64(packet.UnauthorizedPeers)},
				{Name: "lodestar_pgwu_dropped_packets_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "reason": "malformed_gtp"}, Value: float64(packet.MalformedGTP)},
				{Name: "lodestar_pgwu_drop_no_session_total", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.UnknownTEIDs + packet.UnknownUEAddresses)},
				{Name: "lodestar_pgwu_drop_malformed_total", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.MalformedGTP + packet.MalformedIP)},
				{Name: "lodestar_pgwu_drop_queue_full_total", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.QueueFullDrops)},
				{Name: "lodestar_pgwu_dropped_packets_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "reason": "malformed_ip"}, Value: float64(packet.MalformedIP)},
				{Name: "lodestar_pgwu_dropped_packets_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "reason": "spoofed_source"}, Value: float64(packet.SpoofedSources)},
				{Name: "lodestar_pgwu_dropped_packets_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "reason": "closed_gate"}, Value: float64(packet.ClosedGates)},
				{Name: "lodestar_pgwu_dropped_packets_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "reason": "qer_rate_exceeded"}, Value: float64(packet.QERRateDrops)},
				{Name: "lodestar_pgwu_dropped_packets_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "reason": "write_error"}, Value: float64(packet.WriteErrors)},
				{Name: "lodestar_pgwu_qer_gate_drops_total", Help: "Packets rejected by a closed PFCP QER gate.", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.QERGateDrops)},
				{Name: "lodestar_pgwu_qer_rate_drops_total", Help: "Packets rejected by PFCP QER maximum-bitrate policing.", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.QERRateDrops)},
				{Name: "lodestar_pgwu_urr_metered_packets_total", Help: "Post-QER packets observed by telemetry-only PFCP URRs.", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.URRMeteredPackets)},
				{Name: "lodestar_pgwu_urr_metered_bytes_total", Help: "Post-QER bytes observed by telemetry-only PFCP URRs.", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.URRMeteredBytes)},
				{Name: "lodestar_pgwu_urr_threshold_events_total", Help: "Telemetry volume thresholds crossed; never a quota or forwarding gate.", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.URRThresholdEvents)},
				{Name: "lodestar_pgwu_urr_active_meters", Help: "Active per-session PFCP URR meters.", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.URRActiveMeters)},
				{Name: "lodestar_pgwu_pfcp_usage_reports_total", Help: "PFCP usage-report delivery lifecycle.", Type: "counter", Labels: map[string]string{"node": "pgw-u", "result": "generated"}, Value: float64(pfcpCounters.UsageReportsGenerated)},
				{Name: "lodestar_pgwu_pfcp_usage_reports_total", Help: "PFCP usage-report delivery lifecycle.", Type: "counter", Labels: map[string]string{"node": "pgw-u", "result": "sent"}, Value: float64(pfcpCounters.UsageReportsSent)},
				{Name: "lodestar_pgwu_pfcp_usage_reports_total", Help: "PFCP usage-report delivery lifecycle.", Type: "counter", Labels: map[string]string{"node": "pgw-u", "result": "retried"}, Value: float64(pfcpCounters.UsageReportsRetried)},
				{Name: "lodestar_pgwu_pfcp_usage_reports_total", Help: "PFCP usage-report delivery lifecycle.", Type: "counter", Labels: map[string]string{"node": "pgw-u", "result": "failed"}, Value: float64(pfcpCounters.UsageReportsFailed)},
				{Name: "lodestar_pgwu_pfcp_usage_reports_pending", Help: "PFCP usage reports awaiting PGW-C acknowledgement.", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: float64(pfcpCounters.UsageReportsPending)},
				{Name: "lodestar_pgwu_pfcp_usage_report_queue_full_total", Help: "PFCP usage reports delayed by a full delivery queue.", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(pfcpCounters.UsageReportQueueFull)},
				{Name: "lodestar_pgwu_pfcp_usage_counter_resets_total", Help: "PFCP usage meters whose cumulative counters moved backwards.", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(pfcpCounters.UsageCounterResets)},
				{Name: "lodestar_pgwu_pfcp_usage_tracked_urrs", Help: "PFCP usage-reporting rules tracked by the report emitter.", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: float64(pfcpCounters.UsageTrackedURRs)},
				{Name: "lodestar_pgwu_qci1_route_packets_total", Help: "QCI 1 downlink packets accepted after nftables policy routing selected the dedicated GTP device.", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.QCI1RoutePackets)},
				{Name: "lodestar_pgwu_qci1_contexts", Help: "Active QCI 1 kernel policy/context generations.", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.ActiveQCI1Contexts)},
				{Name: "lodestar_pgwu_qci1_tft_sessions", Help: "Active UE entries in the nftables QCI 1 verdict map.", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.ActiveQCI1Sessions)},
				{Name: "lodestar_pgwu_qci1_tft_rules", Help: "Active expanded nftables downlink TFT rules.", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.ActiveTFTFilters)},
				{Name: "lodestar_pgwu_qci1_tft_context_drift", Help: "Absolute difference between active QCI 1 context generations and nftables UE dispatch entries; must remain zero.", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: float64(absoluteDifference(packet.ActiveQCI1Contexts, packet.ActiveQCI1Sessions))},
				{Name: "lodestar_pgwu_qci1_tft_sync_errors_total", Help: "Failed transactional nftables classifier updates.", Type: "counter", Labels: map[string]string{"node": "pgw-u"}, Value: float64(packet.TFTSyncErrors)},
				{Name: "lodestar_pgwu_pfcp_sessions_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "operation": "established"}, Value: float64(pfcpCounters.SessionsEstablished)},
				{Name: "lodestar_pgwu_pfcp_sessions_total", Type: "counter", Labels: map[string]string{"node": "pgw-u", "operation": "deleted"}, Value: float64(pfcpCounters.SessionsDeleted)},
				{Name: "lodestar_pgwu_runtime_heap_objects_bytes", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: float64(runtimeSnapshot.HeapObjectsBytes)},
				{Name: "lodestar_pgwu_runtime_goroutines", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: float64(runtimeSnapshot.Goroutines)},
				{Name: "lodestar_pgwu_runtime_gc_pause_quantile_seconds", Type: "gauge", Labels: map[string]string{"node": "pgw-u", "quantile": "0.99"}, Value: runtimeSnapshot.GCPauseP99Seconds},
				{Name: "lodestar_pgwu_runtime_gc_pause_seconds_max", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: runtimeSnapshot.GCPauseMaxSeconds},
			}...,
		)
		capabilities := make(map[string]bool, len(backend.Capabilities()))
		metrics = append(metrics, pgwapi.Metric{
			Name: "lodestar_pgwu_dataplane_info", Help: "Selected PGW-U dataplane backend.", Type: "gauge",
			Labels: map[string]string{"node": "pgw-u", "mode": backend.Mode()}, Value: 1,
		})
		for _, capability := range backend.Capabilities() {
			capabilities[capability.Name] = capability.Supported
			value := float64(0)
			if capability.Supported {
				value = 1
			}
			metrics = append(metrics, pgwapi.Metric{
				Name: "lodestar_pgwu_dataplane_capability", Help: "Whether the selected dataplane implements a required capability.", Type: "gauge",
				Labels: map[string]string{"node": "pgw-u", "mode": backend.Mode(), "capability": capability.Name}, Value: value,
			})
		}
		if stateWAL != nil {
			state := stateWAL.Stats()
			recoveredTail := float64(0)
			if state.RecoveredTail {
				recoveredTail = 1
			}
			metrics = append(metrics,
				pgwapi.Metric{Name: "lodestar_pgwu_state_wal_bytes", Help: "Current durable PGW-U WAL size.", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: float64(state.Bytes)},
				pgwapi.Metric{Name: "lodestar_pgwu_state_wal_records", Help: "Valid durable PGW-U WAL records.", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: float64(state.Records)},
				pgwapi.Metric{Name: "lodestar_pgwu_state_wal_tail_recovered", Help: "Whether a partial crash-tail record was safely truncated at startup.", Type: "gauge", Labels: map[string]string{"node": "pgw-u"}, Value: recoveredTail},
			)
		}
		return pgwapi.Snapshot{
			Component: "pgw-u", Healthy: associated, Status: status, StartedAt: started,
			Datapath: backend.Mode(), Capabilities: capabilities, Metrics: metrics,
			Histograms: []pgwapi.Histogram{
				pgwuLatencyHistogram(packet.LatencyBuckets),
				pgwuRuntimeHistogram(runtimeSnapshot.GCPauseBuckets, runtimeSnapshot.GCPauseCount),
			},
		}
	})
	httpServer := &http.Server{
		Addr: value.ManagementListen, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	errCh := make(chan error, 4)
	go func() { errCh <- server.Serve(ctx) }()
	go func() { errCh <- backend.Serve(ctx) }()
	go func() {
		err := httpServer.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	go func() { errCh <- debug.Serve() }()
	go runtimeSampler.Run(ctx, time.Second)
	unsupported := make([]string, 0)
	for _, capability := range backend.Capabilities() {
		if !capability.Supported {
			unsupported = append(unsupported, capability.Name+": "+capability.Detail)
		}
	}
	logger.Info("PGW-U started", "datapath", backend.Mode(), "s5u", backend.S5Addr(), "sxb", server.LocalAddr(), "interface", backend.TunnelName(), "management", value.ManagementListen, "debug", value.DebugListen)
	if len(unsupported) > 0 {
		logger.Warn("PGW-U datapath has unsupported capabilities", "datapath", backend.Mode(), "unsupported", unsupported)
	}

	var runErr error
	select {
	case <-parent.Done():
	case runErr = <-errCh:
		if runErr != nil {
			cancel()
		}
	}
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	httpErr := httpServer.Shutdown(shutdownCtx)
	debugErr := debug.Shutdown(shutdownCtx)
	closeErr := errors.Join(server.Close(), backend.Close())
	if stateWAL != nil {
		closeErr = errors.Join(closeErr, stateWAL.Close())
	}
	logger.Info("PGW-U shutdown complete")
	return errors.Join(runErr, httpErr, debugErr, closeErr)
}

func boundedError(err error) string {
	if err == nil {
		return "unknown error"
	}
	reason := strings.Join(strings.Fields(err.Error()), " ")
	if len(reason) > 512 {
		reason = reason[:512]
	}
	return reason
}

func buildUEPools(value config.PGWU) ([]dataplane.UEPool, error) {
	configured := append([]config.PGWUUEPool(nil), value.UEPools...)
	if len(configured) == 0 {
		configured = []config.PGWUUEPool{{APN: value.APN, UEPoolPrefix: value.UEPoolPrefix, UEGateway: value.UEGateway}}
	}
	pools := make([]dataplane.UEPool, 0, len(configured))
	for index, configuredPool := range configured {
		prefix, err := config.Prefix(configuredPool.UEPoolPrefix, fmt.Sprintf("ue_pools[%d].ue_pool_prefix", index))
		if err != nil {
			return nil, err
		}
		gateway, err := config.Addr(configuredPool.UEGateway, fmt.Sprintf("ue_pools[%d].ue_gateway", index))
		if err != nil {
			return nil, err
		}
		pools = append(pools, dataplane.UEPool{Prefix: prefix, Gateway: gateway})
	}
	return pools, nil
}

func pgwuLatencyHistogram(values []dataplane.LatencyBucket) pgwapi.Histogram {
	histogram := pgwapi.Histogram{Name: "lodestar_pgwu_processing_latency_seconds", Help: "Internal PGW-U processing latency from ingress to successful egress.", Labels: map[string]string{"node": "pgw-u"}}
	var cumulative uint64
	for index, value := range values {
		cumulative += value.Count
		if index+1 < len(values) {
			histogram.Buckets = append(histogram.Buckets, pgwapi.HistogramBucket{UpperBound: float64(value.UpperBoundMicros) / 1_000_000, Count: cumulative})
		}
	}
	histogram.Count = cumulative
	return histogram
}

func absoluteDifference(left, right uint64) uint64 {
	if left >= right {
		return left - right
	}
	return right - left
}

func pgwuRuntimeHistogram(values []runtimeobs.Bucket, count uint64) pgwapi.Histogram {
	histogram := pgwapi.Histogram{Name: "lodestar_pgwu_runtime_gc_pause_seconds", Help: "Go GC stop-the-world pause distribution.", Labels: map[string]string{"node": "pgw-u"}, Count: count}
	for index, value := range values {
		if index+1 < len(values) {
			histogram.Buckets = append(histogram.Buckets, pgwapi.HistogramBucket{UpperBound: value.UpperBoundSeconds, Count: value.Count})
		}
	}
	return histogram
}

func pfcpMetrics(server *pfcpserver.Server, configuredPeer string) (bool, string, []pgwapi.Metric) {
	state := pfcpassociation.StateUnavailable
	peer := configuredPeer
	graceRemaining := time.Duration(0)
	associations := server.Associations()
	if len(associations) > 0 {
		state = associations[0].State
		peer = associations[0].Peer.String()
		graceRemaining = server.GraceRemaining(associations[0].Peer)
	}
	metrics := make([]pgwapi.Metric, 0, 5)
	for _, candidate := range []pfcpassociation.State{
		pfcpassociation.StateAssociated, pfcpassociation.StateGrace,
		pfcpassociation.StateReconciling, pfcpassociation.StateUnavailable,
	} {
		metricValue := float64(0)
		if candidate == state {
			metricValue = 1
		}
		metrics = append(metrics, pgwapi.Metric{
			Name: "pfcp_association_state", Help: "One-hot PFCP association state.", Type: "gauge",
			Labels: map[string]string{"node": "pgw-u", "peer": peer, "state": string(candidate)}, Value: metricValue,
		})
	}
	metrics = append(metrics, pgwapi.Metric{
		Name: "pfcp_grace_seconds_remaining", Help: "Seconds remaining before PFCP grace expiry.", Type: "gauge",
		Labels: map[string]string{"node": "pgw-u", "peer": peer}, Value: graceRemaining.Seconds(),
	})
	return state == pfcpassociation.StateAssociated, string(state), metrics
}
