package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lodestarnetworks/cups/internal/admission"
	"github.com/lodestarnetworks/cups/internal/config"
	recoverystate "github.com/lodestarnetworks/cups/internal/gtprecoverystate"
	gtptransport "github.com/lodestarnetworks/cups/internal/gtpv2/transport"
	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	"github.com/lodestarnetworks/cups/internal/pfcp/usagereport"
	"github.com/lodestarnetworks/cups/internal/pgwapi"
	"github.com/lodestarnetworks/cups/internal/pgwc/gateway"
	"github.com/lodestarnetworks/cups/internal/pgwc/ipam"
	"github.com/lodestarnetworks/cups/internal/pgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/pgwc/policyapi"
	"github.com/lodestarnetworks/cups/internal/pgwc/session"
)

var version = "dev"

type runtimeConfig struct {
	value             config.PGWC
	procedureTimeout  time.Duration
	heartbeatInterval time.Duration
	retransmit        time.Duration
	policyToken       []byte
	policyTLS         *tls.Config
}

func main() {
	configPath := flag.String("config", "configs/pgw-c.lab.yaml", "path to strict YAML configuration")
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
		fmt.Println("PGW-C configuration is valid")
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, runtime, logger); err != nil {
		logger.Error("PGW-C stopped", "error", err)
		os.Exit(1)
	}
}

func parseConfig(path string) (runtimeConfig, error) {
	value, err := config.LoadPGWC(path)
	if err != nil {
		return runtimeConfig{}, err
	}
	procedureTimeout, err := config.Duration(value.ProcedureTimeout, "procedure_timeout")
	if err != nil {
		return runtimeConfig{}, err
	}
	heartbeatInterval, err := config.Duration(value.HeartbeatInterval, "heartbeat_interval")
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
	var policyToken []byte
	var policyTLS *tls.Config
	if value.PolicyListen != "" {
		policyToken, err = policyapi.LoadTokenFile(value.PolicyAuthTokenFile)
		if err != nil {
			return runtimeConfig{}, err
		}
		policyTLS, err = policyapi.LoadMTLSConfig(value.PolicyTLSCertFile, value.PolicyTLSKeyFile, value.PolicyTLSClientCAFile)
		if err != nil {
			return runtimeConfig{}, err
		}
	}
	return runtimeConfig{
		value: value, procedureTimeout: procedureTimeout, heartbeatInterval: heartbeatInterval, retransmit: retransmit,
		policyToken: policyToken, policyTLS: policyTLS,
	}, nil
}

func run(parent context.Context, runtime runtimeConfig, logger *slog.Logger) (resultErr error) {
	value := runtime.value
	var admissionPollInterval time.Duration
	if value.AdmissionPollInterval != "" {
		parsed, err := config.Duration(value.AdmissionPollInterval, "admission_poll_interval")
		if err != nil {
			return err
		}
		admissionPollInterval = parsed
	}
	drainGate, err := admission.NewFileGate(value.AdmissionDrainFile, admissionPollInterval)
	if err != nil {
		return err
	}
	if event, emit := drainGate.Refresh(); emit {
		logAdmissionEvent(logger, "PGW-C", event)
	}
	s5Listen, _ := config.AddrPort(value.S5Listen, "s5_listen")
	s5Advertise, _ := config.Addr(value.S5Advertise, "s5_advertise")
	allowedSGW, _ := config.Addrs(value.AllowedSGW, "allowed_sgw")
	pfcpListen, _ := config.AddrPort(value.PFCPListen, "pfcp_listen")
	pfcpAdvertise, _ := config.Addr(value.PFCPAdvertise, "pfcp_advertise")
	pfcpRemote, _ := config.AddrPort(value.PFCPRemote, "pfcp_remote")
	pgwuUserIP, _ := config.Addr(value.PGWUUserIP, "pgwu_user_ip")
	pgwuQCI1UserIP := netip.Addr{}
	if value.PGWUQCI1UserIP != "" {
		pgwuQCI1UserIP, _ = config.Addr(value.PGWUQCI1UserIP, "pgwu_qci1_user_ip")
	}
	apnProfiles, err := buildAPNProfiles(value)
	if err != nil {
		return err
	}
	stateIdentity, err := pgwcStateIdentity(value)
	if err != nil {
		return err
	}
	var stateWAL *session.WAL
	var peerRecoveryState *recoverystate.Store
	var recovered []session.Session
	var peerRecovery map[string]uint8
	var commitPeerRecovery func(string, uint8) error
	recoveryCounter := value.RecoveryCounter
	if value.StateFile != "" {
		stateWAL, recovered, resultErr = session.OpenWAL(value.StateFile, value.StateWALMaxBytes, stateIdentity, value.RecoveryCounter)
		if resultErr != nil {
			return resultErr
		}
		defer func() { resultErr = errors.Join(resultErr, stateWAL.Close()) }()
		recoveryCounter = stateWAL.RecoveryCounter()
		logger.Info("PGW-C durable state opened", "recovered_sessions", len(recovered), "recovery_counter", recoveryCounter)
		peerRecoveryMaxBytes := value.StateWALMaxBytes
		if peerRecoveryMaxBytes > 64<<20 {
			peerRecoveryMaxBytes = 64 << 20
		}
		peerIdentity := append(append([]byte(nil), stateIdentity...), []byte("\x00pgwc-peer-recovery-v1")...)
		peerRecoveryState, resultErr = recoverystate.Open(value.StateFile+".peers", peerRecoveryMaxBytes, peerIdentity)
		if resultErr != nil {
			return resultErr
		}
		defer func() { resultErr = errors.Join(resultErr, peerRecoveryState.Close()) }()
		peerRecovery = peerRecoveryState.Snapshot()
		commitPeerRecovery = peerRecoveryState.Commit
		logger.Info("PGW-C durable peer-recovery state opened", "peers", len(peerRecovery))
	} else {
		logger.Warn("PGW-C durable state is disabled; sessions and UE leases will not survive a control-plane restart")
	}
	var persister session.Persister
	if stateWAL != nil {
		persister = stateWAL
	}
	sessionStore := session.NewStoreWithPersister(value.MaxSessions, persister)
	if err := sessionStore.Restore(recovered); err != nil {
		return fmt.Errorf("restore PGW-C sessions: %w", err)
	}

	if err := restoreAPNLeases(apnProfiles, recovered); err != nil {
		return err
	}
	recoveredCount := len(recovered)
	if stateWAL != nil {
		if err := stateWAL.Start(); err != nil {
			return err
		}
		if err := peerRecoveryState.Start(); err != nil {
			return err
		}
		logger.Info("PGW-C recovered sessions and UE leases validated; ownership epoch committed", "sessions", recoveredCount, "recovery_counter", recoveryCounter)
	}
	recovered = nil
	started := time.Now().UTC()
	pfcpConfig := pfcptransport.DefaultConfig()
	pfcpConfig.RetransmitTimeout = runtime.retransmit
	pfcpConfig.MaxRetransmits = value.MaxRetransmits
	usageLedger := usagereport.LedgerConfig{
		Identity: append(append([]byte(nil), stateIdentity...), []byte("\x00pgwc-pfcp-usage-v1")...),
		MaxBytes: value.StateWALMaxBytes,
	}
	if value.StateFile != "" {
		usageLedger.Path = value.StateFile + ".usage"
	}
	pfcpClient, err := pfcpclient.New(pfcpclient.Config{
		Listen: pfcpListen, Advertise: pfcpAdvertise, Remote: pfcpRemote,
		StartedAt: started, EnterpriseID: value.PFCPEnterpriseID,
		UsageReportingThreshold: value.UsageReportingThreshold, UsageLedger: usageLedger, Transport: pfcpConfig,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	errCh := make(chan error, 4)
	go drainGate.Run(ctx, func(event admission.Event) { logAdmissionEvent(logger, "PGW-C", event) })
	go func() { errCh <- pfcpClient.Serve(ctx) }()
	associateCtx, associateCancel := context.WithTimeout(ctx, runtime.procedureTimeout)
	err = pfcpClient.Associate(associateCtx)
	associateCancel()
	if err != nil {
		_ = pfcpClient.Close()
		return fmt.Errorf("initial PGW-U association: %w", err)
	}

	gtpConfig := gtptransport.DefaultConfig()
	gtpConfig.RetransmitTimeout = runtime.retransmit
	gtpConfig.MaxRetransmits = value.MaxRetransmits
	control, err := gateway.New(gateway.Config{
		S5Listen: s5Listen, S5Advertise: s5Advertise, PGWUUserIP: pgwuUserIP, PGWUQCI1UserIP: pgwuQCI1UserIP,
		AllowedSGW: allowedSGW, APNProfiles: apnProfiles, RecoveryCounter: recoveryCounter,
		ReconcileWorkers: value.ReconcileWorkers,
		ProcedureTimeout: runtime.procedureTimeout, SubscriberSalt: []byte(value.SubscriberSalt),
		Transport:    gtpConfig,
		PeerRecovery: peerRecovery, CommitPeerRecovery: commitPeerRecovery,
		AllowNewSessions: drainGate.AllowNewSession,
		OnEvent: func(event gateway.Event) {
			logger.Log(ctx, eventLevel(event.Severity), event.Message, "procedure", event.Procedure, "peer", event.Peer, "subscriber", event.Subscriber)
		},
	}, sessionStore, nil, pfcpClient)
	if err != nil {
		_ = pfcpClient.Close()
		return err
	}
	reconciled, err := control.ReconcileAll(ctx)
	if err != nil {
		_ = control.Close()
		_ = pfcpClient.Close()
		return fmt.Errorf("initial PGW-U reconciliation after %d sessions: %w", reconciled, err)
	}
	reconcileCtx, reconcileCancel := context.WithTimeout(ctx, runtime.procedureTimeout)
	err = pfcpClient.CompleteReconciliation(reconcileCtx)
	reconcileCancel()
	if err != nil {
		_ = control.Close()
		_ = pfcpClient.Close()
		return fmt.Errorf("complete initial PGW-U reconciliation: %w", err)
	}
	logger.Info("PGW-U authoritative state replay completed", "sessions", reconciled)
	var policyHandler *policyapi.Handler
	if value.PolicyListen != "" {
		policyHandler, err = policyapi.New(policyapi.Config{
			Token: runtime.policyToken, MaxBodyBytes: value.PolicyMaxBodyBytes,
			MaxInFlight: value.PolicyMaxInFlight, RequestTimeout: runtime.procedureTimeout,
			OnEvent: func(event policyapi.Event) {
				if event.Result == "rejected" {
					logger.Warn("PGW-C policy operation", "operation", event.Operation, "policy_id", event.PolicyID, "session_id", event.SessionID, "result", event.Result, "code", event.Code, "reason", event.Reason)
					return
				}
				logger.Info("PGW-C policy operation", "operation", event.Operation, "policy_id", event.PolicyID, "session_id", event.SessionID, "result", event.Result)
			},
		}, control)
		if err != nil {
			_ = control.Close()
			_ = pfcpClient.Close()
			return err
		}
	}
	for index := range runtime.policyToken {
		runtime.policyToken[index] = 0
	}
	var reconcileFailures atomic.Uint64
	handler := pgwapi.NewHandler(func() pgwapi.Snapshot {
		association, associated := pfcpClient.Association()
		status := "PFCP association unavailable"
		peer := pfcpRemote.String()
		if associated {
			status = "associated"
			if association.NodeAddress.IsValid() {
				peer = association.NodeAddress.String()
			}
		}
		counters := control.Counters()
		transportCounters := control.TransportCounters()
		pfcpTransportCounters := pfcpClient.TransportCounters()
		sessions := control.Sessions()
		associationValue := float64(0)
		if associated {
			associationValue = 1
		}
		labels := map[string]string{"node": "pgw-c", "apn": pgwcMetricScope(value)}
		durableState := float64(0)
		stateStats := session.WALStats{}
		if stateWAL != nil {
			durableState = 1
			stateStats = stateWAL.Stats()
		}
		tailRecovered := float64(0)
		if stateStats.RecoveredTail {
			tailRecovered = 1
		}
		usageStats := pfcpClient.UsageLedgerStats()
		usageDurable := float64(0)
		if usageStats.Durable {
			usageDurable = 1
		}
		usageTailRecovered := float64(0)
		if usageStats.WALRecoveredTail {
			usageTailRecovered = 1
		}
		policyEnabled := float64(0)
		policyStats := policyapi.Stats{}
		if policyHandler != nil {
			policyEnabled = 1
			policyStats = policyHandler.Stats()
		}
		admissionStats := drainGate.Stats()
		admissionDraining := float64(0)
		if admissionStats.Draining {
			admissionDraining = 1
		}
		return pgwapi.Snapshot{
			Component: "pgw-c", Healthy: associated, Status: status, StartedAt: started,
			Metrics: append(pgwcAPNSessionMetrics(value, sessions), []pgwapi.Metric{
				{Name: "pfcp_association_state", Help: "PFCP association state (1 associated, 0 unavailable).", Type: "gauge", Labels: map[string]string{"node": "pgw-c", "peer": peer}, Value: associationValue},
				{Name: "lodestar_pgw_create_session_total", Type: "counter", Labels: map[string]string{"node": "pgw-c", "result": "accepted"}, Value: float64(counters.CreateAccepted)},
				{Name: "lodestar_pgw_create_session_total", Type: "counter", Labels: map[string]string{"node": "pgw-c", "result": "rejected"}, Value: float64(counters.CreateRejected)},
				{Name: "lodestar_pgw_create_session_total", Help: "Create Session outcomes, including operator admission drain rejections.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "result": "admission_drained"}, Value: float64(counters.CreateAdmissionRejected)},
				{Name: "lodestar_pgw_admission_draining", Help: "PGW-C admission state (1 draining, 0 ready).", Type: "gauge", Labels: labels, Value: admissionDraining},
				{Name: "lodestar_pgw_admission_transitions_total", Help: "PGW-C admission ready/draining transitions.", Type: "counter", Labels: labels, Value: float64(admissionStats.Transitions)},
				{Name: "lodestar_pgw_admission_check_errors_total", Help: "PGW-C drain-file checks that failed closed.", Type: "counter", Labels: labels, Value: float64(admissionStats.CheckErrors)},
				{Name: "lodestar_pgw_modify_bearer_total", Type: "counter", Labels: map[string]string{"node": "pgw-c", "result": "accepted"}, Value: float64(counters.ModifyAccepted)},
				{Name: "lodestar_pgw_delete_session_total", Type: "counter", Labels: map[string]string{"node": "pgw-c", "result": "accepted"}, Value: float64(counters.DeleteAccepted)},
				{Name: "lodestar_pgw_bearer_procedure_total", Help: "PGW-initiated dedicated bearer procedures.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "procedure": "create", "result": "accepted"}, Value: float64(counters.CreateBearerAccepted)},
				{Name: "lodestar_pgw_bearer_procedure_total", Help: "PGW-initiated dedicated bearer procedures.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "procedure": "create", "result": "rejected"}, Value: float64(counters.CreateBearerRejected)},
				{Name: "lodestar_pgw_bearer_procedure_total", Help: "PGW-initiated dedicated bearer procedures.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "procedure": "update", "result": "accepted"}, Value: float64(counters.UpdateBearerAccepted)},
				{Name: "lodestar_pgw_bearer_procedure_total", Help: "PGW-initiated dedicated bearer procedures.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "procedure": "update", "result": "rejected"}, Value: float64(counters.UpdateBearerRejected)},
				{Name: "lodestar_pgw_bearer_procedure_total", Help: "PGW-initiated dedicated bearer procedures.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "procedure": "delete", "result": "accepted"}, Value: float64(counters.DeleteBearerAccepted)},
				{Name: "lodestar_pgw_bearer_procedure_total", Help: "PGW-initiated dedicated bearer procedures.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "procedure": "delete", "result": "rejected"}, Value: float64(counters.DeleteBearerRejected)},
				{Name: "lodestar_pgw_gtpv2_malformed_total", Type: "counter", Labels: map[string]string{"node": "pgw-c"}, Value: float64(transportCounters.Malformed)},
				{Name: "lodestar_pgw_control_socket_drops_total", Type: "counter", Labels: map[string]string{"node": "pgw-c", "interface": "s5c"}, Value: float64(transportCounters.SocketDrops)},
				{Name: "lodestar_pgw_control_socket_drops_total", Type: "counter", Labels: map[string]string{"node": "pgw-c", "interface": "sxb"}, Value: float64(pfcpTransportCounters.SocketDrops)},
				{Name: "lodestar_pgw_reconciliation_failures_total", Type: "counter", Labels: map[string]string{"node": "pgw-c"}, Value: float64(reconcileFailures.Load())},
				{Name: "lodestar_pgw_control_state_durable", Help: "Durable PGW-C session ownership enabled (1 enabled, 0 volatile).", Type: "gauge", Labels: labels, Value: durableState},
				{Name: "lodestar_pgw_control_state_wal_bytes", Help: "PGW-C durable journal size in bytes.", Type: "gauge", Labels: labels, Value: float64(stateStats.Bytes)},
				{Name: "lodestar_pgw_control_state_wal_records_total", Help: "PGW-C durable session transitions appended or recovered.", Type: "counter", Labels: labels, Value: float64(stateStats.DataRecords)},
				{Name: "lodestar_pgw_control_state_starts_total", Help: "PGW-C starts recorded in the durable journal.", Type: "counter", Labels: labels, Value: float64(stateStats.Starts)},
				{Name: "lodestar_pgw_control_state_compactions_total", Help: "Atomic PGW-C durable journal compactions completed by this process.", Type: "counter", Labels: labels, Value: float64(stateStats.Compactions)},
				{Name: "lodestar_pgw_control_state_recovered_sessions", Help: "PGW-C sessions recovered at this process start.", Type: "gauge", Labels: labels, Value: float64(recoveredCount)},
				{Name: "lodestar_pgw_control_state_tail_recovered", Help: "A partial final PGW-C journal record was safely truncated at this start.", Type: "gauge", Labels: labels, Value: tailRecovered},
				{Name: "lodestar_pgw_control_recovery_counter", Help: "Current PGW-C GTPv2 recovery counter.", Type: "gauge", Labels: labels, Value: float64(recoveryCounter)},
				{Name: "lodestar_pgw_peer_restarts_total", Help: "SGW-C restart counter changes completed after stale-session cleanup.", Type: "counter", Labels: labels, Value: float64(counters.PeerRestarts)},
				{Name: "lodestar_pgw_peer_restart_purge_failures_total", Help: "SGW-C restart cleanups withheld because downstream or durable deletion was incomplete.", Type: "counter", Labels: labels, Value: float64(counters.PeerRestartPurgeFailures)},
				{Name: "lodestar_pgw_pfcp_usage_reports_total", Help: "PFCP usage reports processed by PGW-C.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "result": "accepted"}, Value: float64(usageStats.ReportsAccepted)},
				{Name: "lodestar_pgw_pfcp_usage_reports_total", Help: "PFCP usage reports processed by PGW-C.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "result": "duplicate"}, Value: float64(usageStats.ReportsDuplicate)},
				{Name: "lodestar_pgw_pfcp_usage_reports_total", Help: "PFCP usage reports processed by PGW-C.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "result": "sequence_gap"}, Value: float64(usageStats.SequenceGaps)},
				{Name: "lodestar_pgw_pfcp_usage_reports_total", Help: "PFCP usage reports processed by PGW-C.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "result": "sequence_conflict"}, Value: float64(usageStats.SequenceConflicts)},
				{Name: "lodestar_pgw_pfcp_usage_bytes_total", Help: "PFCP-reported telemetry bytes durably accepted by PGW-C.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "direction": "uplink"}, Value: float64(usageStats.UplinkBytes)},
				{Name: "lodestar_pgw_pfcp_usage_bytes_total", Help: "PFCP-reported telemetry bytes durably accepted by PGW-C.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "direction": "downlink"}, Value: float64(usageStats.DownlinkBytes)},
				{Name: "lodestar_pgw_pfcp_usage_packets_total", Help: "PFCP-reported telemetry packets durably accepted by PGW-C.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "direction": "uplink"}, Value: float64(usageStats.UplinkPackets)},
				{Name: "lodestar_pgw_pfcp_usage_packets_total", Help: "PFCP-reported telemetry packets durably accepted by PGW-C.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "direction": "downlink"}, Value: float64(usageStats.DownlinkPackets)},
				{Name: "lodestar_pgw_pfcp_usage_checkpoints", Help: "Active duplicate-detection checkpoints in PGW-C.", Type: "gauge", Labels: labels, Value: float64(usageStats.ActiveCheckpoints)},
				{Name: "lodestar_pgw_pfcp_usage_ledger_durable", Help: "Durable PGW-C usage-report reconciliation enabled.", Type: "gauge", Labels: labels, Value: usageDurable},
				{Name: "lodestar_pgw_pfcp_usage_ledger_wal_bytes", Help: "Current PGW-C usage-ledger journal size.", Type: "gauge", Labels: labels, Value: float64(usageStats.WALBytes)},
				{Name: "lodestar_pgw_pfcp_usage_ledger_wal_records_total", Help: "Durable PGW-C usage-ledger records.", Type: "counter", Labels: labels, Value: float64(usageStats.WALRecords)},
				{Name: "lodestar_pgw_pfcp_usage_ledger_compactions_total", Help: "Atomic PGW-C usage-ledger compactions.", Type: "counter", Labels: labels, Value: float64(usageStats.WALCompactions)},
				{Name: "lodestar_pgw_pfcp_usage_ledger_tail_recovered", Help: "Whether a partial PGW-C usage-ledger tail was safely recovered.", Type: "gauge", Labels: labels, Value: usageTailRecovered},
				{Name: "lodestar_pgw_pfcp_usage_checkpoint_remove_failures_total", Help: "Usage checkpoint tombstones that could not be persisted.", Type: "counter", Labels: labels, Value: float64(pfcpClient.UsageLedgerRemoveFailures())},
				{Name: "lodestar_pgw_policy_api_enabled", Help: "Protected dedicated-bearer policy API enabled.", Type: "gauge", Labels: labels, Value: policyEnabled},
				{Name: "lodestar_pgw_policy_api_requests_total", Help: "Authenticated and unauthenticated policy API requests.", Type: "counter", Labels: labels, Value: float64(policyStats.Requests)},
				{Name: "lodestar_pgw_policy_api_auth_failures_total", Help: "Policy API requests rejected before routing due to invalid credentials.", Type: "counter", Labels: labels, Value: float64(policyStats.AuthFailures)},
				{Name: "lodestar_pgw_policy_api_bad_requests_total", Help: "Authenticated policy API requests rejected by strict input validation.", Type: "counter", Labels: labels, Value: float64(policyStats.BadRequests)},
				{Name: "lodestar_pgw_policy_api_operations_total", Help: "Authoritative dedicated-bearer policy outcomes.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "result": "created"}, Value: float64(policyStats.Created)},
				{Name: "lodestar_pgw_policy_api_operations_total", Help: "Authoritative dedicated-bearer policy outcomes.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "result": "updated"}, Value: float64(policyStats.Updated)},
				{Name: "lodestar_pgw_policy_api_operations_total", Help: "Authoritative dedicated-bearer policy outcomes.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "result": "unchanged"}, Value: float64(policyStats.Unchanged)},
				{Name: "lodestar_pgw_policy_api_operations_total", Help: "Authoritative dedicated-bearer policy outcomes.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "result": "deleted"}, Value: float64(policyStats.Deleted)},
				{Name: "lodestar_pgw_policy_api_operations_total", Help: "Authoritative dedicated-bearer policy outcomes.", Type: "counter", Labels: map[string]string{"node": "pgw-c", "result": "failed"}, Value: float64(policyStats.Failed)},
				{Name: "lodestar_pgw_policy_api_saturated_total", Help: "Policy operations rejected because the bounded in-flight limit was full.", Type: "counter", Labels: labels, Value: float64(policyStats.Saturated)},
				{Name: "lodestar_pgw_policy_api_in_flight", Help: "Current LTE bearer policy procedures in progress.", Type: "gauge", Labels: labels, Value: float64(policyStats.InFlight)},
			}...),
		}
	})
	httpServer := &http.Server{
		Addr: value.ManagementListen, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	var policyServer *http.Server
	var policyListener net.Listener
	if policyHandler != nil {
		policyListener, err = net.Listen("tcp", value.PolicyListen)
		if err != nil {
			_ = control.Close()
			_ = pfcpClient.Close()
			return fmt.Errorf("listen on PGW-C policy endpoint: %w", err)
		}
		defer policyListener.Close()
		if runtime.policyTLS != nil {
			policyListener = tls.NewListener(policyListener, runtime.policyTLS)
		}
		policyServer = &http.Server{
			Addr: value.PolicyListen, Handler: policyHandler, TLSConfig: runtime.policyTLS,
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
			WriteTimeout: runtime.procedureTimeout + 5*time.Second, IdleTimeout: 60 * time.Second,
		}
	}
	go func() { errCh <- control.Serve(ctx) }()
	go func() {
		err := httpServer.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	if policyServer != nil {
		go func() {
			err := policyServer.Serve(policyListener)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			errCh <- err
		}()
	}
	go heartbeat(ctx, control, pfcpClient, runtime.heartbeatInterval, runtime.procedureTimeout, &reconcileFailures, logger)
	logger.Info("PGW-C started", "s5c", control.S5Addr(), "sxb", pfcpRemote, "apn_scope", pgwcMetricScope(value), "management", value.ManagementListen, "recovered_sessions", recoveredCount, "recovery_counter", recoveryCounter)
	if policyServer != nil {
		transport := "http"
		if runtime.policyTLS != nil {
			transport = "https-mtls"
		}
		logger.Info("PGW-C policy API started", "listen", value.PolicyListen, "transport", transport, "max_in_flight", value.PolicyMaxInFlight)
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
	var policyErr error
	if policyServer != nil {
		policyErr = policyServer.Shutdown(shutdownCtx)
	}
	closeErr := errors.Join(control.Close(), pfcpClient.Close())
	logger.Info("PGW-C shutdown complete")
	return errors.Join(runErr, httpErr, policyErr, closeErr)
}

func buildAPNProfiles(value config.PGWC) ([]gateway.APNProfile, error) {
	configured := append([]config.PGWCAPNProfile(nil), value.APNProfiles...)
	if len(configured) == 0 {
		configured = []config.PGWCAPNProfile{{
			APN: value.APN, UEPoolPrefix: value.UEPoolPrefix, UEGateway: value.UEGateway,
			DNSIPv4: append([]string(nil), value.DNSIPv4...), PCSCFIPv4: append([]string(nil), value.PCSCFIPv4...),
			IPv4LinkMTU: value.IPv4LinkMTU, APNAMBRUplinkBPS: value.APNAMBRUplinkBPS,
			APNAMBRDownlinkBPS: value.APNAMBRDownlinkBPS,
		}}
	}
	profiles := make([]gateway.APNProfile, 0, len(configured))
	for index, profile := range configured {
		prefix, err := config.Prefix(profile.UEPoolPrefix, fmt.Sprintf("apn_profiles[%d].ue_pool_prefix", index))
		if err != nil {
			return nil, err
		}
		ueGateway, err := config.Addr(profile.UEGateway, fmt.Sprintf("apn_profiles[%d].ue_gateway", index))
		if err != nil {
			return nil, err
		}
		dns, err := config.Addrs(profile.DNSIPv4, fmt.Sprintf("apn_profiles[%d].dns_ipv4", index))
		if err != nil {
			return nil, err
		}
		pcscf, err := config.Addrs(profile.PCSCFIPv4, fmt.Sprintf("apn_profiles[%d].pcscf_ipv4", index))
		if err != nil {
			return nil, err
		}
		pool, err := ipam.New(prefix, ueGateway, value.MaxSessions)
		if err != nil {
			return nil, fmt.Errorf("build address pool for APN %q: %w", profile.APN, err)
		}
		profiles = append(profiles, gateway.APNProfile{
			APN: profile.APN, Pool: pool, DNSIPv4: dns, PCSCFIPv4: pcscf,
			IPv4LinkMTU: profile.IPv4LinkMTU, APNAMBRUplinkBPS: profile.APNAMBRUplinkBPS,
			APNAMBRDownlinkBPS: profile.APNAMBRDownlinkBPS,
		})
	}
	return profiles, nil
}

func restoreAPNLeases(profiles []gateway.APNProfile, recovered []session.Session) error {
	recoveredLeases := make(map[string][]ipam.Lease, len(profiles))
	profileByAPN := make(map[string]gateway.APNProfile, len(profiles))
	for _, profile := range profiles {
		apn := strings.ToLower(strings.TrimSpace(profile.APN))
		if apn == "" || profile.Pool == nil {
			return errors.New("restore PGW-C UE leases: invalid APN profile")
		}
		profileByAPN[apn] = profile
	}
	for _, current := range recovered {
		apn := strings.ToLower(strings.TrimSpace(current.APN))
		profile, served := profileByAPN[apn]
		if !served || !profile.Pool.Prefix().Contains(current.UEIPv4) {
			return fmt.Errorf("restore PGW-C UE lease: session %d is outside configured APN profiles", current.ID)
		}
		recoveredLeases[apn] = append(recoveredLeases[apn], ipam.Lease{
			Owner: current.SubscriberKey + "\x00" + apn,
			Addr:  current.UEIPv4,
		})
	}
	for apn, profile := range profileByAPN {
		if err := profile.Pool.Restore(recoveredLeases[apn]); err != nil {
			return fmt.Errorf("restore PGW-C UE leases for APN %q: %w", apn, err)
		}
	}
	return nil
}

func pgwcStateIdentity(value config.PGWC) ([]byte, error) {
	allowedSGW := append([]string(nil), value.AllowedSGW...)
	sort.Strings(allowedSGW)
	type apnProfile struct {
		APN                string   `json:"apn"`
		UEPoolPrefix       string   `json:"ue_pool_prefix"`
		UEGateway          string   `json:"ue_gateway"`
		DNSIPv4            []string `json:"dns_ipv4"`
		PCSCFIPv4          []string `json:"pcscf_ipv4"`
		IPv4LinkMTU        uint16   `json:"ipv4_link_mtu"`
		APNAMBRUplinkBPS   uint64   `json:"apn_ambr_uplink_bps"`
		APNAMBRDownlinkBPS uint64   `json:"apn_ambr_downlink_bps"`
	}
	configured := append([]config.PGWCAPNProfile(nil), value.APNProfiles...)
	if len(configured) == 0 {
		configured = []config.PGWCAPNProfile{{
			APN: value.APN, UEPoolPrefix: value.UEPoolPrefix, UEGateway: value.UEGateway,
			DNSIPv4: append([]string(nil), value.DNSIPv4...), PCSCFIPv4: append([]string(nil), value.PCSCFIPv4...),
			IPv4LinkMTU: value.IPv4LinkMTU, APNAMBRUplinkBPS: value.APNAMBRUplinkBPS,
			APNAMBRDownlinkBPS: value.APNAMBRDownlinkBPS,
		}}
	}
	profiles := make([]apnProfile, 0, len(configured))
	for _, profile := range configured {
		profiles = append(profiles, apnProfile{
			APN: strings.ToLower(strings.TrimSpace(profile.APN)), UEPoolPrefix: profile.UEPoolPrefix,
			UEGateway: profile.UEGateway, DNSIPv4: append([]string(nil), profile.DNSIPv4...),
			PCSCFIPv4: append([]string(nil), profile.PCSCFIPv4...), IPv4LinkMTU: profile.IPv4LinkMTU,
			APNAMBRUplinkBPS: profile.APNAMBRUplinkBPS, APNAMBRDownlinkBPS: profile.APNAMBRDownlinkBPS,
		})
	}
	sort.Slice(profiles, func(left, right int) bool { return profiles[left].APN < profiles[right].APN })
	return json.Marshal(struct {
		Schema           uint8        `json:"schema"`
		Component        string       `json:"component"`
		S5Listen         string       `json:"s5_listen"`
		S5Advertise      string       `json:"s5_advertise"`
		AllowedSGW       []string     `json:"allowed_sgw"`
		PFCPListen       string       `json:"pfcp_listen"`
		PFCPAdvertise    string       `json:"pfcp_advertise"`
		PFCPRemote       string       `json:"pfcp_remote"`
		PFCPEnterpriseID uint16       `json:"pfcp_enterprise_id"`
		PGWUUserIP       string       `json:"pgwu_user_ip"`
		PGWUQCI1UserIP   string       `json:"pgwu_qci1_user_ip"`
		APNProfiles      []apnProfile `json:"apn_profiles"`
		SubscriberSecret string       `json:"subscriber_secret"`
	}{
		Schema: 4, Component: "pgw-c", S5Listen: value.S5Listen, S5Advertise: value.S5Advertise,
		AllowedSGW: allowedSGW, PFCPListen: value.PFCPListen, PFCPAdvertise: value.PFCPAdvertise,
		PFCPRemote: value.PFCPRemote, PFCPEnterpriseID: value.PFCPEnterpriseID,
		PGWUUserIP: value.PGWUUserIP, PGWUQCI1UserIP: value.PGWUQCI1UserIP,
		APNProfiles: profiles, SubscriberSecret: value.SubscriberSalt,
	})
}

func heartbeat(ctx context.Context, control *gateway.Gateway, client *pfcpclient.Client, interval, timeout time.Duration, reconcileFailures *atomic.Uint64, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			opCtx, cancel := context.WithTimeout(ctx, timeout)
			err := client.Heartbeat(opCtx)
			cancel()
			if err == nil {
				continue
			}
			restarted := errors.Is(err, pfcpclient.ErrPeerRestarted)
			client.MarkUnavailable()
			logger.Warn("PGW-U heartbeat failed; entering reconnect path", "error", err)
			opCtx, cancel = context.WithTimeout(ctx, timeout)
			err = client.Associate(opCtx)
			cancel()
			if errors.Is(err, pfcpclient.ErrPeerRestarted) {
				restarted = true
				err = nil
			}
			if err != nil {
				logger.Warn("PGW-U reassociation failed", "error", err)
				continue
			}
			reconciled, reconcileErr := control.ReconcileAll(ctx)
			if reconcileErr != nil {
				reconcileFailures.Add(1)
				logger.Error("PGW-U session reconciliation incomplete", "reconciled", reconciled, "restart", restarted, "error", reconcileErr)
				continue
			}
			opCtx, cancel = context.WithTimeout(ctx, timeout)
			reconcileErr = client.CompleteReconciliation(opCtx)
			cancel()
			if reconcileErr != nil {
				reconcileFailures.Add(1)
				logger.Error("PGW-U reconciliation completion failed", "reconciled", reconciled, "error", reconcileErr)
				continue
			}
			logger.Info("PGW-U sessions reconciled", "sessions", reconciled, "restart", restarted)
		case <-ctx.Done():
			return
		}
	}
}

func eventLevel(severity string) slog.Level {
	switch severity {
	case "error":
		return slog.LevelError
	case "warning":
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}

func logAdmissionEvent(logger *slog.Logger, component string, event admission.Event) {
	if event.Err != nil {
		logger.Error(component+" admission control failed closed", "draining", true, "error", event.Err)
		return
	}
	if event.Draining {
		logger.Warn(component + " admission drain enabled; existing sessions remain active")
		return
	}
	logger.Info(component + " admission ready; new sessions are allowed")
}
