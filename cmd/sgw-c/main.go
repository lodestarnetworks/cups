package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/lodestarnetworks/cups/internal/admission"
	"github.com/lodestarnetworks/cups/internal/api"
	"github.com/lodestarnetworks/cups/internal/config"
	recoverystate "github.com/lodestarnetworks/cups/internal/gtprecoverystate"
	gtptransport "github.com/lodestarnetworks/cups/internal/gtpv2/transport"
	"github.com/lodestarnetworks/cups/internal/live"
	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	"github.com/lodestarnetworks/cups/internal/pfcp/usagereport"
	"github.com/lodestarnetworks/cups/internal/sgwc/gateway"
	"github.com/lodestarnetworks/cups/internal/sgwc/pfcpclient"
	"github.com/lodestarnetworks/cups/internal/sgwc/session"
	"github.com/lodestarnetworks/cups/internal/telemetry"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "configs/sgw-c.lab.yaml", "path to strict YAML configuration")
	checkConfig := flag.Bool("check-config", false, "validate configuration and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *checkConfig {
		if _, err := config.LoadSGWC(*configPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("SGW-C configuration is valid")
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *configPath, logger); err != nil {
		logger.Error("SGW-C stopped", "error", err)
		os.Exit(1)
	}
}

func run(parent context.Context, path string, logger *slog.Logger) (resultErr error) {
	value, err := config.LoadSGWC(path)
	if err != nil {
		return err
	}
	s11Listen, err := config.AddrPort(value.S11Listen, "s11Listen")
	if err != nil {
		return err
	}
	s11Advertise, err := config.Addr(value.S11Advertise, "s11Advertise")
	if err != nil {
		return err
	}
	allowedMME, err := config.Addrs(value.AllowedMME, "allowedMme")
	if err != nil {
		return err
	}
	s5Listen, err := config.AddrPort(value.S5Listen, "s5Listen")
	if err != nil {
		return err
	}
	s5Advertise, err := config.Addr(value.S5Advertise, "s5Advertise")
	if err != nil {
		return err
	}
	pgwControl, err := config.AddrPort(value.PGWControl, "pgwControl")
	if err != nil {
		return err
	}
	pgwRoutes := make(map[string]netip.AddrPort, len(value.PGWRoutes))
	for index, route := range value.PGWRoutes {
		address, routeErr := config.AddrPort(route.Address, fmt.Sprintf("pgwRoutes[%d].address", index))
		if routeErr != nil {
			return routeErr
		}
		pgwRoutes[route.APN] = address
	}
	pfcpListen, err := config.AddrPort(value.PFCPListen, "pfcpListen")
	if err != nil {
		return err
	}
	pfcpAdvertise, err := config.Addr(value.PFCPAdvertise, "pfcpAdvertise")
	if err != nil {
		return err
	}
	pfcpRemote, err := config.AddrPort(value.PFCPRemote, "pfcpRemote")
	if err != nil {
		return err
	}
	accessIP, err := config.Addr(value.SGWUAccessIP, "sgwuAccessIp")
	if err != nil {
		return err
	}
	coreIP, err := config.Addr(value.SGWUCoreIP, "sgwuCoreIp")
	if err != nil {
		return err
	}
	procedureTimeout, err := config.Duration(value.ProcedureTimeout, "procedureTimeout")
	if err != nil {
		return err
	}
	heartbeatInterval, err := config.Duration(value.HeartbeatInterval, "heartbeatInterval")
	if err != nil {
		return err
	}
	retransmit, err := config.Duration(value.RetransmitTimeout, "retransmitTimeout")
	if err != nil {
		return err
	}
	downlinkNotificationDelay, err := config.NonNegativeDuration(value.DownlinkNotificationDelay, "downlinkNotificationDelay")
	if err != nil {
		return err
	}
	var admissionPollInterval time.Duration
	if value.AdmissionPollInterval != "" {
		admissionPollInterval, err = config.Duration(value.AdmissionPollInterval, "admissionPollInterval")
		if err != nil {
			return err
		}
	}
	drainGate, err := admission.NewFileGate(value.AdmissionDrainFile, admissionPollInterval)
	if err != nil {
		return err
	}
	if event, emit := drainGate.Refresh(); emit {
		logAdmissionEvent(logger, "SGW-C", event)
	}
	stateIdentity, err := sgwcStateIdentity(value)
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
		stateWAL, recovered, err = session.OpenWAL(value.StateFile, value.StateWALMaxBytes, stateIdentity, value.RecoveryCounter)
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, stateWAL.Close()) }()
		recoveryCounter = stateWAL.RecoveryCounter()
		logger.Info("SGW-C durable state opened", "recovered_sessions", len(recovered), "recovery_counter", recoveryCounter)
		peerRecoveryMaxBytes := value.StateWALMaxBytes
		if peerRecoveryMaxBytes > 64<<20 {
			peerRecoveryMaxBytes = 64 << 20
		}
		peerIdentity := append(append([]byte(nil), stateIdentity...), []byte("\x00sgwc-peer-recovery-v1")...)
		peerRecoveryState, err = recoverystate.Open(value.StateFile+".peers", peerRecoveryMaxBytes, peerIdentity)
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, peerRecoveryState.Close()) }()
		peerRecovery = peerRecoveryState.Snapshot()
		commitPeerRecovery = peerRecoveryState.Commit
		logger.Info("SGW-C durable peer-recovery state opened", "peers", len(peerRecovery))
	} else {
		logger.Warn("SGW-C durable state is disabled; sessions will not survive a control-plane restart")
	}
	var persister session.Persister
	if stateWAL != nil {
		persister = stateWAL
	}
	sessionStore := session.NewStoreWithPersister(value.MaxSessions, persister)
	if err := sessionStore.Restore(recovered); err != nil {
		return fmt.Errorf("restore SGW-C sessions: %w", err)
	}
	recoveredCount := len(recovered)
	if stateWAL != nil {
		if err := stateWAL.Start(); err != nil {
			return err
		}
		if err := peerRecoveryState.Start(); err != nil {
			return err
		}
		logger.Info("SGW-C recovered state validated and ownership epoch committed", "sessions", recoveredCount, "recovery_counter", recoveryCounter)
	}
	recovered = nil

	started := time.Now().UTC()
	pfcpConfig := pfcptransport.DefaultConfig()
	pfcpConfig.RetransmitTimeout = retransmit
	pfcpConfig.MaxRetransmits = value.MaxRetransmits
	usageLedger := usagereport.LedgerConfig{
		Identity: append(append([]byte(nil), stateIdentity...), []byte("\x00sgwc-pfcp-usage-v1")...),
		MaxBytes: value.StateWALMaxBytes,
	}
	if value.StateFile != "" {
		usageLedger.Path = value.StateFile + ".usage"
	}
	pfcpClient, err := pfcpclient.New(pfcpclient.Config{
		Listen: pfcpListen, Advertise: pfcpAdvertise, Remote: pfcpRemote,
		StartedAt: started, EnterpriseID: value.PFCPEnterpriseID,
		DownlinkNotificationDelay: downlinkNotificationDelay,
		UsageReportingThreshold:   value.UsageReportingThreshold, UsageLedger: usageLedger, Transport: pfcpConfig,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	errCh := make(chan error, 3)
	go drainGate.Run(ctx, func(event admission.Event) { logAdmissionEvent(logger, "SGW-C", event) })
	go func() { errCh <- pfcpClient.Serve(ctx) }()
	associateCtx, associateCancel := context.WithTimeout(ctx, procedureTimeout)
	err = pfcpClient.Associate(associateCtx)
	associateCancel()
	if err != nil {
		_ = pfcpClient.Close()
		return fmt.Errorf("initial SGW-U association: %w", err)
	}

	events := live.NewEventLog(200)
	events.Add("sgw-c", telemetry.SeverityInfo, "pfcp-association", "SGW-U association established", map[string]string{"peer": pfcpRemote.String()})
	gtpConfig := gtptransport.DefaultConfig()
	gtpConfig.RetransmitTimeout = retransmit
	gtpConfig.MaxRetransmits = value.MaxRetransmits
	control, err := gateway.New(gateway.Config{
		S11Listen: s11Listen, S11Advertise: s11Advertise,
		S5Listen: s5Listen, S5Advertise: s5Advertise, PGWControl: pgwControl, PGWRoutes: pgwRoutes,
		SGWUAccessIP: accessIP, SGWUCoreIP: coreIP, AllowedMME: allowedMME,
		RecoveryCounter: recoveryCounter, ProcedureTimeout: procedureTimeout, ReconcileWorkers: value.ReconcileWorkers,
		SubscriberSalt: []byte(value.SubscriberSalt), Transport: gtpConfig,
		PeerRecovery: peerRecovery, CommitPeerRecovery: commitPeerRecovery,
		AllowNewSessions: drainGate.AllowNewSession, OnEvent: events.GatewaySink,
	}, sessionStore, pfcpClient)
	if err != nil {
		_ = pfcpClient.Close()
		return err
	}
	reconciled, err := control.ReconcileAll(ctx)
	if err != nil {
		_ = control.Close()
		_ = pfcpClient.Close()
		return fmt.Errorf("initial SGW-U reconciliation after %d sessions: %w", reconciled, err)
	}
	reconcileCtx, reconcileCancel := context.WithTimeout(ctx, procedureTimeout)
	err = pfcpClient.CompleteReconciliation(reconcileCtx)
	reconcileCancel()
	if err != nil {
		_ = control.Close()
		_ = pfcpClient.Close()
		return fmt.Errorf("complete initial SGW-U reconciliation: %w", err)
	}
	events.Add("sgw-c", telemetry.SeverityInfo, "pfcp-reconciliation", "SGW-U authoritative state replay completed", map[string]string{"sessions": fmt.Sprint(reconciled)})
	var stateStats func() session.WALStats
	if stateWAL != nil {
		stateStats = stateWAL.Stats
	}
	provider := live.NewControlProvider(live.ControlConfig{
		Started: started, Recovery: recoveryCounter,
		MMEAddresses: value.AllowedMME, PGWAddress: value.PGWControl,
		SGWUAddress: value.PFCPRemote, SGWUMetricsURL: value.SGWUMetricsURL,
		DurableState: stateWAL != nil, RecoveredSessions: uint64(recoveredCount), StateStats: stateStats,
		AdmissionStats: drainGate.Stats,
	}, control, pfcpClient, events)
	httpServer := &http.Server{
		Addr:              value.ManagementListen,
		Handler:           api.NewHandler(provider, api.Config{AllowedOrigins: value.AllowedOrigins}),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	go func() { errCh <- control.Serve(ctx) }()
	go func() {
		err := httpServer.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	go provider.Run(ctx, time.Second)
	go heartbeat(ctx, control, pfcpClient, heartbeatInterval, procedureTimeout, events, logger)
	go downlinkReports(ctx, control, pfcpClient, logger)
	logger.Info("SGW-C started", "s11", control.S11Addr(), "s5c", control.S5Addr(), "sxa", pfcpRemote, "management", value.ManagementListen, "recovered_sessions", recoveredCount, "recovery_counter", recoveryCounter)

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
	closeErr := errors.Join(control.Close(), pfcpClient.Close())
	logger.Info("SGW-C shutdown complete")
	return errors.Join(runErr, httpErr, closeErr)
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

func sgwcStateIdentity(value config.SGWC) ([]byte, error) {
	allowedMME := append([]string(nil), value.AllowedMME...)
	sort.Strings(allowedMME)
	pgwRoutes := append([]config.SGWCPGWRoute(nil), value.PGWRoutes...)
	sort.Slice(pgwRoutes, func(i, j int) bool {
		if pgwRoutes[i].APN != pgwRoutes[j].APN {
			return pgwRoutes[i].APN < pgwRoutes[j].APN
		}
		return pgwRoutes[i].Address < pgwRoutes[j].Address
	})
	return json.Marshal(struct {
		Schema           uint8                 `json:"schema"`
		Component        string                `json:"component"`
		S11Listen        string                `json:"s11_listen"`
		S11Advertise     string                `json:"s11_advertise"`
		AllowedMME       []string              `json:"allowed_mme"`
		S5Listen         string                `json:"s5_listen"`
		S5Advertise      string                `json:"s5_advertise"`
		PGWControl       string                `json:"pgw_control"`
		PGWRoutes        []config.SGWCPGWRoute `json:"pgw_routes,omitempty"`
		PFCPListen       string                `json:"pfcp_listen"`
		PFCPAdvertise    string                `json:"pfcp_advertise"`
		PFCPRemote       string                `json:"pfcp_remote"`
		SGWUAccessIP     string                `json:"sgwu_access_ip"`
		SGWUCoreIP       string                `json:"sgwu_core_ip"`
		SubscriberSecret string                `json:"subscriber_secret"`
	}{
		Schema: 1, Component: "sgw-c", S11Listen: value.S11Listen, S11Advertise: value.S11Advertise,
		AllowedMME: allowedMME, S5Listen: value.S5Listen, S5Advertise: value.S5Advertise,
		PGWControl: value.PGWControl, PGWRoutes: pgwRoutes, PFCPListen: value.PFCPListen, PFCPAdvertise: value.PFCPAdvertise,
		PFCPRemote: value.PFCPRemote, SGWUAccessIP: value.SGWUAccessIP, SGWUCoreIP: value.SGWUCoreIP,
		SubscriberSecret: value.SubscriberSalt,
	})
}

func downlinkReports(ctx context.Context, control *gateway.Gateway, client *pfcpclient.Client, logger *slog.Logger) {
	for {
		select {
		case report := <-client.Reports():
			if err := control.HandleDownlinkReport(ctx, report); err != nil && ctx.Err() == nil {
				logger.Warn("idle downlink report handling failed", "cp_seid", report.CPSEID, "pdr_id", report.PDRID, "error", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func heartbeat(ctx context.Context, control *gateway.Gateway, client *pfcpclient.Client, interval, timeout time.Duration, events *live.EventLog, logger *slog.Logger) {
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
			logger.Warn("SGW-U heartbeat failed; entering grace/reconnect path", "error", err)
			opCtx, cancel = context.WithTimeout(ctx, timeout)
			err = client.Associate(opCtx)
			cancel()
			if errors.Is(err, pfcpclient.ErrPeerRestarted) {
				restarted = true
				err = nil
			}
			if err != nil {
				events.Add("sgw-c", telemetry.SeverityError, "pfcp-association", "SGW-U reassociation failed", nil)
				continue
			}
			reconciled, reconcileErr := control.ReconcileAll(ctx)
			if reconcileErr != nil {
				events.Add("sgw-c", telemetry.SeverityError, "pfcp-reconciliation", "SGW-U reconciliation incomplete", map[string]string{"reconciledSessions": fmt.Sprint(reconciled)})
				logger.Error("SGW-U session reconciliation incomplete", "sessions", reconciled, "restart", restarted, "error", reconcileErr)
				continue
			}
			opCtx, cancel = context.WithTimeout(ctx, timeout)
			reconcileErr = client.CompleteReconciliation(opCtx)
			cancel()
			if reconcileErr != nil {
				events.Add("sgw-c", telemetry.SeverityError, "pfcp-reconciliation", "SGW-U reconciliation completion failed", nil)
				logger.Error("SGW-U reconciliation completion failed", "error", reconcileErr)
				continue
			}
			events.Add("sgw-c", telemetry.SeverityInfo, "pfcp-reconciliation", "SGW-U sessions reconciled", map[string]string{"sessions": fmt.Sprint(reconciled)})
			logger.Info("SGW-U sessions reconciled", "sessions", reconciled, "restart", restarted)
		case <-ctx.Done():
			return
		}
	}
}
