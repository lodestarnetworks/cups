// cups-control-bench drives the real SGW-C, PGW-C, SGW-U PFCP server, and
// PGW-U PFCP/kernel-GTP path inside a disposable network namespace.
// It is a benchmark peer, not an LTE network function.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	gtptransport "github.com/lodestarnetworks/cups/internal/gtpv2/transport"
	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	pgwcgateway "github.com/lodestarnetworks/cups/internal/pgwc/gateway"
	"github.com/lodestarnetworks/cups/internal/pgwc/ipam"
	pgwcpfcp "github.com/lodestarnetworks/cups/internal/pgwc/pfcpclient"
	pgwcsession "github.com/lodestarnetworks/cups/internal/pgwc/session"
	pgwudataplane "github.com/lodestarnetworks/cups/internal/pgwu/dataplane"
	pgwupfcp "github.com/lodestarnetworks/cups/internal/pgwu/pfcpserver"
	pgwurules "github.com/lodestarnetworks/cups/internal/pgwu/rules"
	sgwcgateway "github.com/lodestarnetworks/cups/internal/sgwc/gateway"
	sgwcpfcp "github.com/lodestarnetworks/cups/internal/sgwc/pfcpclient"
	sgwcsession "github.com/lodestarnetworks/cups/internal/sgwc/session"
	sgwupfcp "github.com/lodestarnetworks/cups/internal/sgwu/pfcpserver"
	sgwurules "github.com/lodestarnetworks/cups/internal/sgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

const (
	guardEnvironment        = "SGW_NEXT_ISOLATED_CONTROL_BENCH"
	faultProfileEnvironment = "SGW_NEXT_CONTROL_FAULT_PROFILE"
	apn                     = "lodestartest"
	defaultEBI              = uint8(5)
	sgwcBenchmarkIdentity   = "cups-control-bench:sgw-c:v1"
	pgwcBenchmarkIdentity   = "cups-control-bench:pgw-c:v1"
)

var (
	mmeIP      = netip.MustParseAddr("10.254.101.1")
	sgwcS11IP  = netip.MustParseAddr("10.254.101.2")
	sgwcS5IP   = netip.MustParseAddr("10.254.102.1")
	pgwcS5IP   = netip.MustParseAddr("10.254.102.2")
	sgwcPFCPIP = netip.MustParseAddr("10.254.103.1")
	sgwuPFCPIP = netip.MustParseAddr("10.254.103.2")
	pgwcPFCPIP = netip.MustParseAddr("10.254.104.1")
	pgwuPFCPIP = netip.MustParseAddr("10.254.104.2")
	sgwuAccess = netip.MustParseAddr("10.254.105.1")
	enodebIP   = netip.MustParseAddr("10.254.105.2")
	sgwuCore   = netip.MustParseAddr("10.254.106.1")
	pgwuUser   = netip.MustParseAddr("10.254.106.2")
	uePool     = netip.MustParsePrefix("10.64.0.0/10")
	ueGateway  = netip.MustParseAddr("10.64.0.1")
)

type config struct {
	sessions          int
	concurrency       int
	serverWorkers     int
	reconcileWorkers  int
	procedureTimeout  time.Duration
	retransmitTimeout time.Duration
	maxRetransmits    int
	socketBuffer      int
	kernelHashSize    uint
	sgwcWALPath       string
	sgwcWALMaxBytes   int64
	pgwcWALPath       string
	pgwcWALMaxBytes   int64
	pgwuWALPath       string
	pgwuWALMaxBytes   int64
	restartControl    bool
	faultProfile      string
}

type latencyResult struct {
	Samples int     `json:"samples"`
	MinMS   float64 `json:"minimumMilliseconds"`
	P50MS   float64 `json:"p50Milliseconds"`
	P95MS   float64 `json:"p95Milliseconds"`
	P99MS   float64 `json:"p99Milliseconds"`
	MaxMS   float64 `json:"maximumMilliseconds"`
}

type phaseResult struct {
	Name                  string        `json:"name"`
	Attempted             int           `json:"attempted"`
	Succeeded             int           `json:"succeeded"`
	Failed                int           `json:"failed"`
	WallMilliseconds      float64       `json:"wallMilliseconds"`
	RequestsPerSecond     float64       `json:"requestsPerSecond"`
	TransactionsPerSecond float64       `json:"successfulTransactionsPerSecond"`
	Latency               latencyResult `json:"successfulLatency"`
	ErrorSamples          []string      `json:"errorSamples,omitempty"`
}

type stateSnapshot struct {
	SGWCSessions int `json:"sgwcSessions"`
	PGWCSessions int `json:"pgwcSessions"`
	SGWUSessions int `json:"sgwuSessions"`
	PGWUSessions int `json:"pgwuSessions"`
	IPv4Leases   int `json:"ipv4Leases"`
}

type transportSnapshot struct {
	MMEGTP   gtptransport.Counters  `json:"mmeGtp"`
	SGWCS11  gtptransport.Counters  `json:"sgwcS11"`
	SGWCS5   gtptransport.Counters  `json:"sgwcS5"`
	PGWCS5   gtptransport.Counters  `json:"pgwcS5"`
	SGWCPFCP pfcptransport.Counters `json:"sgwcPfcp"`
	SGWUPFCP pfcptransport.Counters `json:"sgwuPfcp"`
	PGWCPFCP pfcptransport.Counters `json:"pgwcPfcp"`
	PGWUPFCP pfcptransport.Counters `json:"pgwuPfcp"`
}

type result struct {
	Scope               string                 `json:"scope"`
	SessionsRequested   int                    `json:"sessionsRequested"`
	Concurrency         int                    `json:"concurrency"`
	ServerWorkers       int                    `json:"serverWorkers"`
	ReconcileWorkers    int                    `json:"reconcileWorkers"`
	ProcedureTimeoutMS  float64                `json:"procedureTimeoutMilliseconds"`
	RetransmitTimeoutMS float64                `json:"retransmitTimeoutMilliseconds"`
	MaxRetransmits      int                    `json:"maxRetransmits"`
	GOMAXPROCS          int                    `json:"goMaxProcs"`
	CPUAffinity         string                 `json:"cpuAffinity,omitempty"`
	Create              phaseResult            `json:"createSession"`
	Modify              phaseResult            `json:"modifyBearer"`
	Delete              phaseResult            `json:"deleteSession"`
	AfterCreate         stateSnapshot          `json:"stateAfterCreate"`
	AfterControlRestart stateSnapshot          `json:"stateAfterControlRestart"`
	AfterModify         stateSnapshot          `json:"stateAfterModify"`
	AfterDelete         stateSnapshot          `json:"stateAfterDelete"`
	SGWC                sgwcgateway.Counters   `json:"sgwcCounters"`
	PGWC                pgwcgateway.Counters   `json:"pgwcCounters"`
	SGWU                sgwupfcp.Counters      `json:"sgwuCounters"`
	PGWU                pgwupfcp.Counters      `json:"pgwuCounters"`
	PGWUBackend         pgwudataplane.Counters `json:"pgwuBackendCounters"`
	SGWCStateMode       string                 `json:"sgwcStateMode"`
	SGWCWAL             *sgwcsession.WALStats  `json:"sgwcWal,omitempty"`
	PGWCStateMode       string                 `json:"pgwcStateMode"`
	PGWCWAL             *pgwcsession.WALStats  `json:"pgwcWal,omitempty"`
	PGWUStateMode       string                 `json:"pgwuStateMode"`
	PGWUWAL             *pgwurules.WALStats    `json:"pgwuWal,omitempty"`
	Transport           transportSnapshot      `json:"transportCounters"`
	ControlRestarted    bool                   `json:"controlRestarted"`
	ControlRestartMS    float64                `json:"controlRestartMilliseconds"`
	FaultProfile        string                 `json:"faultProfile"`
	TransportFaultsSeen bool                   `json:"transportFaultsObserved"`
	Clean               bool                   `json:"clean"`
	ElapsedMilliseconds float64                `json:"elapsedMilliseconds"`
}

type sessionRecord struct {
	mmeTEID uint32
	sgwTEID uint32
	created bool
}

func main() {
	sessions := flag.Int("sessions", 1_000, "number of LTE sessions to create, modify, and delete")
	concurrency := flag.Int("concurrency", 64, "maximum concurrent MME procedures")
	serverWorkers := flag.Int("server-workers", 128, "worker limit on every GTP-C and PFCP server endpoint")
	reconcileWorkers := flag.Int("reconcile-workers", 64, "bounded workers used for SGW-C and PGW-C restart replay")
	procedureTimeout := flag.Duration("procedure-timeout", 5*time.Second, "timeout for each complete MME procedure")
	retransmitTimeout := flag.Duration("retransmit-timeout", time.Second, "GTP-C and PFCP response timeout before retransmission")
	maxRetransmits := flag.Int("max-retransmits", 3, "maximum GTP-C and PFCP retransmissions")
	socketBuffer := flag.Int("socket-buffer-bytes", 16<<20, "kernel GTP socket buffer request")
	kernelHashSize := flag.Uint("kernel-hash-size", 262_147, "PGW-U kernel GTP PDP hash buckets")
	sgwcWALPath := flag.String("sgwc-wal-path", "", "absolute path for fsync-before-acknowledgement SGW-C state (empty uses volatile state)")
	sgwcWALMaxBytes := flag.Int64("sgwc-wal-max-bytes", sgwcsession.DefaultWALMaxBytes, "maximum durable SGW-C WAL size")
	pgwcWALPath := flag.String("pgwc-wal-path", "", "absolute path for fsync-before-acknowledgement PGW-C state (empty uses volatile state)")
	pgwcWALMaxBytes := flag.Int64("pgwc-wal-max-bytes", pgwcsession.DefaultWALMaxBytes, "maximum durable PGW-C WAL size")
	pgwuWALPath := flag.String("pgwu-wal-path", "", "absolute path for fsync-before-acknowledgement PGW-U state (empty uses volatile state)")
	pgwuWALMaxBytes := flag.Int64("pgwu-wal-max-bytes", pgwurules.DefaultWALMaxBytes, "maximum durable PGW-U WAL size")
	restartControl := flag.Bool("restart-control-planes", false, "restart and reconcile SGW-C and PGW-C after create before modify/delete")
	flag.Parse()

	value, err := run(config{
		sessions: *sessions, concurrency: *concurrency, serverWorkers: *serverWorkers, reconcileWorkers: *reconcileWorkers,
		procedureTimeout: *procedureTimeout, retransmitTimeout: *retransmitTimeout,
		maxRetransmits: *maxRetransmits, socketBuffer: *socketBuffer, kernelHashSize: *kernelHashSize,
		sgwcWALPath: *sgwcWALPath, sgwcWALMaxBytes: *sgwcWALMaxBytes,
		pgwcWALPath: *pgwcWALPath, pgwcWALMaxBytes: *pgwcWALMaxBytes,
		pgwuWALPath: *pgwuWALPath, pgwuWALMaxBytes: *pgwuWALMaxBytes,
		restartControl: *restartControl,
		faultProfile:   os.Getenv(faultProfileEnvironment),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(cfg config) (result, error) {
	started := time.Now()
	if err := validateEnvironment(cfg); err != nil {
		return result{}, err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	gtpConfig := gtptransport.DefaultConfig()
	gtpConfig.RetransmitTimeout = cfg.retransmitTimeout
	gtpConfig.MaxRetransmits = cfg.maxRetransmits
	gtpConfig.MaxWorkers = cfg.serverWorkers
	pfcpConfig := pfcptransport.DefaultConfig()
	pfcpConfig.RetransmitTimeout = cfg.retransmitTimeout
	pfcpConfig.MaxRetransmits = cfg.maxRetransmits
	pfcpConfig.MaxWorkers = cfg.serverWorkers

	sgwuStore := sgwurules.NewStoreWithLimit(cfg.sessions)
	sgwuServer, err := sgwupfcp.New(sgwupfcp.Config{
		Listen: netip.AddrPortFrom(sgwuPFCPIP, 0), Advertise: sgwuPFCPIP,
		AccessUserIP: sgwuAccess, CoreUserIP: sgwuCore, AllowedCP: []netip.Addr{sgwcPFCPIP},
		StartedAt: time.Now().UTC(), AssociationTimeout: time.Hour, GraceWindow: time.Minute, Transport: pfcpConfig,
	}, sgwuStore)
	if err != nil {
		return result{}, fmt.Errorf("start SGW-U PFCP server: %w", err)
	}
	defer sgwuServer.Close()

	kernelOwnerDirectory, err := os.MkdirTemp("", "sgw-next-control-kernel-owner-")
	if err != nil {
		return result{}, fmt.Errorf("create temporary kernel ownership directory: %w", err)
	}
	defer os.RemoveAll(kernelOwnerDirectory)
	pgwuBackend, err := pgwudataplane.OpenKernel(pgwudataplane.KernelConfig{
		S5: netip.AddrPortFrom(pgwuUser, 2152), AllowedSGWPeers: []netip.Addr{sgwuCore},
		TunnelName: "lodctrlpgw", OwnershipFile: filepath.Join(kernelOwnerDirectory, "kernel.owner"),
		UEPoolPrefix: uePool, UEGateway: ueGateway,
		HashSize: uint32(cfg.kernelHashSize), MTU: 1_400, SocketBufferBytes: cfg.socketBuffer,
		AllowUnsupportedPolicy: true,
	})
	if err != nil {
		return result{}, fmt.Errorf("start PGW-U kernel dataplane: %w", err)
	}
	defer pgwuBackend.Close()
	pgwuStateMode := "volatile-upper-bound"
	var pgwuWAL *pgwurules.WAL
	if cfg.pgwuWALPath != "" {
		var recovered []pgwurules.Session
		pgwuWAL, recovered, err = pgwurules.OpenWAL(cfg.pgwuWALPath, cfg.pgwuWALMaxBytes)
		if err != nil {
			return result{}, fmt.Errorf("open PGW-U benchmark WAL: %w", err)
		}
		defer pgwuWAL.Close()
		if len(recovered) != 0 || pgwuWAL.Stats().Records != 0 {
			return result{}, errors.New("PGW-U benchmark WAL must not contain prior records or recovered sessions")
		}
		pgwuStateMode = "durable-fsync-before-acknowledgement"
	}
	var pgwuStore *pgwurules.Store
	if pgwuWAL == nil {
		pgwuStore = pgwurules.NewStoreWithApplier(cfg.sessions, pgwuBackend)
	} else {
		pgwuStore = pgwurules.NewStoreWithParticipants(cfg.sessions, pgwuBackend, pgwuWAL)
	}
	pgwuServer, err := pgwupfcp.New(pgwupfcp.Config{
		Listen: netip.AddrPortFrom(pgwuPFCPIP, 0), Advertise: pgwuPFCPIP, UserIP: pgwuUser,
		AllowedCP: []netip.Addr{pgwcPFCPIP}, StartedAt: time.Now().UTC(),
		AssociationTimeout: time.Hour, GraceWindow: time.Minute, Transport: pfcpConfig,
	}, pgwuStore)
	if err != nil {
		return result{}, fmt.Errorf("start PGW-U PFCP server: %w", err)
	}
	defer pgwuServer.Close()

	child, cancel := context.WithCancel(ctx)
	defer cancel()
	serveErrors := make(chan error, 9)
	start := func(name string, serve func(context.Context) error) {
		go func() {
			if err := serve(child); err != nil && child.Err() == nil {
				serveErrors <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}
	start("sgwu-pfcp", sgwuServer.Serve)
	start("pgwu-pfcp", pgwuServer.Serve)
	start("pgwu-kernel", pgwuBackend.Serve)

	sgwcPFCP, err := sgwcpfcp.New(sgwcpfcp.Config{
		Listen: netip.AddrPortFrom(sgwcPFCPIP, 0), Advertise: sgwcPFCPIP,
		Remote: sgwuServer.LocalAddr(), StartedAt: time.Now().UTC(), Transport: pfcpConfig,
	})
	if err != nil {
		return result{}, err
	}
	defer func() {
		if sgwcPFCP != nil {
			_ = sgwcPFCP.Close()
		}
	}()
	start("sgwc-pfcp", sgwcPFCP.Serve)
	if err := associate(ctx, cfg.procedureTimeout, sgwcPFCP.Associate); err != nil {
		return result{}, fmt.Errorf("associate SGW-C to SGW-U: %w", err)
	}

	pgwcPFCP, err := pgwcpfcp.New(pgwcpfcp.Config{
		Listen: netip.AddrPortFrom(pgwcPFCPIP, 0), Advertise: pgwcPFCPIP,
		Remote: pgwuServer.LocalAddr(), StartedAt: time.Now().UTC(), Transport: pfcpConfig,
	})
	if err != nil {
		return result{}, err
	}
	defer func() {
		if pgwcPFCP != nil {
			_ = pgwcPFCP.Close()
		}
	}()
	start("pgwc-pfcp", pgwcPFCP.Serve)
	if err := associate(ctx, cfg.procedureTimeout, pgwcPFCP.Associate); err != nil {
		return result{}, fmt.Errorf("associate PGW-C to PGW-U: %w", err)
	}

	sgwcStateMode := "volatile-upper-bound"
	var sgwcWAL *sgwcsession.WAL
	if cfg.sgwcWALPath != "" {
		var recovered []sgwcsession.Session
		sgwcWAL, recovered, err = sgwcsession.OpenWAL(cfg.sgwcWALPath, cfg.sgwcWALMaxBytes, []byte(sgwcBenchmarkIdentity), 1)
		if err != nil {
			return result{}, fmt.Errorf("open SGW-C benchmark WAL: %w", err)
		}
		defer func() {
			if sgwcWAL != nil {
				_ = sgwcWAL.Close()
			}
		}()
		if len(recovered) != 0 || sgwcWAL.Stats().DataRecords != 0 {
			return result{}, errors.New("SGW-C benchmark WAL must not contain prior transitions or recovered sessions")
		}
		sgwcStateMode = "durable-fsync-before-acknowledgement"
	}
	pgwcStateMode := "volatile-upper-bound"
	var pgwcWAL *pgwcsession.WAL
	if cfg.pgwcWALPath != "" {
		var recovered []pgwcsession.Session
		pgwcWAL, recovered, err = pgwcsession.OpenWAL(cfg.pgwcWALPath, cfg.pgwcWALMaxBytes, []byte(pgwcBenchmarkIdentity), 1)
		if err != nil {
			return result{}, fmt.Errorf("open PGW-C benchmark WAL: %w", err)
		}
		defer func() {
			if pgwcWAL != nil {
				_ = pgwcWAL.Close()
			}
		}()
		if len(recovered) != 0 || pgwcWAL.Stats().DataRecords != 0 {
			return result{}, errors.New("PGW-C benchmark WAL must not contain prior transitions or recovered sessions")
		}
		pgwcStateMode = "durable-fsync-before-acknowledgement"
	}

	addressPool, err := ipam.New(uePool, ueGateway, cfg.sessions)
	if err != nil {
		return result{}, err
	}
	var pgwcPersister pgwcsession.Persister
	if pgwcWAL != nil {
		pgwcPersister = pgwcWAL
	}
	pgwcStore := pgwcsession.NewStoreWithPersister(cfg.sessions, pgwcPersister)
	if pgwcWAL != nil {
		if err := pgwcWAL.Start(); err != nil {
			return result{}, fmt.Errorf("start PGW-C benchmark WAL: %w", err)
		}
	}
	pgwc, err := pgwcgateway.New(pgwcgateway.Config{
		S5Listen: netip.AddrPortFrom(pgwcS5IP, 0), S5Advertise: pgwcS5IP,
		PGWUUserIP: pgwuUser, AllowedSGW: []netip.Addr{sgwcS5IP}, APN: apn,
		RecoveryCounter: 1, ProcedureTimeout: cfg.procedureTimeout, ReconcileWorkers: cfg.reconcileWorkers,
		SubscriberSalt: []byte("lodestar-control-benchmark"), Transport: gtpConfig,
	}, pgwcStore, addressPool, pgwcPFCP)
	if err != nil {
		return result{}, err
	}
	defer func() {
		if pgwc != nil {
			_ = pgwc.Close()
		}
	}()
	start("pgwc-gtp", pgwc.Serve)

	var sgwcPersister sgwcsession.Persister
	if sgwcWAL != nil {
		sgwcPersister = sgwcWAL
	}
	sgwcStore := sgwcsession.NewStoreWithPersister(cfg.sessions, sgwcPersister)
	if sgwcWAL != nil {
		if err := sgwcWAL.Start(); err != nil {
			return result{}, fmt.Errorf("start SGW-C benchmark WAL: %w", err)
		}
	}
	sgwc, err := sgwcgateway.New(sgwcgateway.Config{
		S11Listen: netip.AddrPortFrom(sgwcS11IP, 0), S11Advertise: sgwcS11IP,
		S5Listen: netip.AddrPortFrom(sgwcS5IP, 0), S5Advertise: sgwcS5IP,
		PGWControl: pgwc.S5Addr(), SGWUAccessIP: sgwuAccess, SGWUCoreIP: sgwuCore,
		AllowedMME: []netip.Addr{mmeIP}, RecoveryCounter: 1, ProcedureTimeout: cfg.procedureTimeout, ReconcileWorkers: cfg.reconcileWorkers,
		SubscriberSalt: []byte("lodestar-control-benchmark"), Transport: gtpConfig,
	}, sgwcStore, sgwcPFCP)
	if err != nil {
		return result{}, err
	}
	defer func() {
		if sgwc != nil {
			_ = sgwc.Close()
		}
	}()
	start("sgwc-gtp", sgwc.Serve)

	mme, err := gtptransport.Listen(netip.AddrPortFrom(mmeIP, 0), nil, gtpConfig)
	if err != nil {
		return result{}, err
	}
	defer mme.Close()
	start("mme-gtp", mme.Serve)

	records := make([]sessionRecord, cfg.sessions)
	create := runPhase(ctx, "create-session", indexes(cfg.sessions), cfg.concurrency, func(operation context.Context, index int) error {
		request, mmeTEID, err := createRequest(index)
		if err != nil {
			return err
		}
		response, err := mme.Do(operation, sgwc.S11Addr(), request)
		if err != nil {
			return err
		}
		if err := accepted(response); err != nil {
			return err
		}
		controlIE, ok := response.Find(gtpv2.IEFTEID, 0)
		if !ok {
			return errors.New("Create Session response omitted SGW S11 F-TEID")
		}
		control, err := controlIE.FTEID()
		if err != nil || control.InterfaceType != gtpv2.InterfaceS11SGWGTPC || control.TEID == 0 {
			return errors.New("Create Session response had invalid SGW S11 F-TEID")
		}
		records[index] = sessionRecord{mmeTEID: mmeTEID, sgwTEID: control.TEID, created: true}
		return nil
	}, cfg.procedureTimeout)
	afterCreate := snapshotState(sgwcStore, pgwcStore, sgwuStore, pgwuStore, addressPool)
	afterControlRestart := stateSnapshot{}
	controlRestartMilliseconds := float64(0)
	if cfg.restartControl {
		restartStarted := time.Now()
		sgwcS11Listen := sgwc.S11Addr()
		sgwcS5Listen := sgwc.S5Addr()
		pgwcS5Listen := pgwc.S5Addr()
		sgwcPFCPListen := sgwcPFCP.LocalAddr()
		pgwcPFCPListen := pgwcPFCP.LocalAddr()
		if err := errors.Join(sgwc.Close(), pgwc.Close(), sgwcPFCP.Close(), pgwcPFCP.Close(), sgwcWAL.Close(), pgwcWAL.Close()); err != nil {
			return result{}, fmt.Errorf("stop control planes for restart: %w", err)
		}
		// This harness performs two production process lifetimes inside one Go
		// process. Drop every closed pre-restart owner before replay so peak RSS
		// does not count memory that a real process exit would have released.
		sgwc, pgwc, sgwcPFCP, pgwcPFCP, sgwcWAL, pgwcWAL = nil, nil, nil, nil, nil, nil
		sgwcStore, pgwcStore, addressPool = nil, nil, nil
		runtime.GC()

		var recoveredSGWC []sgwcsession.Session
		sgwcWAL, recoveredSGWC, err = sgwcsession.OpenWAL(cfg.sgwcWALPath, cfg.sgwcWALMaxBytes, []byte(sgwcBenchmarkIdentity), 1)
		if err != nil {
			return result{}, fmt.Errorf("reopen SGW-C benchmark WAL: %w", err)
		}
		if len(recoveredSGWC) != cfg.sessions || sgwcWAL.RecoveryCounter() != 2 {
			return result{}, fmt.Errorf("SGW-C restart recovered %d sessions at counter %d; want %d sessions at counter 2", len(recoveredSGWC), sgwcWAL.RecoveryCounter(), cfg.sessions)
		}
		sgwcStore = sgwcsession.NewStoreWithPersister(cfg.sessions, sgwcWAL)
		if err := sgwcStore.Restore(recoveredSGWC); err != nil {
			return result{}, fmt.Errorf("restore SGW-C benchmark sessions: %w", err)
		}
		if err := sgwcWAL.Start(); err != nil {
			return result{}, fmt.Errorf("start recovered SGW-C benchmark WAL: %w", err)
		}
		recoveredSGWC = nil

		var recoveredPGWC []pgwcsession.Session
		pgwcWAL, recoveredPGWC, err = pgwcsession.OpenWAL(cfg.pgwcWALPath, cfg.pgwcWALMaxBytes, []byte(pgwcBenchmarkIdentity), 1)
		if err != nil {
			return result{}, fmt.Errorf("reopen PGW-C benchmark WAL: %w", err)
		}
		if len(recoveredPGWC) != cfg.sessions || pgwcWAL.RecoveryCounter() != 2 {
			return result{}, fmt.Errorf("PGW-C restart recovered %d sessions at counter %d; want %d sessions at counter 2", len(recoveredPGWC), pgwcWAL.RecoveryCounter(), cfg.sessions)
		}
		pgwcStore = pgwcsession.NewStoreWithPersister(cfg.sessions, pgwcWAL)
		if err := pgwcStore.Restore(recoveredPGWC); err != nil {
			return result{}, fmt.Errorf("restore PGW-C benchmark sessions: %w", err)
		}
		addressPool, err = ipam.New(uePool, ueGateway, cfg.sessions)
		if err != nil {
			return result{}, err
		}
		leases := make([]ipam.Lease, 0, len(recoveredPGWC))
		for _, current := range recoveredPGWC {
			leases = append(leases, ipam.Lease{Owner: current.SubscriberKey + "\x00" + current.APN, Addr: current.UEIPv4})
		}
		if err := addressPool.Restore(leases); err != nil {
			return result{}, fmt.Errorf("restore PGW-C benchmark leases: %w", err)
		}
		if err := pgwcWAL.Start(); err != nil {
			return result{}, fmt.Errorf("start recovered PGW-C benchmark WAL: %w", err)
		}
		recoveredPGWC, leases = nil, nil

		restartEpoch := time.Now().UTC().Add(time.Second)
		pgwcPFCP, err = pgwcpfcp.New(pgwcpfcp.Config{
			Listen: pgwcPFCPListen, Advertise: pgwcPFCPIP,
			Remote: pgwuServer.LocalAddr(), StartedAt: restartEpoch, Transport: pfcpConfig,
		})
		if err != nil {
			return result{}, fmt.Errorf("restart PGW-C PFCP: %w", err)
		}
		start("pgwc-pfcp-restart", pgwcPFCP.Serve)
		if err := associate(ctx, cfg.procedureTimeout, pgwcPFCP.Associate); err != nil {
			return result{}, fmt.Errorf("reassociate PGW-C to PGW-U: %w", err)
		}
		pgwc, err = pgwcgateway.New(pgwcgateway.Config{
			S5Listen: pgwcS5Listen, S5Advertise: pgwcS5IP,
			PGWUUserIP: pgwuUser, AllowedSGW: []netip.Addr{sgwcS5IP}, APN: apn,
			RecoveryCounter: pgwcWAL.RecoveryCounter(), ProcedureTimeout: cfg.procedureTimeout, ReconcileWorkers: cfg.reconcileWorkers,
			SubscriberSalt: []byte("lodestar-control-benchmark"), Transport: gtpConfig,
		}, pgwcStore, addressPool, pgwcPFCP)
		if err != nil {
			return result{}, fmt.Errorf("restart PGW-C GTP: %w", err)
		}
		reconciledPGWC, err := pgwc.ReconcileAll(ctx)
		if err != nil {
			return result{}, fmt.Errorf("reconcile PGW-C sessions after %d successes: %w", reconciledPGWC, err)
		}
		if reconciledPGWC != cfg.sessions {
			return result{}, fmt.Errorf("reconcile PGW-C sessions: reconciled=%d, want %d", reconciledPGWC, cfg.sessions)
		}
		if err := associate(ctx, cfg.procedureTimeout, pgwcPFCP.CompleteReconciliation); err != nil {
			return result{}, fmt.Errorf("complete PGW-C reconciliation: %w", err)
		}
		start("pgwc-gtp-restart", pgwc.Serve)

		sgwcPFCP, err = sgwcpfcp.New(sgwcpfcp.Config{
			Listen: sgwcPFCPListen, Advertise: sgwcPFCPIP,
			Remote: sgwuServer.LocalAddr(), StartedAt: restartEpoch, Transport: pfcpConfig,
		})
		if err != nil {
			return result{}, fmt.Errorf("restart SGW-C PFCP: %w", err)
		}
		start("sgwc-pfcp-restart", sgwcPFCP.Serve)
		if err := associate(ctx, cfg.procedureTimeout, sgwcPFCP.Associate); err != nil {
			return result{}, fmt.Errorf("reassociate SGW-C to SGW-U: %w", err)
		}
		sgwc, err = sgwcgateway.New(sgwcgateway.Config{
			S11Listen: sgwcS11Listen, S11Advertise: sgwcS11IP,
			S5Listen: sgwcS5Listen, S5Advertise: sgwcS5IP,
			PGWControl: pgwc.S5Addr(), SGWUAccessIP: sgwuAccess, SGWUCoreIP: sgwuCore,
			AllowedMME: []netip.Addr{mmeIP}, RecoveryCounter: sgwcWAL.RecoveryCounter(), ProcedureTimeout: cfg.procedureTimeout, ReconcileWorkers: cfg.reconcileWorkers,
			SubscriberSalt: []byte("lodestar-control-benchmark"), Transport: gtpConfig,
		}, sgwcStore, sgwcPFCP)
		if err != nil {
			return result{}, fmt.Errorf("restart SGW-C GTP: %w", err)
		}
		reconciledSGWC, err := sgwc.ReconcileAll(ctx)
		if err != nil {
			return result{}, fmt.Errorf("reconcile SGW-C sessions after %d successes: %w", reconciledSGWC, err)
		}
		if reconciledSGWC != cfg.sessions {
			return result{}, fmt.Errorf("reconcile SGW-C sessions: reconciled=%d, want %d", reconciledSGWC, cfg.sessions)
		}
		if err := associate(ctx, cfg.procedureTimeout, sgwcPFCP.CompleteReconciliation); err != nil {
			return result{}, fmt.Errorf("complete SGW-C reconciliation: %w", err)
		}
		start("sgwc-gtp-restart", sgwc.Serve)
		afterControlRestart = snapshotState(sgwcStore, pgwcStore, sgwuStore, pgwuStore, addressPool)
		controlRestartMilliseconds = float64(time.Since(restartStarted).Microseconds()) / 1_000
	}

	createdIndexes := make([]int, 0, create.Succeeded)
	for index := range records {
		if records[index].created {
			createdIndexes = append(createdIndexes, index)
		}
	}
	modify := runPhase(ctx, "modify-bearer", createdIndexes, cfg.concurrency, func(operation context.Context, index int) error {
		request, err := modifyRequest(records[index].sgwTEID, index)
		if err != nil {
			return err
		}
		response, err := mme.Do(operation, sgwc.S11Addr(), request)
		if err != nil {
			return err
		}
		return accepted(response)
	}, cfg.procedureTimeout)
	afterModify := snapshotState(sgwcStore, pgwcStore, sgwuStore, pgwuStore, addressPool)

	deletePhase := runPhase(ctx, "delete-session", createdIndexes, cfg.concurrency, func(operation context.Context, index int) error {
		request := deleteRequest(records[index].sgwTEID)
		response, err := mme.Do(operation, sgwc.S11Addr(), request)
		if err != nil {
			return err
		}
		return accepted(response)
	}, cfg.procedureTimeout)
	afterDelete := snapshotState(sgwcStore, pgwcStore, sgwuStore, pgwuStore, addressPool)

	s11Counters, s5Counters := sgwc.TransportCounters()
	transports := transportSnapshot{
		MMEGTP: mme.Counters(), SGWCS11: s11Counters, SGWCS5: s5Counters, PGWCS5: pgwc.TransportCounters(),
		SGWCPFCP: sgwcPFCP.TransportCounters(), SGWUPFCP: sgwuServer.TransportCounters(),
		PGWCPFCP: pgwcPFCP.TransportCounters(), PGWUPFCP: pgwuServer.TransportCounters(),
	}
	pgwuPacketCounters := pgwuBackend.Counters()
	var pgwuWALStats *pgwurules.WALStats
	if pgwuWAL != nil {
		stats := pgwuWAL.Stats()
		pgwuWALStats = &stats
	}
	var sgwcWALStats *sgwcsession.WALStats
	if sgwcWAL != nil {
		stats := sgwcWAL.Stats()
		sgwcWALStats = &stats
	}
	var pgwcWALStats *pgwcsession.WALStats
	if pgwcWAL != nil {
		stats := pgwcWAL.Stats()
		pgwcWALStats = &stats
	}
	transportFaultsSeen := transportFaultsObserved(transports)
	transportHealthy := cleanTransports(transports)
	if cfg.faultProfile != "none" {
		transportHealthy = resilientTransports(transports) && transportFaultsSeen
	}
	clean := create.Failed == 0 && modify.Failed == 0 && deletePhase.Failed == 0 &&
		afterCreate.SGWCSessions == cfg.sessions && afterCreate.PGWCSessions == cfg.sessions &&
		afterCreate.SGWUSessions == cfg.sessions && afterCreate.PGWUSessions == cfg.sessions && afterCreate.IPv4Leases == cfg.sessions &&
		afterDelete == (stateSnapshot{}) && transportHealthy && pgwuPacketCounters.DroppedPackets == 0
	if cfg.restartControl {
		clean = clean && afterControlRestart == afterCreate &&
			sgwuServer.Counters().Reconciliations == 1 && pgwuServer.Counters().Reconciliations == 1 &&
			sgwuServer.Counters().StaleSessionsPurged == 0 && pgwuServer.Counters().StaleSessionsPurged == 0
	}
	if pgwuWALStats != nil {
		clean = clean && pgwuWALStats.Records == uint64(2*cfg.sessions)
	}
	if sgwcWALStats != nil {
		clean = clean && sgwcWALStats.DataRecords > 0
	}
	if pgwcWALStats != nil {
		clean = clean && pgwcWALStats.DataRecords > 0
	}

	select {
	case componentErr := <-serveErrors:
		return result{}, componentErr
	default:
	}
	return result{
		Scope:             "real SGW-C -> PGW-C GTPv2-C with real Sxa/Sxb PFCP and PGW-U Linux kernel-GTP context programming in one disposable network namespace",
		SessionsRequested: cfg.sessions, Concurrency: cfg.concurrency, ServerWorkers: cfg.serverWorkers, ReconcileWorkers: cfg.reconcileWorkers,
		ProcedureTimeoutMS:  float64(cfg.procedureTimeout.Microseconds()) / 1_000,
		RetransmitTimeoutMS: float64(cfg.retransmitTimeout.Microseconds()) / 1_000, MaxRetransmits: cfg.maxRetransmits,
		GOMAXPROCS: runtime.GOMAXPROCS(0), CPUAffinity: os.Getenv("BENCH_CPU_LIST"),
		Create: create, Modify: modify, Delete: deletePhase,
		AfterCreate: afterCreate, AfterControlRestart: afterControlRestart, AfterModify: afterModify, AfterDelete: afterDelete,
		SGWC: sgwc.Counters(), PGWC: pgwc.Counters(), SGWU: sgwuServer.Counters(), PGWU: pgwuServer.Counters(),
		PGWUBackend:   pgwuPacketCounters,
		SGWCStateMode: sgwcStateMode, SGWCWAL: sgwcWALStats,
		PGWCStateMode: pgwcStateMode, PGWCWAL: pgwcWALStats,
		PGWUStateMode: pgwuStateMode, PGWUWAL: pgwuWALStats,
		Transport: transports, ControlRestarted: cfg.restartControl, ControlRestartMS: controlRestartMilliseconds,
		FaultProfile: cfg.faultProfile, TransportFaultsSeen: transportFaultsSeen, Clean: clean,
		ElapsedMilliseconds: float64(time.Since(started).Microseconds()) / 1_000,
	}, nil
}

func validateEnvironment(cfg config) error {
	if os.Getenv(guardEnvironment) != "1" {
		return fmt.Errorf("cups-control-bench refuses to run unless %s=1", guardEnvironment)
	}
	if cfg.faultProfile == "" {
		cfg.faultProfile = "none"
	}
	if cfg.faultProfile != "none" && cfg.faultProfile != "loss-duplicate-reorder" {
		return fmt.Errorf("unsupported control fault profile %q", cfg.faultProfile)
	}
	if os.Geteuid() != 0 {
		return errors.New("cups-control-bench requires root inside a disposable network namespace")
	}
	selfNS, selfErr := os.Readlink("/proc/self/ns/net")
	initNS, initErr := os.Readlink("/proc/1/ns/net")
	if selfErr == nil && initErr == nil && selfNS == initNS {
		return errors.New("cups-control-bench refuses to run in the initial network namespace")
	}
	if cfg.sessions < 1 || cfg.sessions > 1_000_000 {
		return errors.New("sessions must be between 1 and 1000000")
	}
	if cfg.concurrency < 1 || cfg.concurrency > 16_384 {
		return errors.New("concurrency must be between 1 and 16384")
	}
	if cfg.serverWorkers < 1 || cfg.serverWorkers > 16_384 {
		return errors.New("server-workers must be between 1 and 16384")
	}
	if cfg.reconcileWorkers < 1 || cfg.reconcileWorkers > 1_024 {
		return errors.New("reconcile-workers must be between 1 and 1024")
	}
	if cfg.procedureTimeout < 100*time.Millisecond || cfg.procedureTimeout > time.Minute {
		return errors.New("procedure-timeout must be between 100ms and 1m")
	}
	if cfg.retransmitTimeout < time.Millisecond || cfg.retransmitTimeout > time.Minute {
		return errors.New("retransmit-timeout must be between 1ms and 1m")
	}
	if cfg.maxRetransmits < 0 || cfg.maxRetransmits > 100 {
		return errors.New("max-retransmits must be between 0 and 100")
	}
	if cfg.socketBuffer < 64*1024 || cfg.socketBuffer > 1<<30 {
		return errors.New("socket-buffer-bytes must be between 65536 and 1073741824")
	}
	if cfg.kernelHashSize < 1_024 || cfg.kernelHashSize > 16_777_216 {
		return errors.New("kernel-hash-size must be between 1024 and 16777216")
	}
	if cfg.restartControl && (cfg.sgwcWALPath == "" || cfg.pgwcWALPath == "") {
		return errors.New("restart-control-planes requires both sgwc-wal-path and pgwc-wal-path")
	}
	statePaths := make(map[string]string)
	for _, state := range []struct {
		name     string
		path     string
		maxBytes int64
	}{
		{name: "sgwc", path: cfg.sgwcWALPath, maxBytes: cfg.sgwcWALMaxBytes},
		{name: "pgwc", path: cfg.pgwcWALPath, maxBytes: cfg.pgwcWALMaxBytes},
		{name: "pgwu", path: cfg.pgwuWALPath, maxBytes: cfg.pgwuWALMaxBytes},
	} {
		if state.path == "" {
			continue
		}
		cleaned := filepath.Clean(state.path)
		if !filepath.IsAbs(cleaned) || cleaned == string(filepath.Separator) {
			return fmt.Errorf("%s-wal-path must be an absolute non-root file path", state.name)
		}
		if previous, exists := statePaths[cleaned]; exists {
			return fmt.Errorf("%s and %s WAL paths must be different", previous, state.name)
		}
		statePaths[cleaned] = state.name
		if state.maxBytes < 1<<20 {
			return fmt.Errorf("%s-wal-max-bytes must be at least 1048576", state.name)
		}
	}
	return nil
}

func associate(parent context.Context, timeout time.Duration, operation func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return operation(ctx)
}

func indexes(count int) []int {
	values := make([]int, count)
	for index := range values {
		values[index] = index
	}
	return values
}

func runPhase(parent context.Context, name string, indexes []int, concurrency int, operation func(context.Context, int) error, timeout time.Duration) phaseResult {
	started := time.Now()
	if concurrency > len(indexes) {
		concurrency = len(indexes)
	}
	if concurrency == 0 {
		return phaseResult{Name: name}
	}
	durations := make([]int64, len(indexes))
	jobs := make(chan int)
	var succeeded atomic.Int64
	var errorsMu sync.Mutex
	errorSamples := make([]string, 0, 8)
	var workers sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for position := range jobs {
				operationCtx, cancel := context.WithTimeout(parent, timeout)
				operationStarted := time.Now()
				err := operation(operationCtx, indexes[position])
				duration := time.Since(operationStarted).Nanoseconds()
				cancel()
				if err == nil {
					durations[position] = duration
					succeeded.Add(1)
					continue
				}
				durations[position] = -duration
				errorsMu.Lock()
				if len(errorSamples) < cap(errorSamples) {
					errorSamples = append(errorSamples, err.Error())
				}
				errorsMu.Unlock()
			}
		}()
	}
	for position := range indexes {
		jobs <- position
	}
	close(jobs)
	workers.Wait()
	wall := time.Since(started)
	successDurations := make([]int64, 0, succeeded.Load())
	for _, duration := range durations {
		if duration > 0 {
			successDurations = append(successDurations, duration)
		}
	}
	success := int(succeeded.Load())
	return phaseResult{
		Name: name, Attempted: len(indexes), Succeeded: success, Failed: len(indexes) - success,
		WallMilliseconds:  float64(wall.Microseconds()) / 1_000,
		RequestsPerSecond: float64(len(indexes)) / wall.Seconds(), TransactionsPerSecond: float64(success) / wall.Seconds(),
		Latency: summarizeLatency(successDurations), ErrorSamples: errorSamples,
	}
}

func summarizeLatency(values []int64) latencyResult {
	if len(values) == 0 {
		return latencyResult{}
	}
	sort.Slice(values, func(left, right int) bool { return values[left] < values[right] })
	milliseconds := func(value int64) float64 { return float64(value) / float64(time.Millisecond) }
	quantile := func(value float64) float64 {
		index := int(math.Ceil(float64(len(values))*value)) - 1
		if index < 0 {
			index = 0
		}
		return milliseconds(values[index])
	}
	return latencyResult{
		Samples: len(values), MinMS: milliseconds(values[0]), P50MS: quantile(0.50),
		P95MS: quantile(0.95), P99MS: quantile(0.99), MaxMS: milliseconds(values[len(values)-1]),
	}
}

func createRequest(index int) (gtpv2.Message, uint32, error) {
	imsi, err := gtpv2.NewIMSIIE(fmt.Sprintf("%015d", uint64(901_740_000_000_000+index)))
	if err != nil {
		return gtpv2.Message{}, 0, err
	}
	apnIE, _ := gtpv2.NewAPNIE(apn)
	mmeTEID := uint32(0x1000_0000 + index + 1)
	mmeControl, err := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS11MMEGTPC, TEID: mmeTEID, IPv4: mmeIP,
	})
	if err != nil {
		return gtpv2.Message{}, 0, err
	}
	ebi, _ := gtpv2.NewEBIIE(defaultEBI, 0)
	qos, _ := gtpv2.NewBearerQoSIEWithBitrates(0, 9, 8, 1_000_000_000, 1_000_000_000, 0, 0)
	bearer, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebi, qos)
	if err != nil {
		return gtpv2.Message{}, 0, err
	}
	pdnType, _ := gtpv2.NewPDNTypeIE(0, gtpv2.PDNTypeIPv4)
	ambr, _ := gtpv2.NewAMBRIE(0, 1_000_000_000, 1_000_000_000)
	return gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageCreateSessionRequest},
		IEs:    []gtpv2.IE{imsi, apnIE, mmeControl, pdnType, ambr, bearer},
	}, mmeTEID, nil
}

func modifyRequest(sgwTEID uint32, index int) (gtpv2.Message, error) {
	ebi, _ := gtpv2.NewEBIIE(defaultEBI, 0)
	enodeb, err := gtpv2.NewFTEIDIE(0, gtpv2.FTEID{
		InterfaceType: gtpv2.InterfaceS1UENodeBGTPU, TEID: uint32(0x2000_0000 + index + 1), IPv4: enodebIP,
	})
	if err != nil {
		return gtpv2.Message{}, err
	}
	bearer, err := gtpv2.NewGroupedIE(gtpv2.IEBearerContext, 0, ebi, enodeb)
	if err != nil {
		return gtpv2.Message{}, err
	}
	return gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageModifyBearerRequest, TEID: sgwTEID},
		IEs:    []gtpv2.IE{bearer},
	}, nil
}

func deleteRequest(sgwTEID uint32) gtpv2.Message {
	ebi, _ := gtpv2.NewEBIIE(defaultEBI, 0)
	return gtpv2.Message{
		Header: gtpv2.Header{Version: gtpv2.Version, HasTEID: true, MessageType: gtpv2.MessageDeleteSessionRequest, TEID: sgwTEID},
		IEs:    []gtpv2.IE{ebi},
	}
}

func accepted(message gtpv2.Message) error {
	causeIE, ok := message.Find(gtpv2.IECause, 0)
	if !ok {
		return errors.New("response omitted Cause IE")
	}
	cause, err := causeIE.Cause()
	if err != nil {
		return err
	}
	if cause.Value != gtpv2.CauseRequestAccepted {
		return fmt.Errorf("procedure rejected with GTP cause %d", cause.Value)
	}
	return nil
}

func snapshotState(sgwc *sgwcsession.Store, pgwc *pgwcsession.Store, sgwu *sgwurules.Store, pgwu *pgwurules.Store, pool *ipam.Pool) stateSnapshot {
	return stateSnapshot{
		SGWCSessions: len(sgwc.Snapshot()), PGWCSessions: len(pgwc.Snapshot()),
		SGWUSessions: len(sgwu.Snapshot()), PGWUSessions: pgwu.Count(), IPv4Leases: pool.Used(),
	}
}

func cleanTransports(value transportSnapshot) bool {
	gtpClean := func(counters gtptransport.Counters) bool {
		return counters.Malformed == 0 && counters.Retransmitted == 0 && counters.TimedOut == 0 &&
			counters.WorkerDrops == 0 && counters.SocketDrops == 0 && counters.ActiveTransactions == 0 && counters.TransactionCollisions == 0
	}
	pfcpClean := func(counters pfcptransport.Counters) bool {
		return counters.Malformed == 0 && counters.Retransmitted == 0 && counters.TimedOut == 0 && counters.WorkerDrops == 0 && counters.SocketDrops == 0
	}
	return gtpClean(value.MMEGTP) && gtpClean(value.SGWCS11) && gtpClean(value.SGWCS5) && gtpClean(value.PGWCS5) &&
		pfcpClean(value.SGWCPFCP) && pfcpClean(value.SGWUPFCP) && pfcpClean(value.PGWCPFCP) && pfcpClean(value.PGWUPFCP)
}

func resilientTransports(value transportSnapshot) bool {
	gtpHealthy := func(counters gtptransport.Counters) bool {
		return counters.Malformed == 0 && counters.TimedOut == 0 && counters.WorkerDrops == 0 &&
			counters.SocketDrops == 0 && counters.ActiveTransactions == 0 && counters.TransactionCollisions == 0
	}
	pfcpHealthy := func(counters pfcptransport.Counters) bool {
		return counters.Malformed == 0 && counters.TimedOut == 0 && counters.WorkerDrops == 0 && counters.SocketDrops == 0
	}
	return gtpHealthy(value.MMEGTP) && gtpHealthy(value.SGWCS11) && gtpHealthy(value.SGWCS5) && gtpHealthy(value.PGWCS5) &&
		pfcpHealthy(value.SGWCPFCP) && pfcpHealthy(value.SGWUPFCP) && pfcpHealthy(value.PGWCPFCP) && pfcpHealthy(value.PGWUPFCP)
}

func transportFaultsObserved(value transportSnapshot) bool {
	gtpFaults := func(counters gtptransport.Counters) uint64 {
		return counters.Retransmitted + counters.CacheHits
	}
	pfcpFaults := func(counters pfcptransport.Counters) uint64 {
		return counters.Retransmitted + counters.CacheHits
	}
	return gtpFaults(value.MMEGTP)+gtpFaults(value.SGWCS11)+gtpFaults(value.SGWCS5)+gtpFaults(value.PGWCS5)+
		pfcpFaults(value.SGWCPFCP)+pfcpFaults(value.SGWUPFCP)+pfcpFaults(value.PGWCPFCP)+pfcpFaults(value.PGWUPFCP) > 0
}
