// sgwu-wire-bench is a guarded two-host benchmark for the SGW-U TCX path and
// the combined SGW-U -> PGW-U CUPS user plane. It is not an LTE network
// function and refuses to run outside a disposable network namespace created
// by the accompanying benchmark wrappers.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	pgwudataplane "github.com/lodestarnetworks/cups/internal/pgwu/dataplane"
	pgwurules "github.com/lodestarnetworks/cups/internal/pgwu/rules"
	sgwudataplane "github.com/lodestarnetworks/cups/internal/sgwu/dataplane"
	"github.com/lodestarnetworks/cups/internal/sgwu/fastpath"
	sgwurules "github.com/lodestarnetworks/cups/internal/sgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

const (
	guardEnvironment = "SGW_NEXT_SGWU_WIRE_BENCH"
	minimumInnerSize = 64
	maximumInnerSize = 1400
	maximumSessions  = 65_000

	accessInputTEIDBase      uint32 = 0x10000000
	coreOutputTEIDBase       uint32 = 0x20000000
	coreInputTEIDBase        uint32 = 0x30000000
	accessOutputTEIDBase     uint32 = 0x40000000
	qci1AccessInputTEIDBase  uint32 = 0x50000000
	qci1CoreOutputTEIDBase   uint32 = 0x60000000
	qci1CoreInputTEIDBase    uint32 = 0x70000000
	qci1AccessOutputTEIDBase uint32 = 0x80000000
	mixedVoiceLocalPort             = 40_000
	mixedVoiceRemotePort            = 40_002
)

var (
	dutAccessIP           = netip.MustParseAddr("198.18.0.1")
	dutCoreIP             = netip.MustParseAddr("198.18.0.2")
	chainSGWUAccessIP     = netip.MustParseAddr("10.253.166.1")
	chainSGWUCoreIP       = netip.MustParseAddr("10.253.168.1")
	chainPGWUIP           = netip.MustParseAddr("10.253.168.2")
	chainPGWUQCI1IP       = netip.MustParseAddr("10.253.168.3")
	chainServiceIP        = netip.MustParseAddr("10.253.169.2")
	chainUEPrefix         = netip.MustParsePrefix("10.128.0.0/10")
	chainUEGateway        = netip.MustParseAddr("10.128.0.1")
	accessPeerBaseIP      = netip.MustParseAddr("198.18.1.0")
	chainAccessPeerBaseIP = netip.MustParseAddr("10.253.167.0")
	corePeerBaseIP        = netip.MustParseAddr("198.19.1.0")
	defaultAccessMAC      = "02:4c:53:57:00:01"
	defaultCoreMAC        = "02:4c:53:57:00:02"
	defaultGeneratorMAC   = "02:4c:53:57:00:03"
	defaultPGWUMAC        = "02:4c:53:57:00:04"
	defaultSGiMAC         = "02:4c:53:57:00:05"
)

type options struct {
	role               string
	direction          string
	cupsChain          bool
	dedicatedBearer    bool
	mixedBearers       bool
	duration           time.Duration
	drain              time.Duration
	innerPacketBytes   int
	voicePacketBytes   int
	sessions           int
	activeSessions     int
	targetPPS          int
	voicePPS           int
	workers            int
	receiverWorkers    int
	socketBufferBytes  int
	accessInterface    string
	coreInterface      string
	pgwuInterface      string
	sgiInterface       string
	generatorInterface string
	accessMAC          net.HardwareAddr
	coreMAC            net.HardwareAddr
	pgwuMAC            net.HardwareAddr
	sgiMAC             net.HardwareAddr
	generatorMAC       net.HardwareAddr
}

type dutResult struct {
	Scope                string                         `json:"scope"`
	CUPSChain            bool                           `json:"cupsChain"`
	DedicatedBearer      bool                           `json:"dedicatedBearer"`
	MixedBearers         bool                           `json:"mixedBearers"`
	Sessions             int                            `json:"sessions"`
	AccessInterface      string                         `json:"accessInterface"`
	CoreInterface        string                         `json:"coreInterface"`
	PGWUInterface        string                         `json:"pgwuInterface,omitempty"`
	SGiInterface         string                         `json:"sgiInterface,omitempty"`
	DurationMilliseconds float64                        `json:"durationMilliseconds"`
	FastPathCounters     sgwudataplane.FastPathCounters `json:"sgwuFastPathCounters"`
	PGWUCounters         *pgwudataplane.Counters        `json:"pgwuCounters,omitempty"`
	GoMaxProcs           int                            `json:"goMaxProcs"`
	GoHeapBytes          uint64                         `json:"goHeapBytes"`
	GoHeapObjects        uint64                         `json:"goHeapObjects"`
	GoGCCount            uint32                         `json:"goGcCount"`
	CPUAffinity          string                         `json:"cpuAffinity,omitempty"`
}

func main() {
	cfg, err := parseOptions()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := validateEnvironment(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var result any
	switch cfg.role {
	case "dut":
		result, err = runDUT(cfg)
	case "generator":
		result, err = runGenerator(cfg)
	case "headroom":
		result, err = runHeadroom(cfg)
	default:
		err = fmt.Errorf("unsupported role %q", cfg.role)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseOptions() (options, error) {
	role := flag.String("role", "", "benchmark role: dut, generator, or headroom")
	direction := flag.String("direction", "uplink", "traffic direction: uplink, downlink, or both")
	cupsChain := flag.Bool("cups-chain", false, "benchmark the combined SGW-U to PGW-U path")
	dedicatedBearer := flag.Bool("dedicated-bearer", false, "send all combined-path traffic over a QCI 1 dedicated bearer")
	mixedBearers := flag.Bool("mixed-bearers", false, "send default-bearer bulk data and QCI 1 voice traffic together")
	duration := flag.Duration("duration", 10*time.Second, "measurement duration")
	drain := flag.Duration("drain", 3*time.Second, "receiver drain time after sending")
	innerPacketBytes := flag.Int("inner-packet-bytes", 1400, "complete inner IPv4 packet bytes")
	voicePacketBytes := flag.Int("voice-packet-bytes", 200, "complete QCI 1 voice inner IPv4 packet bytes in mixed mode")
	sessions := flag.Int("sessions", 1024, "installed SGW-U sessions")
	activeSessions := flag.Int("active-sessions", 0, "sessions used by traffic; zero uses all installed sessions")
	targetPPS := flag.Int("target-pps", 100_000, "offered packets/s per direction; zero is unpaced")
	voicePPS := flag.Int("voice-pps", 51_200, "additional QCI 1 voice packets/s per direction in mixed mode")
	workers := flag.Int("workers", 8, "sender workers per direction")
	receiverWorkers := flag.Int("receiver-workers", 8, "AF_PACKET fanout receiver workers")
	socketBufferBytes := flag.Int("socket-buffer-bytes", 64<<20, "send and receive socket buffer request")
	accessInterface := flag.String("access-interface", "lswacc", "DUT access-side benchmark interface")
	coreInterface := flag.String("core-interface", "lswcore", "DUT core-side benchmark interface")
	pgwuInterface := flag.String("pgwu-interface", "lswpgw", "PGW-U S5-side benchmark interface")
	sgiInterface := flag.String("sgi-interface", "lswsgi", "PGW-U SGi-side benchmark interface")
	generatorInterface := flag.String("generator-interface", "lswgen", "generator benchmark interface")
	accessMAC := flag.String("access-mac", defaultAccessMAC, "DUT access-side benchmark MAC")
	coreMAC := flag.String("core-mac", defaultCoreMAC, "DUT core-side benchmark MAC")
	pgwuMAC := flag.String("pgwu-mac", defaultPGWUMAC, "PGW-U S5-side benchmark MAC")
	sgiMAC := flag.String("sgi-mac", defaultSGiMAC, "PGW-U SGi-side benchmark MAC")
	generatorMAC := flag.String("generator-mac", defaultGeneratorMAC, "generator benchmark MAC")
	flag.Parse()

	parsedAccessMAC, err := net.ParseMAC(*accessMAC)
	if err != nil {
		return options{}, fmt.Errorf("parse access MAC: %w", err)
	}
	parsedCoreMAC, err := net.ParseMAC(*coreMAC)
	if err != nil {
		return options{}, fmt.Errorf("parse core MAC: %w", err)
	}
	parsedPGWUMAC, err := net.ParseMAC(*pgwuMAC)
	if err != nil {
		return options{}, fmt.Errorf("parse PGW-U MAC: %w", err)
	}
	parsedSGiMAC, err := net.ParseMAC(*sgiMAC)
	if err != nil {
		return options{}, fmt.Errorf("parse SGi MAC: %w", err)
	}
	parsedGeneratorMAC, err := net.ParseMAC(*generatorMAC)
	if err != nil {
		return options{}, fmt.Errorf("parse generator MAC: %w", err)
	}
	return options{
		role: *role, direction: *direction, cupsChain: *cupsChain, dedicatedBearer: *dedicatedBearer, mixedBearers: *mixedBearers,
		duration: *duration, drain: *drain,
		innerPacketBytes: *innerPacketBytes, voicePacketBytes: *voicePacketBytes, sessions: *sessions,
		activeSessions: *activeSessions, targetPPS: *targetPPS,
		voicePPS: *voicePPS,
		workers:  *workers, receiverWorkers: *receiverWorkers,
		socketBufferBytes: *socketBufferBytes,
		accessInterface:   *accessInterface, coreInterface: *coreInterface,
		pgwuInterface: *pgwuInterface, sgiInterface: *sgiInterface,
		generatorInterface: *generatorInterface,
		accessMAC:          parsedAccessMAC, coreMAC: parsedCoreMAC,
		pgwuMAC: parsedPGWUMAC, sgiMAC: parsedSGiMAC,
		generatorMAC: parsedGeneratorMAC,
	}, nil
}

func validateEnvironment(cfg options) error {
	if os.Getenv(guardEnvironment) != "1" {
		return fmt.Errorf("sgwu-wire-bench refuses to run unless %s=1", guardEnvironment)
	}
	if os.Geteuid() != 0 {
		return errors.New("sgwu-wire-bench requires root in a disposable network namespace")
	}
	selfNS, selfErr := os.Readlink("/proc/self/ns/net")
	initNS, initErr := os.Readlink("/proc/1/ns/net")
	if selfErr != nil || initErr != nil || selfNS == initNS {
		return errors.New("sgwu-wire-bench refuses to run in the initial network namespace")
	}
	if cfg.role != "dut" && cfg.role != "generator" && cfg.role != "headroom" {
		return errors.New("role must be dut, generator, or headroom")
	}
	if cfg.cupsChain && cfg.role == "headroom" {
		return errors.New("cups-chain is not valid for the generator-only headroom role")
	}
	if cfg.dedicatedBearer && !cfg.cupsChain {
		return errors.New("dedicated-bearer requires cups-chain")
	}
	if cfg.mixedBearers && (!cfg.cupsChain || !cfg.dedicatedBearer) {
		return errors.New("mixed-bearers requires cups-chain and dedicated-bearer")
	}
	if cfg.direction != "uplink" && cfg.direction != "downlink" && cfg.direction != "both" {
		return errors.New("direction must be uplink, downlink, or both")
	}
	if cfg.duration < 100*time.Millisecond || cfg.duration > 30*time.Minute {
		return errors.New("duration must be between 100ms and 30m")
	}
	if cfg.drain < 100*time.Millisecond || cfg.drain > 30*time.Second {
		return errors.New("drain must be between 100ms and 30s")
	}
	if cfg.innerPacketBytes < minimumInnerSize || cfg.innerPacketBytes > maximumInnerSize {
		return fmt.Errorf("inner-packet-bytes must be between %d and %d", minimumInnerSize, maximumInnerSize)
	}
	if cfg.voicePacketBytes < minimumInnerSize || cfg.voicePacketBytes > maximumInnerSize {
		return fmt.Errorf("voice-packet-bytes must be between %d and %d", minimumInnerSize, maximumInnerSize)
	}
	if cfg.sessions < 1 || cfg.sessions > maximumSessions {
		return fmt.Errorf("sessions must be between 1 and %d", maximumSessions)
	}
	if cfg.activeSessions == 0 {
		cfg.activeSessions = cfg.sessions
	}
	if cfg.activeSessions < 1 || cfg.activeSessions > cfg.sessions {
		return errors.New("active-sessions must be between 1 and installed sessions")
	}
	if cfg.targetPPS < 0 || cfg.targetPPS > 20_000_000 {
		return errors.New("target-pps must be between 0 and 20000000")
	}
	if cfg.voicePPS < 1 || cfg.voicePPS > 2_000_000 {
		return errors.New("voice-pps must be between 1 and 2000000")
	}
	if cfg.workers < 1 || cfg.workers > 128 {
		return errors.New("workers must be between 1 and 128")
	}
	if cfg.receiverWorkers < 1 || cfg.receiverWorkers > 128 {
		return errors.New("receiver-workers must be between 1 and 128")
	}
	if cfg.socketBufferBytes < 64*1024 || cfg.socketBufferBytes > 1<<30 {
		return errors.New("socket-buffer-bytes must be between 65536 and 1073741824")
	}
	macs := map[string]net.HardwareAddr{
		"access": cfg.accessMAC, "core": cfg.coreMAC, "generator": cfg.generatorMAC,
	}
	if cfg.cupsChain {
		macs["PGW-U"] = cfg.pgwuMAC
		macs["SGi"] = cfg.sgiMAC
	}
	seenMACs := make(map[string]string, len(macs))
	for name, value := range macs {
		if len(value) != 6 || value[0]&1 != 0 {
			return fmt.Errorf("%s MAC must be a six-byte unicast address", name)
		}
		canonical := value.String()
		if previous, exists := seenMACs[canonical]; exists {
			return fmt.Errorf("%s and %s MACs must be distinct", previous, name)
		}
		seenMACs[canonical] = name
	}
	if cfg.cupsChain {
		seenInterfaces := make(map[string]string, 4)
		for name, value := range map[string]string{
			"access": cfg.accessInterface, "core": cfg.coreInterface,
			"PGW-U": cfg.pgwuInterface, "SGi": cfg.sgiInterface,
		} {
			value = strings.TrimSpace(value)
			if value == "" {
				return fmt.Errorf("%s interface must not be empty", name)
			}
			if previous, exists := seenInterfaces[value]; exists {
				return fmt.Errorf("%s and %s interfaces must be distinct", previous, name)
			}
			seenInterfaces[value] = name
		}
	}
	return nil
}

func runDUT(cfg options) (dutResult, error) {
	if cfg.cupsChain {
		return runCUPSDUT(cfg)
	}
	started := time.Now()
	store := sgwurules.NewStoreWithLimit(cfg.sessions)
	for index := 0; index < cfg.sessions; index++ {
		if _, err := store.Create(wireSession(index)); err != nil {
			return dutResult{}, fmt.Errorf("install session %d: %w", index, err)
		}
	}
	accessNeighbours := make([]fastpath.Neighbour, 0, cfg.sessions)
	coreNeighbours := make([]fastpath.Neighbour, 0, cfg.sessions)
	for index := 0; index < cfg.sessions; index++ {
		accessNeighbours = append(accessNeighbours, fastpath.Neighbour{IP: accessPeerIP(index), MAC: cfg.generatorMAC})
		coreNeighbours = append(coreNeighbours, fastpath.Neighbour{IP: corePeerIP(index), MAC: cfg.generatorMAC})
	}
	backend, err := fastpath.Open(fastpath.Config{
		Access:      fastpath.Side{Interface: cfg.accessInterface, LocalIP: dutAccessIP, Neighbours: accessNeighbours},
		Core:        fastpath.Side{Interface: cfg.coreInterface, LocalIP: dutCoreIP, Neighbours: coreNeighbours},
		MaxSessions: cfg.sessions, MaxRules: cfg.sessions * 4,
	}, store)
	if err != nil {
		return dutResult{}, err
	}
	defer backend.Close()

	ready := map[string]any{
		"event": "ready", "role": "dut", "sessions": cfg.sessions,
		"accessInterface": cfg.accessInterface, "coreInterface": cfg.coreInterface,
	}
	readyJSON, _ := json.Marshal(ready)
	fmt.Fprintln(os.Stderr, string(readyJSON))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	timer := time.NewTimer(cfg.duration)
	select {
	case <-ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
	case <-timer.C:
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return dutResult{
		Scope: "two-host physical-wire SGW-U TCX DUT", CUPSChain: false,
		Sessions: cfg.sessions, AccessInterface: cfg.accessInterface,
		CoreInterface:        cfg.coreInterface,
		DurationMilliseconds: float64(time.Since(started).Microseconds()) / 1000,
		FastPathCounters:     backend.Counters(), GoMaxProcs: runtime.GOMAXPROCS(0),
		GoHeapBytes: memory.HeapAlloc, GoHeapObjects: memory.HeapObjects,
		GoGCCount: memory.NumGC, CPUAffinity: os.Getenv("BENCH_CPU_LIST"),
	}, nil
}

func runCUPSDUT(cfg options) (dutResult, error) {
	started := time.Now()
	for name, expected := range map[string]net.HardwareAddr{
		cfg.accessInterface: cfg.accessMAC,
		cfg.coreInterface:   cfg.coreMAC,
		cfg.pgwuInterface:   cfg.pgwuMAC,
		cfg.sgiInterface:    cfg.sgiMAC,
	} {
		if err := validateBenchmarkInterface(name, expected); err != nil {
			return dutResult{}, err
		}
	}

	sgwuStore := sgwurules.NewStoreWithLimit(cfg.sessions)
	for index := 0; index < cfg.sessions; index++ {
		session := cupsWireSGWUSession(index)
		if cfg.dedicatedBearer {
			session = cupsWireDedicatedSGWUSession(index)
		}
		if _, err := sgwuStore.Create(session); err != nil {
			return dutResult{}, fmt.Errorf("install SGW-U session %d: %w", index, err)
		}
	}
	accessNeighbours := make([]fastpath.Neighbour, 0, cfg.sessions)
	for index := 0; index < cfg.sessions; index++ {
		accessNeighbours = append(accessNeighbours, fastpath.Neighbour{IP: chainAccessPeerIP(index), MAC: cfg.generatorMAC})
	}
	sgwu, err := fastpath.Open(fastpath.Config{
		Access: fastpath.Side{
			Interface: cfg.accessInterface, LocalIP: chainSGWUAccessIP,
			Neighbours: accessNeighbours,
		},
		Core: fastpath.Side{
			Interface: cfg.coreInterface, LocalIP: chainSGWUCoreIP,
			Neighbours: []fastpath.Neighbour{{IP: chainPGWUIP, MAC: cfg.pgwuMAC}, {IP: chainPGWUQCI1IP, MAC: cfg.pgwuMAC}},
		},
		MaxSessions: cfg.sessions,
		MaxRules:    cfg.sessions * 8,
	}, sgwuStore)
	if err != nil {
		return dutResult{}, fmt.Errorf("start SGW-U TCX dataplane: %w", err)
	}
	defer sgwu.Close()

	ownerDirectory, err := os.MkdirTemp("", "sgw-next-cups-wire-owner-")
	if err != nil {
		return dutResult{}, fmt.Errorf("create PGW-U ownership directory: %w", err)
	}
	defer os.RemoveAll(ownerDirectory)
	pgwuConfig := pgwudataplane.KernelConfig{
		S5:                     netip.AddrPortFrom(chainPGWUIP, gtpuPort),
		AllowedSGWPeers:        []netip.Addr{chainSGWUCoreIP},
		TunnelName:             "lodcupswirepgw",
		OwnershipFile:          filepath.Join(ownerDirectory, "kernel.owner"),
		UEPoolPrefix:           chainUEPrefix,
		UEGateway:              chainUEGateway,
		HashSize:               wireKernelHashSize(cfg.sessions),
		MTU:                    maximumInnerSize,
		SocketBufferBytes:      cfg.socketBufferBytes,
		AllowUnsupportedPolicy: !cfg.dedicatedBearer,
	}
	if cfg.dedicatedBearer {
		pgwuConfig.QCI1S5 = netip.AddrPortFrom(chainPGWUQCI1IP, gtpuPort)
		pgwuConfig.QCI1TunnelName = "lodcupswireq1"
		pgwuConfig.QCI1OwnershipFile = filepath.Join(ownerDirectory, "kernel-qci1.owner")
		pgwuConfig.MaxSessions = cfg.sessions
		pgwuConfig.MaxPolicyFilters = cfg.sessions * 2
		pgwuConfig.QERBurstDuration = 100 * time.Millisecond
	}
	pgwu, err := pgwudataplane.OpenKernel(pgwuConfig)
	if err != nil {
		return dutResult{}, fmt.Errorf("start PGW-U kernel dataplane: %w", err)
	}
	defer pgwu.Close()
	pgwuStore := pgwurules.NewStoreWithApplier(cfg.sessions, pgwu)
	for index := 0; index < cfg.sessions; index++ {
		session := cupsWirePGWUSession(index)
		if cfg.dedicatedBearer {
			session = cupsWireDedicatedPGWUSession(index)
			if cfg.mixedBearers {
				session = cupsWireMixedPGWUSession(index)
			}
		}
		if _, err := pgwuStore.Create(session); err != nil {
			return dutResult{}, fmt.Errorf("install PGW-U session %d: %w", index, err)
		}
	}

	ready := map[string]any{
		"event": "ready", "role": "dut", "cupsChain": true,
		"dedicatedBearer": cfg.dedicatedBearer,
		"mixedBearers":    cfg.mixedBearers,
		"sessions":        cfg.sessions, "accessInterface": cfg.accessInterface,
		"coreInterface": cfg.coreInterface, "pgwuInterface": cfg.pgwuInterface,
		"sgiInterface": cfg.sgiInterface,
	}
	readyJSON, _ := json.Marshal(ready)
	fmt.Fprintln(os.Stderr, string(readyJSON))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	timer := time.NewTimer(cfg.duration)
	select {
	case <-ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
	case <-timer.C:
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	pgwuCounters := pgwu.Counters()
	runtime.KeepAlive(pgwuStore)
	return dutResult{
		Scope:     "two-host physical-wire SGW-U TCX to PGW-U kernel-GTP DUT",
		CUPSChain: true, DedicatedBearer: cfg.dedicatedBearer, MixedBearers: cfg.mixedBearers, Sessions: cfg.sessions,
		AccessInterface: cfg.accessInterface, CoreInterface: cfg.coreInterface,
		PGWUInterface: cfg.pgwuInterface, SGiInterface: cfg.sgiInterface,
		DurationMilliseconds: float64(time.Since(started).Microseconds()) / 1000,
		FastPathCounters:     sgwu.Counters(), PGWUCounters: &pgwuCounters,
		GoMaxProcs: runtime.GOMAXPROCS(0), GoHeapBytes: memory.HeapAlloc,
		GoHeapObjects: memory.HeapObjects, GoGCCount: memory.NumGC,
		CPUAffinity: os.Getenv("BENCH_CPU_LIST"),
	}, nil
}

func cupsWireDedicatedSGWUSession(index int) sgwurules.Session {
	value := cupsWireSGWUSession(index)
	outerCore := sgwurules.FTEID{TEID: qci1CoreOutputTEID(index), IP: chainPGWUQCI1IP}
	outerAccess := sgwurules.FTEID{TEID: qci1AccessOutputTEID(index), IP: chainAccessPeerIP(index)}
	value.PDRs[3] = sgwurules.PDR{ID: 3, SourceInterface: sgwurules.SourceAccess, LocalFTEID: sgwurules.FTEID{TEID: qci1AccessInputTEID(index), IP: chainSGWUAccessIP}, FARID: 3}
	value.PDRs[4] = sgwurules.PDR{ID: 4, SourceInterface: sgwurules.SourceCore, LocalFTEID: sgwurules.FTEID{TEID: qci1CoreInputTEID(index), IP: chainSGWUCoreIP}, FARID: 4}
	value.FARs[3] = sgwurules.FAR{ID: 3, ApplyAction: sgwurules.ActionForward, DestinationInterface: sgwurules.DestinationCore, OuterHeader: &outerCore}
	value.FARs[4] = sgwurules.FAR{ID: 4, ApplyAction: sgwurules.ActionForward, DestinationInterface: sgwurules.DestinationAccess, OuterHeader: &outerAccess}
	return value
}

func validateBenchmarkInterface(name string, expected net.HardwareAddr) error {
	device, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("resolve benchmark interface %s: %w", name, err)
	}
	if device.Flags&net.FlagUp == 0 {
		return fmt.Errorf("benchmark interface %s is down", name)
	}
	if !hardwareAddressEqual(device.HardwareAddr, expected) {
		return fmt.Errorf("benchmark interface %s MAC is %s, expected %s", name, device.HardwareAddr, expected)
	}
	return nil
}

func wireSession(index int) sgwurules.Session {
	outerCore := sgwurules.FTEID{TEID: coreOutputTEID(index), IP: corePeerIP(index)}
	outerAccess := sgwurules.FTEID{TEID: accessOutputTEID(index), IP: accessPeerIP(index)}
	return sgwurules.Session{
		CPSEID: uint64(index + 1), UPSEID: uint64(index + 1),
		PDRs: map[uint16]sgwurules.PDR{
			1: {ID: 1, SourceInterface: sgwurules.SourceAccess, LocalFTEID: sgwurules.FTEID{TEID: accessInputTEID(index), IP: dutAccessIP}, FARID: 1},
			2: {ID: 2, SourceInterface: sgwurules.SourceCore, LocalFTEID: sgwurules.FTEID{TEID: coreInputTEID(index), IP: dutCoreIP}, FARID: 2},
		},
		FARs: map[uint32]sgwurules.FAR{
			1: {ID: 1, ApplyAction: sgwurules.ActionForward, DestinationInterface: sgwurules.DestinationCore, OuterHeader: &outerCore},
			2: {ID: 2, ApplyAction: sgwurules.ActionForward, DestinationInterface: sgwurules.DestinationAccess, OuterHeader: &outerAccess},
		},
		QERs: map[uint32]sgwurules.QER{}, URRs: map[uint32]sgwurules.URR{},
	}
}

func cupsWireSGWUSession(index int) sgwurules.Session {
	outerCore := sgwurules.FTEID{TEID: coreOutputTEID(index), IP: chainPGWUIP}
	outerAccess := sgwurules.FTEID{TEID: accessOutputTEID(index), IP: chainAccessPeerIP(index)}
	return sgwurules.Session{
		CPSEID: uint64(index)*2 + 1, UPSEID: uint64(index)*2 + 2,
		PDRs: map[uint16]sgwurules.PDR{
			1: {ID: 1, SourceInterface: sgwurules.SourceAccess, LocalFTEID: sgwurules.FTEID{TEID: accessInputTEID(index), IP: chainSGWUAccessIP}, FARID: 1},
			2: {ID: 2, SourceInterface: sgwurules.SourceCore, LocalFTEID: sgwurules.FTEID{TEID: coreInputTEID(index), IP: chainSGWUCoreIP}, FARID: 2},
		},
		FARs: map[uint32]sgwurules.FAR{
			1: {ID: 1, ApplyAction: sgwurules.ActionForward, DestinationInterface: sgwurules.DestinationCore, OuterHeader: &outerCore},
			2: {ID: 2, ApplyAction: sgwurules.ActionForward, DestinationInterface: sgwurules.DestinationAccess, OuterHeader: &outerAccess},
		},
		QERs: map[uint32]sgwurules.QER{}, URRs: map[uint32]sgwurules.URR{},
	}
}

func cupsWirePGWUSession(index int) pgwurules.Session {
	return pgwurules.Session{
		CPSEID: uint64(index)*2 + 1, UPSEID: uint64(index)*2 + 2,
		UEIPv4:         chainUEAddress(index),
		Local:          pgwurules.Tunnel{TEID: coreOutputTEID(index), IP: chainPGWUIP},
		Remote:         pgwurules.Tunnel{TEID: coreInputTEID(index), IP: chainSGWUCoreIP},
		UplinkGateOpen: true, DownlinkGateOpen: true,
	}
}

func cupsWireDedicatedPGWUSession(index int) pgwurules.Session {
	value := cupsWirePGWUSession(index)
	filter := pgwurules.FlowFilter{
		PDRID: 3, Precedence: 10, Direction: gtpv2.TFTDirectionBidirectional,
		Filter: gtpv2.IPv4PacketFilter{
			ID: 1, Direction: gtpv2.TFTDirectionBidirectional, Precedence: 10,
			HasProtocol: true, Protocol: 17,
		},
	}
	value.UplinkPDRID, value.DownlinkPDRID = 1, 2
	value.UplinkFARID, value.DownlinkFARID = 1, 2
	value.DedicatedBearers = []pgwurules.Bearer{{
		Local:       pgwurules.Tunnel{TEID: qci1CoreOutputTEID(index), IP: chainPGWUQCI1IP},
		Remote:      pgwurules.Tunnel{TEID: qci1CoreInputTEID(index), IP: chainSGWUCoreIP},
		UplinkFARID: 3, DownlinkFARID: 4,
		UplinkGateOpen: true, DownlinkGateOpen: true,
		QERID: 1, URRID: 1, MeasureVolume: true,
		UsageReportingThreshold: 1 << 40, QCI: 1, ARP: 2,
		Filters: []pgwurules.FlowFilter{filter},
	}}
	return value
}

func cupsWireMixedPGWUSession(index int) pgwurules.Session {
	value := cupsWireDedicatedPGWUSession(index)
	filter := &value.DedicatedBearers[0].Filters[0].Filter
	filter.HasLocalPort = true
	filter.LocalPortLow = mixedVoiceLocalPort
	filter.LocalPortHigh = mixedVoiceLocalPort
	return value
}

func chainUEAddress(index int) netip.Addr {
	return addIPv4(chainUEPrefix.Addr(), index+2)
}

func wireKernelHashSize(sessions int) uint32 {
	target := uint64(sessions+7) / 8
	value := uint32(1_024)
	for uint64(value) < target && value < 131_072 {
		value <<= 1
	}
	return value
}

func accessPeerIP(index int) netip.Addr { return addIPv4(accessPeerBaseIP, index) }
func chainAccessPeerIP(index int) netip.Addr {
	return addIPv4(chainAccessPeerBaseIP, index)
}
func corePeerIP(index int) netip.Addr { return addIPv4(corePeerBaseIP, index) }

func addIPv4(base netip.Addr, index int) netip.Addr {
	bytes := base.As4()
	value := binary.BigEndian.Uint32(bytes[:]) + uint32(index)
	binary.BigEndian.PutUint32(bytes[:], value)
	return netip.AddrFrom4(bytes)
}

func accessInputTEID(index int) uint32      { return accessInputTEIDBase + uint32(index) }
func coreOutputTEID(index int) uint32       { return coreOutputTEIDBase + uint32(index) }
func coreInputTEID(index int) uint32        { return coreInputTEIDBase + uint32(index) }
func accessOutputTEID(index int) uint32     { return accessOutputTEIDBase + uint32(index) }
func qci1AccessInputTEID(index int) uint32  { return qci1AccessInputTEIDBase + uint32(index) }
func qci1CoreOutputTEID(index int) uint32   { return qci1CoreOutputTEIDBase + uint32(index) }
func qci1CoreInputTEID(index int) uint32    { return qci1CoreInputTEIDBase + uint32(index) }
func qci1AccessOutputTEID(index int) uint32 { return qci1AccessOutputTEIDBase + uint32(index) }

func parseCPUList(value string) ([]int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	seen := make(map[int]struct{})
	var result []int
	for _, part := range strings.Split(value, ",") {
		bounds := strings.SplitN(strings.TrimSpace(part), "-", 2)
		first, err := strconv.Atoi(bounds[0])
		if err != nil || first < 0 {
			return nil, fmt.Errorf("invalid CPU list %q", value)
		}
		last := first
		if len(bounds) == 2 {
			last, err = strconv.Atoi(bounds[1])
			if err != nil || last < first {
				return nil, fmt.Errorf("invalid CPU list %q", value)
			}
		}
		for cpu := first; cpu <= last; cpu++ {
			if _, exists := seen[cpu]; !exists {
				seen[cpu] = struct{}{}
				result = append(result, cpu)
			}
		}
	}
	return result, nil
}
