// cups-dataplane-bench drives the real SGW-U portable dataplane into the real
// PGW-U kernel-GTP dataplane inside a disposable network namespace.
// It is a benchmark peer, not an LTE network function.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	pgwudataplane "github.com/lodestarnetworks/cups/internal/pgwu/dataplane"
	pgwurules "github.com/lodestarnetworks/cups/internal/pgwu/rules"
	sgwudataplane "github.com/lodestarnetworks/cups/internal/sgwu/dataplane"
	"github.com/lodestarnetworks/cups/internal/sgwu/fastpath"
	sgwurules "github.com/lodestarnetworks/cups/internal/sgwu/rules"
	"github.com/lodestarnetworks/cups/internal/udpstats"
	"github.com/lodestarnetworks/cups/pkg/gtpu"
)

const (
	guardEnvironment  = "SGW_NEXT_ISOLATED_CUPS_BENCH"
	gtpuPort          = 2152
	servicePort       = 9000
	uePort            = 9001
	metadataBytes     = 32
	minimumInnerSize  = 64
	maximumDuration   = 10 * time.Minute
	latencySampleMask = 255
	receiverBatchSize = 64

	enbIncomingTEID      = 100
	sgwuCoreIncomingTEID = 200
	pgwuIncomingTEID     = 300
	enbOutgoingTEID      = 400
)

var (
	sgwuAccessIP = netip.MustParseAddr("10.254.91.1")
	enbIP        = netip.MustParseAddr("10.254.91.2")
	sgwuCoreIP   = netip.MustParseAddr("10.254.92.1")
	pgwuIP       = netip.MustParseAddr("10.254.92.2")
	pgwuQCI1IP   = netip.MustParseAddr("10.254.92.3")
	uePrefix     = netip.MustParsePrefix("10.0.0.0/9")
	ueGateway    = netip.MustParseAddr("10.0.0.1")
	serviceIP    = netip.MustParseAddr("10.254.94.1")
)

type packetSizeWeight struct {
	InnerPacketBytes int `json:"innerPacketBytes"`
	Weight           int `json:"weight"`
}

type packetProfile struct {
	name       string
	weights    []packetSizeWeight
	cumulative []uint64
	total      uint64
	average    float64
}

type streamResult struct {
	Direction           string  `json:"direction"`
	InnerPacketBytes    int     `json:"innerPacketBytes"`
	PacketProfile       string  `json:"packetProfile"`
	AveragePacketBytes  float64 `json:"averageInnerPacketBytes"`
	InstalledSessions   int     `json:"installedSessions"`
	ActiveSessions      int     `json:"activeSessions"`
	Workers             int     `json:"workers"`
	TargetPacketsPerS   int     `json:"targetPacketsPerSecond"`
	DurationMS          float64 `json:"durationMilliseconds"`
	SentPackets         uint64  `json:"sentPackets"`
	ReceivedPackets     uint64  `json:"receivedPackets"`
	ReceiverSocketDrops uint64  `json:"receiverSocketDroppedPackets"`
	LostPackets         uint64  `json:"lostPackets"`
	LossPercent         float64 `json:"lossPercent"`
	SentPacketsPerS     float64 `json:"sentPacketsPerSecond"`
	ReceivedPacketsPerS float64 `json:"receivedPacketsPerSecond"`
	OfferedMbps         float64 `json:"offeredMbps"`
	ReceivedMbps        float64 `json:"receivedMbps"`
	LatencySamples      uint64  `json:"latencySamples"`
	P50LatencyMS        float64 `json:"p50LatencyMilliseconds"`
	P95LatencyMS        float64 `json:"p95LatencyMilliseconds"`
	P99LatencyMS        float64 `json:"p99LatencyMilliseconds"`
}

type result struct {
	Scope               string                 `json:"scope"`
	PacketProfile       string                 `json:"packetProfile"`
	PacketSizeWeights   []packetSizeWeight     `json:"packetSizeWeights"`
	InstalledSessions   int                    `json:"installedSessions"`
	ActiveSessions      int                    `json:"activeSessions"`
	Streams             []streamResult         `json:"streams"`
	SGWUCounters        sgwudataplane.Counters `json:"sgwuCounters"`
	PGWUCounters        pgwudataplane.Counters `json:"pgwuCounters"`
	SGWUP95HandlerMS    float64                `json:"sgwuP95HandlerMilliseconds"`
	SGWUFastPathP95MS   float64                `json:"sgwuFastPathP95Milliseconds"`
	SessionSetupMS      float64                `json:"sessionSetupMilliseconds"`
	LoadProcessCPU      float64                `json:"loadProcessCPUPercent"`
	PeakResidentBytes   uint64                 `json:"peakResidentBytes"`
	GoHeapBytes         uint64                 `json:"goHeapBytes"`
	ElapsedMilliseconds float64                `json:"elapsedMilliseconds"`
	GOMAXPROCS          int                    `json:"goMaxProcs"`
	CPUAffinity         string                 `json:"cpuAffinity,omitempty"`
}

type measurement struct {
	direction        string
	runID            uint64
	received         atomic.Uint64
	sent             atomic.Uint64
	receivedBytes    atomic.Uint64
	sentBytes        atomic.Uint64
	writeErrs        atomic.Uint64
	readErrs         atomic.Uint64
	validationErrors atomic.Uint64
	socketDrops      atomic.Uint64
	latency          latencyHistogram
	started          time.Time
	ended            time.Time
	cancel           context.CancelFunc
	recvDone         chan struct{}
}

var latencyUpperBounds = [...]time.Duration{
	5 * time.Microsecond,
	10 * time.Microsecond,
	15 * time.Microsecond,
	20 * time.Microsecond,
	25 * time.Microsecond,
	30 * time.Microsecond,
	40 * time.Microsecond,
	50 * time.Microsecond,
	75 * time.Microsecond,
	100 * time.Microsecond,
	150 * time.Microsecond,
	200 * time.Microsecond,
	300 * time.Microsecond,
	500 * time.Microsecond,
	750 * time.Microsecond,
	1 * time.Millisecond,
	2 * time.Millisecond,
	5 * time.Millisecond,
	10 * time.Millisecond,
	20 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
}

type latencyHistogram struct {
	samples atomic.Uint64
	buckets [len(latencyUpperBounds) + 1]atomic.Uint64
}

func (h *latencyHistogram) record(sequence, sentAt uint64) {
	if sequence&latencySampleMask != 0 || sentAt == 0 {
		return
	}
	elapsed := time.Since(time.Unix(0, int64(sentAt)))
	if elapsed < 0 {
		return
	}
	h.samples.Add(1)
	for index, upper := range latencyUpperBounds {
		if elapsed <= upper {
			h.buckets[index].Add(1)
			return
		}
	}
	h.buckets[len(latencyUpperBounds)].Add(1)
}

func (h *latencyHistogram) quantile(value float64) float64 {
	samples := h.samples.Load()
	if samples == 0 {
		return 0
	}
	target := uint64(math.Ceil(float64(samples) * value))
	var cumulative uint64
	for index := range h.buckets {
		cumulative += h.buckets[index].Load()
		if cumulative >= target {
			if index == len(latencyUpperBounds) {
				return float64(latencyUpperBounds[len(latencyUpperBounds)-1]) / float64(time.Millisecond)
			}
			return float64(latencyUpperBounds[index]) / float64(time.Millisecond)
		}
	}
	return 0
}

func main() {
	direction := flag.String("direction", "both", "traffic direction: uplink, downlink, or both")
	duration := flag.Duration("duration", 3*time.Second, "offered-load duration")
	innerSize := flag.Int("inner-packet-bytes", 1200, "inner IPv4 packet size used for Mbps accounting")
	profile := flag.String("packet-profile", "fixed", "packet size profile: fixed or mobile-imix")
	sessions := flag.Int("sessions", 1, "number of SGW-U and PGW-U sessions installed before load")
	activeSessions := flag.Int("active-sessions", 0, "sessions selected by load; zero uses all installed sessions")
	targetPPS := flag.Int("target-pps", 60_000, "aggregate packets/s per direction; zero sends without pacing")
	workers := flag.Int("workers", 4, "sender workers per direction")
	socketBuffer := flag.Int("socket-buffer-bytes", 16<<20, "UDP socket buffer request")
	sgwuBackend := flag.String("sgwu-backend", "portable", "SGW-U backend: portable or tcx")
	accessInterface := flag.String("access-interface", "", "TCX SGW-U access interface")
	enbInterface := flag.String("enb-interface", "", "TCX synthetic eNodeB peer interface")
	coreInterface := flag.String("core-interface", "", "TCX SGW-U core interface")
	pgwInterface := flag.String("pgw-interface", "", "TCX synthetic PGW peer interface")
	pgwuPolicy := flag.Bool("pgwu-policy", false, "enable the production PGW-U TCX policy and URR layer")
	flag.Parse()

	value, err := run(config{
		direction: *direction, duration: *duration, innerSize: *innerSize,
		profileName: *profile, sessions: *sessions, activeSessions: *activeSessions,
		targetPPS: *targetPPS, workers: *workers, socketBuffer: *socketBuffer,
		sgwuBackend: *sgwuBackend, accessInterface: *accessInterface,
		enbInterface: *enbInterface, coreInterface: *coreInterface,
		pgwInterface: *pgwInterface,
		pgwuPolicy:   *pgwuPolicy,
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

type config struct {
	direction       string
	duration        time.Duration
	innerSize       int
	profileName     string
	profile         packetProfile
	sessions        int
	activeSessions  int
	targetPPS       int
	workers         int
	socketBuffer    int
	sgwuBackend     string
	accessInterface string
	enbInterface    string
	coreInterface   string
	pgwInterface    string
	pgwuPolicy      bool
}

func run(cfg config) (result, error) {
	started := time.Now()
	profile, err := newPacketProfile(cfg.profileName, cfg.innerSize)
	if err != nil {
		return result{}, err
	}
	cfg.profile = profile
	if cfg.activeSessions == 0 {
		cfg.activeSessions = cfg.sessions
	}
	if err := validateEnvironment(cfg); err != nil {
		return result{}, err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sessionSetupStarted := time.Now()
	sgwuStore := sgwurules.NewStoreWithLimit(cfg.sessions)
	for index := 0; index < cfg.sessions; index++ {
		if _, err := sgwuStore.Create(sgwuSession(index)); err != nil {
			return result{}, fmt.Errorf("create SGW-U rules for session %d: %w", index, err)
		}
	}
	sgwu, err := sgwudataplane.Listen(sgwudataplane.Config{
		Access:             netip.AddrPortFrom(sgwuAccessIP, gtpuPort),
		Core:               netip.AddrPortFrom(sgwuCoreIP, gtpuPort),
		AllowedAccessPeers: []netip.Addr{enbIP}, AllowedCorePeers: []netip.Addr{pgwuIP},
		SocketBufferBytes: cfg.socketBuffer,
	}, sgwuStore)
	if err != nil {
		return result{}, fmt.Errorf("start SGW-U dataplane: %w", err)
	}
	defer sgwu.Close()
	if cfg.sgwuBackend == "tcx" {
		accessNeighbour, err := benchmarkNeighbour(cfg.enbInterface, enbIP)
		if err != nil {
			return result{}, fmt.Errorf("resolve synthetic eNodeB neighbour: %w", err)
		}
		coreNeighbour, err := benchmarkNeighbour(cfg.pgwInterface, pgwuIP)
		if err != nil {
			return result{}, fmt.Errorf("resolve synthetic PGW neighbour: %w", err)
		}
		kernelPath, err := fastpath.Open(fastpath.Config{
			Access:      fastpath.Side{Interface: cfg.accessInterface, LocalIP: sgwuAccessIP, Neighbours: []fastpath.Neighbour{accessNeighbour}},
			Core:        fastpath.Side{Interface: cfg.coreInterface, LocalIP: sgwuCoreIP, Neighbours: []fastpath.Neighbour{coreNeighbour}},
			MaxSessions: cfg.sessions, MaxRules: fastPathRuleCapacity(cfg.sessions),
		}, sgwuStore)
		if err != nil {
			return result{}, fmt.Errorf("start SGW-U TCX dataplane: %w", err)
		}
		sgwu.SetFastPath(kernelPath)
	}

	kernelOwnerDirectory, err := os.MkdirTemp("", "sgw-next-dataplane-kernel-owner-")
	if err != nil {
		return result{}, fmt.Errorf("create temporary kernel ownership directory: %w", err)
	}
	defer os.RemoveAll(kernelOwnerDirectory)
	kernelConfig := pgwudataplane.KernelConfig{
		S5: netip.AddrPortFrom(pgwuIP, gtpuPort), AllowedSGWPeers: []netip.Addr{sgwuCoreIP},
		TunnelName: "lodcupspgw", OwnershipFile: filepath.Join(kernelOwnerDirectory, "kernel.owner"),
		UEPoolPrefix: uePrefix, UEGateway: ueGateway,
		HashSize: kernelHashSize(cfg.sessions), MTU: 1_400, SocketBufferBytes: cfg.socketBuffer,
		AllowUnsupportedPolicy: !cfg.pgwuPolicy,
	}
	if cfg.pgwuPolicy {
		kernelConfig.QCI1S5 = netip.AddrPortFrom(pgwuQCI1IP, gtpuPort)
		kernelConfig.QCI1TunnelName = "lodcupsqci1"
		kernelConfig.QCI1OwnershipFile = filepath.Join(kernelOwnerDirectory, "qci1-kernel.owner")
		kernelConfig.MaxSessions = cfg.sessions
		kernelConfig.MaxPolicyFilters = fastPathRuleCapacity(cfg.sessions)
		kernelConfig.QERBurstDuration = 100 * time.Millisecond
	}
	pgwu, err := pgwudataplane.OpenKernel(kernelConfig)
	if err != nil {
		return result{}, fmt.Errorf("start PGW-U kernel dataplane: %w", err)
	}
	defer pgwu.Close()
	pgwuStore := pgwurules.NewStoreWithApplier(cfg.sessions, pgwu)
	for index := 0; index < cfg.sessions; index++ {
		if _, err := pgwuStore.Create(pgwuSession(index, cfg.pgwuPolicy)); err != nil {
			return result{}, fmt.Errorf("create PGW-U rules for session %d: %w", index, err)
		}
	}
	sessionSetupDuration := time.Since(sessionSetupStarted)

	enb, err := listenUDP(netip.AddrPortFrom(enbIP, gtpuPort), cfg.socketBuffer)
	if err != nil {
		return result{}, fmt.Errorf("listen synthetic eNodeB: %w", err)
	}
	defer enb.Close()
	service, err := listenUDP(netip.AddrPortFrom(serviceIP, servicePort), cfg.socketBuffer)
	if err != nil {
		return result{}, fmt.Errorf("listen synthetic internet service: %w", err)
	}
	defer service.Close()
	enbReader, err := udpstats.NewReader(enb)
	if err != nil {
		return result{}, fmt.Errorf("enable synthetic eNodeB overflow accounting: %w", err)
	}
	serviceReader, err := udpstats.NewReader(service)
	if err != nil {
		return result{}, fmt.Errorf("enable synthetic service overflow accounting: %w", err)
	}

	serveCtx, cancelServe := context.WithCancel(ctx)
	serveDone := make(chan error, 1)
	go func() { serveDone <- sgwu.Serve(serveCtx) }()
	defer func() {
		cancelServe()
		select {
		case <-serveDone:
		case <-time.After(2 * time.Second):
		}
	}()
	time.Sleep(50 * time.Millisecond)
	if err := warmup(enb, enbReader, service, serviceReader, cfg); err != nil {
		return result{}, fmt.Errorf("dataplane preflight: %w; SGW-U counters=%+v; PGW-U counters=%+v", err, sgwu.Counters(), pgwu.Counters())
	}
	// Some kernel-GTP versions publish the first-link tx_error statistic from a
	// deferred per-CPU update even when the preflight packet is delivered. Let
	// that initialization accounting settle before taking the load baseline.
	time.Sleep(50 * time.Millisecond)
	_ = sgwu.Usage()
	sgwuBaseline := sgwu.Counters()
	pgwuBaseline := pgwu.Counters()

	plans := make([]*measurement, 0, 2)
	if cfg.direction == "uplink" || cfg.direction == "both" {
		plans = append(plans, startUplinkReceiver(ctx, serviceReader, cfg))
	}
	if cfg.direction == "downlink" || cfg.direction == "both" {
		plans = append(plans, startDownlinkReceiver(ctx, enbReader, cfg))
	}

	var senders sync.WaitGroup
	startAt := time.Now().Add(100 * time.Millisecond)
	loadCPUStart := processCPUTime()
	for _, current := range plans {
		current := current
		senders.Add(1)
		go func() {
			defer senders.Done()
			if current.direction == "uplink" {
				sendUplink(ctx, current, cfg, startAt)
			} else {
				sendDownlink(ctx, current, cfg, startAt)
			}
		}()
	}
	senders.Wait()
	loadCPUEnd := processCPUTime()
	loadWallDuration := time.Since(startAt)
	for _, current := range plans {
		drain(current, 2*time.Second)
		current.cancel()
		<-current.recvDone
	}

	streams := make([]streamResult, 0, len(plans))
	for _, current := range plans {
		if current.writeErrs.Load() != 0 {
			return result{}, fmt.Errorf("%s generator had %d UDP write errors", current.direction, current.writeErrs.Load())
		}
		if current.readErrs.Load() != 0 {
			return result{}, fmt.Errorf("%s receiver had %d UDP read errors", current.direction, current.readErrs.Load())
		}
		if current.validationErrors.Load() != 0 {
			return result{}, fmt.Errorf("%s receiver had %d session validation errors", current.direction, current.validationErrors.Load())
		}
		streams = append(streams, summarize(current, cfg))
	}
	_ = sgwu.Usage()
	sgwuCounters := subtractSGWUCounters(sgwu.Counters(), sgwuBaseline)
	pgwuCounters := subtractPGWUCounters(pgwu.Counters(), pgwuBaseline)
	scope := "real SGW-U portable Go relay chained to real PGW-U Linux kernel-GTP backend in one disposable network namespace"
	if cfg.sgwuBackend == "tcx" {
		scope = "real SGW-U TCX/eBPF rewrite chained to real PGW-U Linux kernel-GTP backend in one disposable network namespace"
	}
	if cfg.pgwuPolicy {
		scope += " with production PGW-U TCX QER/URR policy"
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	loadCPUPercent := float64(0)
	if loadWallDuration > 0 && loadCPUEnd >= loadCPUStart {
		loadCPUPercent = (loadCPUEnd - loadCPUStart).Seconds() / loadWallDuration.Seconds() * 100
	}
	return result{
		Scope: scope, PacketProfile: cfg.profile.name,
		PacketSizeWeights: append([]packetSizeWeight(nil), cfg.profile.weights...),
		InstalledSessions: cfg.sessions, ActiveSessions: cfg.activeSessions,
		Streams: streams, SGWUCounters: sgwuCounters, PGWUCounters: pgwuCounters,
		SGWUP95HandlerMS:    float64(sgwuCounters.P95LatencyMicros) / 1000,
		SGWUFastPathP95MS:   float64(sgwuCounters.FastPathP95Micros) / 1000,
		SessionSetupMS:      float64(sessionSetupDuration.Microseconds()) / 1000,
		LoadProcessCPU:      loadCPUPercent,
		PeakResidentBytes:   peakResidentBytes(),
		GoHeapBytes:         memory.HeapAlloc,
		ElapsedMilliseconds: float64(time.Since(started).Microseconds()) / 1000,
		GOMAXPROCS:          runtime.GOMAXPROCS(0),
		CPUAffinity:         os.Getenv("BENCH_CPU_LIST"),
	}, nil
}

func warmup(enb *net.UDPConn, enbReader *udpstats.Reader, service *net.UDPConn, serviceReader *udpstats.Reader, cfg config) error {
	probeSize := cfg.profile.size(1)
	probeUE := ueAddress(0)
	probeTunnels := sessionTunnels(0)
	deadline := time.Now().Add(time.Second)
	if err := serviceReader.SetReadDeadline(deadline); err != nil {
		return err
	}
	inner, _, err := innerUDPPacket(probeSize, probeUE, serviceIP, 10_000, servicePort, 1)
	if err != nil {
		return err
	}
	wire, err := gtpu.Marshal(gtpu.Header{
		Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: probeTunnels.enbIncoming,
	}, inner)
	if err != nil {
		return err
	}
	if _, err := enb.WriteToUDPAddrPort(wire, netip.AddrPortFrom(sgwuAccessIP, gtpuPort)); err != nil {
		return fmt.Errorf("send uplink probe: %w", err)
	}
	buffer := make([]byte, 65_535)
	n, _, _, err := serviceReader.ReadFromUDPAddrPort(buffer)
	if err != nil {
		return fmt.Errorf("receive uplink probe: %w", err)
	}
	if n < metadataBytes || binary.BigEndian.Uint64(buffer[:8]) != 1 {
		return errors.New("invalid uplink probe payload")
	}

	if err := enbReader.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	payload := make([]byte, probeSize-28)
	if _, err := service.WriteToUDPAddrPort(payload, netip.AddrPortFrom(probeUE, uePort)); err != nil {
		return fmt.Errorf("send downlink probe: %w", err)
	}
	n, _, _, err = enbReader.ReadFromUDPAddrPort(buffer)
	if err != nil {
		return fmt.Errorf("receive downlink probe: %w", err)
	}
	header, encapsulated, err := gtpu.Parse(buffer[:n])
	if err != nil {
		return fmt.Errorf("parse downlink probe: %w", err)
	}
	if header.TEID != probeTunnels.enbOutgoing {
		return fmt.Errorf("invalid downlink probe TEID: got %d, want %d", header.TEID, probeTunnels.enbOutgoing)
	}
	if _, ok := udpPayload(encapsulated, uePort); !ok {
		return errors.New("invalid downlink probe inner packet")
	}
	if err := serviceReader.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	return enbReader.SetReadDeadline(time.Time{})
}

func validateEnvironment(cfg config) error {
	if os.Getenv(guardEnvironment) != "1" {
		return fmt.Errorf("cups-dataplane-bench refuses to run unless %s=1", guardEnvironment)
	}
	if os.Geteuid() != 0 {
		return errors.New("cups-dataplane-bench requires root inside a disposable network namespace")
	}
	selfNS, selfErr := os.Readlink("/proc/self/ns/net")
	initNS, initErr := os.Readlink("/proc/1/ns/net")
	if selfErr == nil && initErr == nil && selfNS == initNS {
		return errors.New("cups-dataplane-bench refuses to run in the initial network namespace")
	}
	if cfg.direction != "uplink" && cfg.direction != "downlink" && cfg.direction != "both" {
		return errors.New("direction must be uplink, downlink, or both")
	}
	if err := validateDuration(cfg.duration); err != nil {
		return err
	}
	if cfg.innerSize < minimumInnerSize || cfg.innerSize > 1_400 {
		return fmt.Errorf("inner-packet-bytes must be between %d and 1400", minimumInnerSize)
	}
	if cfg.sessions < 1 || cfg.sessions > 1_000_000 {
		return errors.New("sessions must be between 1 and 1000000")
	}
	if cfg.activeSessions < 1 || cfg.activeSessions > cfg.sessions {
		return errors.New("active-sessions must be between 1 and sessions")
	}
	if cfg.profile.total == 0 {
		return errors.New("packet profile is empty")
	}
	if cfg.targetPPS < 0 || cfg.targetPPS > 10_000_000 {
		return errors.New("target-pps must be between 0 and 10000000")
	}
	if cfg.workers < 1 || cfg.workers > 128 {
		return errors.New("workers must be between 1 and 128")
	}
	if cfg.socketBuffer < 64*1024 || cfg.socketBuffer > 1<<30 {
		return errors.New("socket-buffer-bytes must be between 65536 and 1073741824")
	}
	if cfg.sgwuBackend != "portable" && cfg.sgwuBackend != "tcx" {
		return errors.New("sgwu-backend must be portable or tcx")
	}
	if cfg.sgwuBackend == "tcx" {
		for name, value := range map[string]string{
			"access-interface": cfg.accessInterface, "enb-interface": cfg.enbInterface,
			"core-interface": cfg.coreInterface, "pgw-interface": cfg.pgwInterface,
		} {
			if value == "" || len(value) > 15 {
				return fmt.Errorf("%s must be a 1..15 character interface name in TCX mode", name)
			}
		}
	}
	return nil
}

func validateDuration(duration time.Duration) error {
	if duration < 100*time.Millisecond || duration > maximumDuration {
		return errors.New("duration must be between 100ms and 10m")
	}
	return nil
}

func benchmarkNeighbour(interfaceName string, ip netip.Addr) (fastpath.Neighbour, error) {
	device, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fastpath.Neighbour{}, err
	}
	if len(device.HardwareAddr) != 6 {
		return fastpath.Neighbour{}, fmt.Errorf("interface %s has a non-Ethernet address", interfaceName)
	}
	return fastpath.Neighbour{IP: ip, MAC: append(net.HardwareAddr(nil), device.HardwareAddr...)}, nil
}

type tunnelSet struct {
	enbIncoming  uint32
	sgwuCore     uint32
	pgwuIncoming uint32
	enbOutgoing  uint32
}

func sessionTunnels(index int) tunnelSet {
	offset := uint32(index)
	return tunnelSet{
		enbIncoming: enbIncomingTEID + offset, sgwuCore: sgwuCoreIncomingTEID + offset,
		pgwuIncoming: pgwuIncomingTEID + offset, enbOutgoing: enbOutgoingTEID + offset,
	}
}

func sgwuSession(index int) sgwurules.Session {
	tunnels := sessionTunnels(index)
	outerCore := sgwurules.FTEID{TEID: tunnels.pgwuIncoming, IP: pgwuIP}
	outerAccess := sgwurules.FTEID{TEID: tunnels.enbOutgoing, IP: enbIP}
	return sgwurules.Session{
		CPSEID: uint64(index)*2 + 1, UPSEID: uint64(index)*2 + 2,
		PDRs: map[uint16]sgwurules.PDR{
			1: {ID: 1, SourceInterface: sgwurules.SourceAccess, LocalFTEID: sgwurules.FTEID{TEID: tunnels.enbIncoming, IP: sgwuAccessIP}, FARID: 1, QERIDs: []uint32{1}, URRIDs: []uint32{1}},
			2: {ID: 2, SourceInterface: sgwurules.SourceCore, LocalFTEID: sgwurules.FTEID{TEID: tunnels.sgwuCore, IP: sgwuCoreIP}, FARID: 2, QERIDs: []uint32{1}, URRIDs: []uint32{1}},
		},
		FARs: map[uint32]sgwurules.FAR{
			1: {ID: 1, ApplyAction: sgwurules.ActionForward, DestinationInterface: sgwurules.DestinationCore, OuterHeader: &outerCore},
			2: {ID: 2, ApplyAction: sgwurules.ActionForward, DestinationInterface: sgwurules.DestinationAccess, OuterHeader: &outerAccess},
		},
		QERs: map[uint32]sgwurules.QER{1: {
			ID: 1, UplinkGateOpen: true, DownlinkGateOpen: true, QCI: 9, ARP: 8,
		}},
		URRs: map[uint32]sgwurules.URR{1: {
			ID: 1, MeasureVolume: true, ReportingThreshold: 1 << 40,
		}},
	}
}

func pgwuSession(index int, policy bool) pgwurules.Session {
	tunnels := sessionTunnels(index)
	session := pgwurules.Session{
		CPSEID: uint64(index)*2 + 1, UPSEID: uint64(index)*2 + 2, UEIPv4: ueAddress(index),
		Local:          pgwurules.Tunnel{TEID: tunnels.pgwuIncoming, IP: pgwuIP},
		Remote:         pgwurules.Tunnel{TEID: tunnels.sgwuCore, IP: sgwuCoreIP},
		UplinkGateOpen: true, DownlinkGateOpen: true,
	}
	if policy {
		session.QERID = 1
		session.URRID = 1
		session.MeasureVolume = true
		session.UsageReportingThreshold = 1 << 40
	}
	return session
}

func ueAddress(index int) netip.Addr {
	base := uePrefix.Addr().As4()
	value := binary.BigEndian.Uint32(base[:]) + uint32(index) + 2
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return netip.AddrFrom4(raw)
}

func fastPathRuleCapacity(sessions int) int {
	if sessions < 2 {
		return 4
	}
	return sessions * 2
}

func kernelHashSize(sessions int) uint32 {
	// Linux's GTP link creation allocates the bucket array as one kernel
	// object. Very large bucket counts can fail even when normal RAM is ample.
	// Keep the proven production default as the ceiling and target no more
	// than eight contexts per bucket at the configured session limit.
	target := uint64(sessions+7) / 8
	value := uint32(1_024)
	for uint64(value) < target && value < 131_072 {
		value <<= 1
	}
	return value
}

func newPacketProfile(name string, fixedSize int) (packetProfile, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	var weights []packetSizeWeight
	switch name {
	case "fixed":
		weights = []packetSizeWeight{{InnerPacketBytes: fixedSize, Weight: 1}}
	case "mobile-imix":
		// Deterministic synthetic mobile mix: signalling/small ACKs, medium
		// application packets, and bulk payloads. It is not claimed as a
		// standards-defined or operator-measured distribution.
		weights = []packetSizeWeight{
			{InnerPacketBytes: 64, Weight: 40},
			{InnerPacketBytes: 256, Weight: 20},
			{InnerPacketBytes: 512, Weight: 10},
			{InnerPacketBytes: 1_200, Weight: 30},
		}
	default:
		return packetProfile{}, errors.New("packet-profile must be fixed or mobile-imix")
	}
	profile := packetProfile{name: name, weights: weights, cumulative: make([]uint64, len(weights))}
	var weightedBytes uint64
	for index, entry := range weights {
		if entry.InnerPacketBytes < minimumInnerSize || entry.InnerPacketBytes > 1_400 || entry.Weight < 1 {
			return packetProfile{}, errors.New("packet profile contains an invalid size or weight")
		}
		profile.total += uint64(entry.Weight)
		profile.cumulative[index] = profile.total
		weightedBytes += uint64(entry.InnerPacketBytes * entry.Weight)
	}
	profile.average = float64(weightedBytes) / float64(profile.total)
	return profile, nil
}

func (p packetProfile) size(sequence uint64) int {
	value := uint64(0)
	if p.total > 0 && sequence > 0 {
		value = (sequence - 1) % p.total
	}
	for index, upper := range p.cumulative {
		if value < upper {
			return p.weights[index].InnerPacketBytes
		}
	}
	return p.weights[len(p.weights)-1].InnerPacketBytes
}

func (p packetProfile) maxSize() int {
	maximum := 0
	for _, entry := range p.weights {
		if entry.InnerPacketBytes > maximum {
			maximum = entry.InnerPacketBytes
		}
	}
	return maximum
}

func sessionIndex(sequence uint64, active int) int {
	value := sequence + 0x9e3779b97f4a7c15
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9
	value = (value ^ (value >> 27)) * 0x94d049bb133111eb
	value ^= value >> 31
	return int(value % uint64(active))
}

func listenUDP(address netip.AddrPort, bufferBytes int) (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(address))
	if err != nil {
		return nil, err
	}
	if err := conn.SetReadBuffer(bufferBytes); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetWriteBuffer(bufferBytes); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func newMeasurement(parent context.Context, direction string) (*measurement, context.Context) {
	ctx, cancel := context.WithCancel(parent)
	value := &measurement{
		direction: direction, runID: uint64(time.Now().UnixNano()) ^ uint64(len(direction))<<56,
		cancel: cancel, recvDone: make(chan struct{}),
	}
	return value, ctx
}

func startUplinkReceiver(parent context.Context, service *udpstats.Reader, cfg config) *measurement {
	value, ctx := newMeasurement(parent, "uplink")
	go func() {
		defer close(value.recvDone)
		batch, err := service.NewBatch(receiverBatchSize, 65_535)
		if err != nil {
			value.readErrs.Add(1)
			return
		}
		for {
			_ = service.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, socketDrops, err := service.ReadBatch(batch)
			if err != nil {
				if isTimeout(err) {
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}
				value.readErrs.Add(1)
				return
			}
			value.socketDrops.Add(socketDrops)
			for index := 0; index < n; index++ {
				datagram := &batch.Datagrams[index]
				buffer := datagram.Buffer[:datagram.N]
				if len(buffer) >= metadataBytes && binary.BigEndian.Uint64(buffer[:8]) == value.runID {
					sequence := binary.BigEndian.Uint64(buffer[8:16])
					expectedSession := sessionIndex(sequence, cfg.activeSessions)
					claimedSession := binary.BigEndian.Uint64(buffer[24:32])
					if claimedSession != uint64(expectedSession) || datagram.Peer.Addr().Unmap() != ueAddress(expectedSession) {
						value.validationErrors.Add(1)
						continue
					}
					value.received.Add(1)
					value.receivedBytes.Add(uint64(len(buffer) + 28))
					value.latency.record(sequence, binary.BigEndian.Uint64(buffer[16:24]))
				}
			}
		}
	}()
	return value
}

func startDownlinkReceiver(parent context.Context, enb *udpstats.Reader, cfg config) *measurement {
	value, ctx := newMeasurement(parent, "downlink")
	go func() {
		defer close(value.recvDone)
		batch, err := enb.NewBatch(receiverBatchSize, 65_535)
		if err != nil {
			value.readErrs.Add(1)
			return
		}
		for {
			_ = enb.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, socketDrops, err := enb.ReadBatch(batch)
			if err != nil {
				if isTimeout(err) {
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}
				value.readErrs.Add(1)
				return
			}
			value.socketDrops.Add(socketDrops)
			for index := 0; index < n; index++ {
				datagram := &batch.Datagrams[index]
				header, inner, parseErr := gtpu.Parse(datagram.Buffer[:datagram.N])
				if parseErr != nil {
					continue
				}
				application, ok := udpPayload(inner, uePort)
				if ok && len(application) >= metadataBytes && binary.BigEndian.Uint64(application[:8]) == value.runID {
					sequence := binary.BigEndian.Uint64(application[8:16])
					expectedSession := sessionIndex(sequence, cfg.activeSessions)
					claimedSession := binary.BigEndian.Uint64(application[24:32])
					if claimedSession != uint64(expectedSession) || header.TEID != sessionTunnels(expectedSession).enbOutgoing || innerIPv4Destination(inner) != ueAddress(expectedSession) {
						value.validationErrors.Add(1)
						continue
					}
					value.received.Add(1)
					value.receivedBytes.Add(uint64(len(inner)))
					value.latency.record(sequence, binary.BigEndian.Uint64(application[16:24]))
				}
			}
		}
	}()
	return value
}

func sendUplink(ctx context.Context, value *measurement, cfg config, startAt time.Time) {
	destination := netip.AddrPortFrom(sgwuAccessIP, gtpuPort)
	sendWorkers(ctx, value, cfg, startAt, func(worker int) (func(uint64) error, func() error, error) {
		sender, err := listenUDP(netip.AddrPortFrom(enbIP, 0), cfg.socketBuffer)
		if err != nil {
			return nil, nil, err
		}
		inner, sequenceOffset, err := innerUDPPacket(cfg.profile.maxSize(), ueAddress(0), serviceIP, uint16(10_000+worker), servicePort, value.runID)
		if err != nil {
			_ = sender.Close()
			return nil, nil, err
		}
		wire, err := gtpu.Marshal(gtpu.Header{Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: sessionTunnels(0).enbIncoming}, inner)
		if err != nil {
			_ = sender.Close()
			return nil, nil, err
		}
		wireOffset := 8 + sequenceOffset
		return func(sequence uint64) error {
			session := sessionIndex(sequence, cfg.activeSessions)
			packetSize := cfg.profile.size(sequence)
			tunnels := sessionTunnels(session)
			binary.BigEndian.PutUint16(wire[2:4], uint16(packetSize))
			binary.BigEndian.PutUint32(wire[4:8], tunnels.enbIncoming)
			innerPacket := wire[8 : 8+packetSize]
			binary.BigEndian.PutUint16(innerPacket[2:4], uint16(packetSize))
			source := ueAddress(session).As4()
			copy(innerPacket[12:16], source[:])
			binary.BigEndian.PutUint16(innerPacket[10:12], 0)
			binary.BigEndian.PutUint16(innerPacket[10:12], ipv4Checksum(innerPacket[:20]))
			binary.BigEndian.PutUint16(innerPacket[24:26], uint16(packetSize-20))
			binary.BigEndian.PutUint64(wire[wireOffset:wireOffset+8], sequence)
			binary.BigEndian.PutUint64(wire[wireOffset+8:wireOffset+16], uint64(time.Now().UnixNano()))
			binary.BigEndian.PutUint64(wire[wireOffset+16:wireOffset+24], uint64(session))
			value.sentBytes.Add(uint64(packetSize))
			_, err := sender.WriteToUDPAddrPort(wire[:8+packetSize], destination)
			return err
		}, sender.Close, nil
	})
}

func sendDownlink(ctx context.Context, value *measurement, cfg config, startAt time.Time) {
	sendWorkers(ctx, value, cfg, startAt, func(int) (func(uint64) error, func() error, error) {
		sender, err := listenUDP(netip.AddrPortFrom(serviceIP, 0), cfg.socketBuffer)
		if err != nil {
			return nil, nil, err
		}
		payload := make([]byte, cfg.profile.maxSize()-28)
		binary.BigEndian.PutUint64(payload[:8], value.runID)
		return func(sequence uint64) error {
			session := sessionIndex(sequence, cfg.activeSessions)
			packetSize := cfg.profile.size(sequence)
			binary.BigEndian.PutUint64(payload[8:16], sequence)
			binary.BigEndian.PutUint64(payload[16:24], uint64(time.Now().UnixNano()))
			binary.BigEndian.PutUint64(payload[24:32], uint64(session))
			value.sentBytes.Add(uint64(packetSize))
			_, err := sender.WriteToUDPAddrPort(payload[:packetSize-28], netip.AddrPortFrom(ueAddress(session), uePort))
			return err
		}, sender.Close, nil
	})
}

type senderFactory func(worker int) (send func(sequence uint64) error, close func() error, err error)

func sendWorkers(ctx context.Context, value *measurement, cfg config, startAt time.Time, factory senderFactory) {
	value.started = startAt
	deadline := startAt.Add(cfg.duration)
	var workers sync.WaitGroup
	for worker := 0; worker < cfg.workers; worker++ {
		worker := worker
		workers.Add(1)
		go func() {
			defer workers.Done()
			send, closeSender, err := factory(worker)
			if err != nil {
				value.writeErrs.Add(1)
				return
			}
			defer closeSender()
			if wait := time.Until(startAt); wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
			rate := workerRate(cfg.targetPPS, cfg.workers, worker)
			if cfg.targetPPS == 0 {
				for time.Now().Before(deadline) {
					select {
					case <-ctx.Done():
						return
					default:
					}
					sequence := value.sent.Add(1)
					if err := send(sequence); err != nil {
						value.writeErrs.Add(1)
					}
				}
				return
			}
			pacedSend(ctx, deadline, rate, func() {
				sequence := value.sent.Add(1)
				if err := send(sequence); err != nil {
					value.writeErrs.Add(1)
				}
			})
		}()
	}
	workers.Wait()
	value.ended = time.Now()
}

func workerRate(total, workers, worker int) int {
	base := total / workers
	if worker < total%workers {
		base++
	}
	return base
}

func pacedSend(ctx context.Context, deadline time.Time, packetsPerSecond int, send func()) {
	if packetsPerSecond <= 0 {
		return
	}
	ticker := time.NewTicker(100 * time.Microsecond)
	defer ticker.Stop()
	last := time.Now()
	tokens := float64(0)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if !now.Before(deadline) {
				return
			}
			tokens += now.Sub(last).Seconds() * float64(packetsPerSecond)
			last = now
			count := int(tokens)
			tokens -= float64(count)
			for index := 0; index < count; index++ {
				send()
			}
		}
	}
}

func drain(value *measurement, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	last := value.received.Load()
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		if last >= value.sent.Load() {
			return
		}
		time.Sleep(25 * time.Millisecond)
		current := value.received.Load()
		if current != last {
			last = current
			stableSince = time.Now()
		} else if time.Since(stableSince) >= 200*time.Millisecond {
			return
		}
	}
}

func summarize(value *measurement, cfg config) streamResult {
	sent := value.sent.Load()
	received := value.received.Load()
	sentBytes := value.sentBytes.Load()
	receivedBytes := value.receivedBytes.Load()
	lost := uint64(0)
	if sent > received {
		lost = sent - received
	}
	elapsed := value.ended.Sub(value.started).Seconds()
	if elapsed <= 0 {
		elapsed = cfg.duration.Seconds()
	}
	lossPercent := float64(0)
	if sent > 0 {
		lossPercent = float64(lost) / float64(sent) * 100
	}
	fixedSize := 0
	if cfg.profile.name == "fixed" {
		fixedSize = cfg.innerSize
	}
	return streamResult{
		Direction: value.direction, InnerPacketBytes: fixedSize,
		PacketProfile: cfg.profile.name, AveragePacketBytes: cfg.profile.average,
		InstalledSessions: cfg.sessions, ActiveSessions: cfg.activeSessions, Workers: cfg.workers,
		TargetPacketsPerS: cfg.targetPPS, DurationMS: elapsed * 1000,
		SentPackets: sent, ReceivedPackets: received, ReceiverSocketDrops: value.socketDrops.Load(), LostPackets: lost, LossPercent: lossPercent,
		SentPacketsPerS: float64(sent) / elapsed, ReceivedPacketsPerS: float64(received) / elapsed,
		OfferedMbps:    float64(sentBytes*8) / elapsed / 1_000_000,
		ReceivedMbps:   float64(receivedBytes*8) / elapsed / 1_000_000,
		LatencySamples: value.latency.samples.Load(),
		P50LatencyMS:   value.latency.quantile(0.50),
		P95LatencyMS:   value.latency.quantile(0.95),
		P99LatencyMS:   value.latency.quantile(0.99),
	}
}

func innerUDPPacket(size int, source, destination netip.Addr, sourcePort, destinationPort uint16, runID uint64) ([]byte, int, error) {
	if size < minimumInnerSize || !source.Is4() || !destination.Is4() {
		return nil, 0, errors.New("invalid inner IPv4 packet parameters")
	}
	packet := make([]byte, size)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(size))
	binary.BigEndian.PutUint16(packet[6:8], 0x4000)
	packet[8] = 64
	packet[9] = 17
	sourceRaw := source.As4()
	destinationRaw := destination.As4()
	copy(packet[12:16], sourceRaw[:])
	copy(packet[16:20], destinationRaw[:])
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(size-20))
	applicationOffset := 28
	binary.BigEndian.PutUint64(packet[applicationOffset:applicationOffset+8], runID)
	return packet, applicationOffset + 8, nil
}

func udpPayload(inner []byte, destinationPort uint16) ([]byte, bool) {
	if len(inner) < 28 || inner[0]>>4 != 4 || inner[9] != 17 {
		return nil, false
	}
	headerBytes := int(inner[0]&0x0f) * 4
	if headerBytes < 20 || len(inner) < headerBytes+8 || binary.BigEndian.Uint16(inner[headerBytes+2:headerBytes+4]) != destinationPort {
		return nil, false
	}
	length := int(binary.BigEndian.Uint16(inner[headerBytes+4 : headerBytes+6]))
	if length < 8 || headerBytes+length > len(inner) {
		return nil, false
	}
	return inner[headerBytes+8 : headerBytes+length], true
}

func innerIPv4Destination(inner []byte) netip.Addr {
	if len(inner) < 20 || inner[0]>>4 != 4 {
		return netip.Addr{}
	}
	var raw [4]byte
	copy(raw[:], inner[16:20])
	return netip.AddrFrom4(raw)
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[index : index+2]))
	}
	for sum > math.MaxUint16 {
		sum = (sum & math.MaxUint16) + (sum >> 16)
	}
	return ^uint16(sum)
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func processCPUTime() time.Duration {
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	return time.Duration(usage.Utime.Sec)*time.Second + time.Duration(usage.Utime.Usec)*time.Microsecond +
		time.Duration(usage.Stime.Sec)*time.Second + time.Duration(usage.Stime.Usec)*time.Microsecond
}

func peakResidentBytes() uint64 {
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil || usage.Maxrss < 0 {
		return 0
	}
	// Linux reports ru_maxrss in KiB. This executable refuses to run outside
	// a Linux network namespace, so the conversion is unambiguous.
	return uint64(usage.Maxrss) * 1_024
}

func subtractSGWUCounters(current, baseline sgwudataplane.Counters) sgwudataplane.Counters {
	return sgwudataplane.Counters{
		AccessPackets:            current.AccessPackets - baseline.AccessPackets,
		CorePackets:              current.CorePackets - baseline.CorePackets,
		ForwardedPackets:         current.ForwardedPackets - baseline.ForwardedPackets,
		ForwardedBytes:           current.ForwardedBytes - baseline.ForwardedBytes,
		UplinkBytes:              current.UplinkBytes - baseline.UplinkBytes,
		DownlinkBytes:            current.DownlinkBytes - baseline.DownlinkBytes,
		DroppedPackets:           current.DroppedPackets - baseline.DroppedPackets,
		AccessSocketDrops:        current.AccessSocketDrops - baseline.AccessSocketDrops,
		CoreSocketDrops:          current.CoreSocketDrops - baseline.CoreSocketDrops,
		UnknownTEIDs:             current.UnknownTEIDs - baseline.UnknownTEIDs,
		MalformedPackets:         current.MalformedPackets - baseline.MalformedPackets,
		UnauthorizedPeers:        current.UnauthorizedPeers - baseline.UnauthorizedPeers,
		EchoRequests:             current.EchoRequests - baseline.EchoRequests,
		DownlinkReports:          current.DownlinkReports - baseline.DownlinkReports,
		BufferedPackets:          current.BufferedPackets,
		BufferedBytes:            current.BufferedBytes,
		BufferEnqueued:           current.BufferEnqueued - baseline.BufferEnqueued,
		BufferFlushed:            current.BufferFlushed - baseline.BufferFlushed,
		BufferExpired:            current.BufferExpired - baseline.BufferExpired,
		BufferOverflowDrops:      current.BufferOverflowDrops - baseline.BufferOverflowDrops,
		BufferPurged:             current.BufferPurged - baseline.BufferPurged,
		BufferClasses:            subtractBufferClasses(current.BufferClasses, baseline.BufferClasses),
		FastPathFallbacks:        current.FastPathFallbacks - baseline.FastPathFallbacks,
		FastPathForwardedPackets: current.FastPathForwardedPackets - baseline.FastPathForwardedPackets,
		FastPathForwardedBytes:   current.FastPathForwardedBytes - baseline.FastPathForwardedBytes,
		FastPathSyncFailures:     current.FastPathSyncFailures - baseline.FastPathSyncFailures,
		FastPathRewriteErrors:    current.FastPathRewriteErrors - baseline.FastPathRewriteErrors,
		FastPathP95Micros:        current.FastPathP95Micros,
		P95LatencyMicros:         current.P95LatencyMicros,
		QERGateDrops:             current.QERGateDrops - baseline.QERGateDrops,
		QERRateDrops:             current.QERRateDrops - baseline.QERRateDrops,
		URRMeteredPackets:        current.URRMeteredPackets - baseline.URRMeteredPackets,
		URRMeteredBytes:          current.URRMeteredBytes - baseline.URRMeteredBytes,
		URRThresholdEvents:       current.URRThresholdEvents - baseline.URRThresholdEvents,
		URRActiveMeters:          current.URRActiveMeters,
	}
}

func subtractBufferClasses(current, baseline []sgwudataplane.BufferClassCounters) []sgwudataplane.BufferClassCounters {
	previous := make(map[uint8]sgwudataplane.BufferClassCounters, len(baseline))
	for _, class := range baseline {
		previous[class.QCI] = class
	}
	out := make([]sgwudataplane.BufferClassCounters, 0, len(current))
	for _, class := range current {
		before := previous[class.QCI]
		out = append(out, sgwudataplane.BufferClassCounters{
			QCI: class.QCI, CurrentPackets: class.CurrentPackets, CurrentBytes: class.CurrentBytes,
			Enqueued: class.Enqueued - before.Enqueued, Flushed: class.Flushed - before.Flushed,
			Expired: class.Expired - before.Expired, OverflowDrops: class.OverflowDrops - before.OverflowDrops,
			Purged: class.Purged - before.Purged,
		})
	}
	return out
}

func subtractPGWUCounters(current, baseline pgwudataplane.Counters) pgwudataplane.Counters {
	return pgwudataplane.Counters{
		UplinkPackets:          current.UplinkPackets - baseline.UplinkPackets,
		DownlinkPackets:        current.DownlinkPackets - baseline.DownlinkPackets,
		DefaultUplinkPackets:   current.DefaultUplinkPackets - baseline.DefaultUplinkPackets,
		DefaultUplinkBytes:     current.DefaultUplinkBytes - baseline.DefaultUplinkBytes,
		DefaultDownlinkPackets: current.DefaultDownlinkPackets - baseline.DefaultDownlinkPackets,
		DefaultDownlinkBytes:   current.DefaultDownlinkBytes - baseline.DefaultDownlinkBytes,
		QCI1UplinkPackets:      current.QCI1UplinkPackets - baseline.QCI1UplinkPackets,
		QCI1UplinkBytes:        current.QCI1UplinkBytes - baseline.QCI1UplinkBytes,
		QCI1DownlinkPackets:    current.QCI1DownlinkPackets - baseline.QCI1DownlinkPackets,
		QCI1DownlinkBytes:      current.QCI1DownlinkBytes - baseline.QCI1DownlinkBytes,
		QCI1RoutePackets:       current.QCI1RoutePackets - baseline.QCI1RoutePackets,
		ActiveTFTFilters:       current.ActiveTFTFilters,
		ActiveQCI1Sessions:     current.ActiveQCI1Sessions,
		ActiveQCI1Contexts:     current.ActiveQCI1Contexts,
		TFTSyncErrors:          current.TFTSyncErrors - baseline.TFTSyncErrors,
		ForwardedPackets:       current.ForwardedPackets - baseline.ForwardedPackets,
		ForwardedBytes:         current.ForwardedBytes - baseline.ForwardedBytes,
		UplinkBytes:            current.UplinkBytes - baseline.UplinkBytes,
		DownlinkBytes:          current.DownlinkBytes - baseline.DownlinkBytes,
		DroppedPackets:         current.DroppedPackets - baseline.DroppedPackets,
		UnknownTEIDs:           current.UnknownTEIDs - baseline.UnknownTEIDs,
		TFTUnmatched:           current.TFTUnmatched - baseline.TFTUnmatched,
		FragmentDrops:          current.FragmentDrops - baseline.FragmentDrops,
		UnknownUEAddresses:     current.UnknownUEAddresses - baseline.UnknownUEAddresses,
		UnauthorizedPeers:      current.UnauthorizedPeers - baseline.UnauthorizedPeers,
		MalformedGTP:           current.MalformedGTP - baseline.MalformedGTP,
		MalformedIP:            current.MalformedIP - baseline.MalformedIP,
		SpoofedSources:         current.SpoofedSources - baseline.SpoofedSources,
		ClosedGates:            current.ClosedGates - baseline.ClosedGates,
		QERGateDrops:           current.QERGateDrops - baseline.QERGateDrops,
		QERRateDrops:           current.QERRateDrops - baseline.QERRateDrops,
		URRMeteredPackets:      current.URRMeteredPackets - baseline.URRMeteredPackets,
		URRMeteredBytes:        current.URRMeteredBytes - baseline.URRMeteredBytes,
		URRThresholdEvents:     current.URRThresholdEvents - baseline.URRThresholdEvents,
		URRActiveMeters:        current.URRActiveMeters,
		WriteErrors:            current.WriteErrors - baseline.WriteErrors,
		QueueFullDrops:         current.QueueFullDrops - baseline.QueueFullDrops,
		EchoRequests:           current.EchoRequests - baseline.EchoRequests,
		EndMarkers:             current.EndMarkers - baseline.EndMarkers,
		P50LatencyMicros:       current.P50LatencyMicros,
		P95LatencyMicros:       current.P95LatencyMicros,
		P99LatencyMicros:       current.P99LatencyMicros,
		P999LatencyMicros:      current.P999LatencyMicros,
		MaxLatencyMicros:       current.MaxLatencyMicros,
		RecoveredGTPLinks:      current.RecoveredGTPLinks - baseline.RecoveredGTPLinks,
		RecoveredFirewalls:     current.RecoveredFirewalls - baseline.RecoveredFirewalls,
		RecoveredPolicyRules:   current.RecoveredPolicyRules - baseline.RecoveredPolicyRules,
	}
}
