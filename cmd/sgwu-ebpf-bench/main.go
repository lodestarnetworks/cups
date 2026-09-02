package main

import (
	"context"
	"crypto/rand"
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
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/lodestarnetworks/cups/internal/sgwu/dataplane"
	"github.com/lodestarnetworks/cups/internal/sgwu/fastpath"
	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
)

const (
	guardEnvironment = "SGW_NEXT_ISOLATED_EBPF_BENCH"
	gtpuPort         = 2152
	ethernetBytes    = 14
	ipv4Bytes        = 20
	udpBytes         = 8
	gtpuBytes        = 8
	metadataBytes    = 24
)

var (
	accessLocalIP = netip.MustParseAddr("10.253.1.1")
	enbIP         = netip.MustParseAddr("10.253.1.2")
	coreLocalIP   = netip.MustParseAddr("10.253.2.1")
	pgwIP         = netip.MustParseAddr("10.253.2.2")
)

type config struct {
	direction       string
	duration        time.Duration
	innerSize       int
	targetPPS       int
	workers         int
	receiverWorkers int
	socketBuffer    int
	accessInterface string
	enbInterface    string
	coreInterface   string
	pgwInterface    string
}

type result struct {
	Scope               string                     `json:"scope"`
	Streams             []streamResult             `json:"streams"`
	FastPathCounters    dataplane.FastPathCounters `json:"fastPathCounters"`
	ElapsedMilliseconds float64                    `json:"elapsedMilliseconds"`
	GOMAXPROCS          int                        `json:"goMaxProcs"`
	CPUAffinity         string                     `json:"cpuAffinity"`
}

type streamResult struct {
	Direction                    string  `json:"direction"`
	InnerPacketBytes             int     `json:"innerPacketBytes"`
	Workers                      int     `json:"workers"`
	ReceiverWorkers              int     `json:"receiverWorkers"`
	TargetPacketsPerSecond       int     `json:"targetPacketsPerSecond"`
	DurationMilliseconds         float64 `json:"durationMilliseconds"`
	SentPackets                  uint64  `json:"sentPackets"`
	ReceivedPackets              uint64  `json:"receivedPackets"`
	ReceiverSocketDroppedPackets uint64  `json:"receiverSocketDroppedPackets"`
	LostPackets                  uint64  `json:"lostPackets"`
	LossPercent                  float64 `json:"lossPercent"`
	SentPacketsPerSecond         float64 `json:"sentPacketsPerSecond"`
	ReceivedPacketsPerSecond     float64 `json:"receivedPacketsPerSecond"`
	OfferedMbps                  float64 `json:"offeredMbps"`
	ReceivedMbps                 float64 `json:"receivedMbps"`
	LatencySamples               uint64  `json:"latencySamples"`
	P50LatencyMilliseconds       float64 `json:"p50LatencyMilliseconds"`
	P95LatencyMilliseconds       float64 `json:"p95LatencyMilliseconds"`
	P99LatencyMilliseconds       float64 `json:"p99LatencyMilliseconds"`
}

type packetEndpoint struct {
	sendFD    int
	ifindex   int
	receivers []int
}

type trafficPlan struct {
	direction  string
	source     *packetEndpoint
	receiver   *packetEndpoint
	sourceMAC  [6]byte
	targetMAC  [6]byte
	sourceIP   netip.Addr
	targetIP   netip.Addr
	inputTEID  uint32
	outputTEID uint32
	runID      uint64

	sequence    atomic.Uint64
	sent        atomic.Uint64
	received    atomic.Uint64
	writeErrors atomic.Uint64
	histogram   latencyHistogram
}

var latencyUpperBounds = [...]time.Duration{
	10 * time.Microsecond, 25 * time.Microsecond, 50 * time.Microsecond,
	100 * time.Microsecond, 250 * time.Microsecond, 500 * time.Microsecond,
	time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond,
	10 * time.Millisecond, 20 * time.Millisecond, 50 * time.Millisecond,
	100 * time.Millisecond,
}

type latencyHistogram struct {
	samples atomic.Uint64
	buckets [len(latencyUpperBounds) + 1]atomic.Uint64
}

type multiMessageHeader struct {
	header unix.Msghdr
	length uint32
	_      uint32
}

type receiveBatch struct {
	buffers  [][]byte
	iovecs   []unix.Iovec
	messages []multiMessageHeader
}

func main() {
	direction := flag.String("direction", "both", "traffic direction: uplink, downlink, or both")
	duration := flag.Duration("duration", 5*time.Second, "offered-load duration")
	innerSize := flag.Int("inner-packet-bytes", 1200, "GTP-U payload bytes used for Mbps accounting")
	targetPPS := flag.Int("target-pps", 100_000, "packets/s per direction; zero sends without pacing")
	workers := flag.Int("workers", 4, "sender workers per direction")
	receiverWorkers := flag.Int("receiver-workers", 4, "AF_PACKET fanout receivers per direction")
	socketBuffer := flag.Int("socket-buffer-bytes", 16<<20, "AF_PACKET socket buffer request")
	accessInterface := flag.String("access-interface", "lseacc", "SGW-U access-side veth")
	enbInterface := flag.String("enb-interface", "lseenb", "synthetic eNodeB veth")
	coreInterface := flag.String("core-interface", "lsecore", "SGW-U core-side veth")
	pgwInterface := flag.String("pgw-interface", "lsepgw", "synthetic PGW veth")
	flag.Parse()

	value, err := run(config{
		direction: *direction, duration: *duration, innerSize: *innerSize,
		targetPPS: *targetPPS, workers: *workers, receiverWorkers: *receiverWorkers, socketBuffer: *socketBuffer,
		accessInterface: *accessInterface, enbInterface: *enbInterface,
		coreInterface: *coreInterface, pgwInterface: *pgwInterface,
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

	accessDevice, err := net.InterfaceByName(cfg.accessInterface)
	if err != nil {
		return result{}, err
	}
	enbDevice, err := net.InterfaceByName(cfg.enbInterface)
	if err != nil {
		return result{}, err
	}
	coreDevice, err := net.InterfaceByName(cfg.coreInterface)
	if err != nil {
		return result{}, err
	}
	pgwDevice, err := net.InterfaceByName(cfg.pgwInterface)
	if err != nil {
		return result{}, err
	}

	store := rules.NewStoreWithLimit(16)
	if _, err := store.Create(benchmarkSession()); err != nil {
		return result{}, err
	}
	backend, err := fastpath.Open(fastpath.Config{
		Access:      fastpath.Side{Interface: cfg.accessInterface, LocalIP: accessLocalIP, Neighbours: []fastpath.Neighbour{{IP: enbIP, MAC: enbDevice.HardwareAddr}}},
		Core:        fastpath.Side{Interface: cfg.coreInterface, LocalIP: coreLocalIP, Neighbours: []fastpath.Neighbour{{IP: pgwIP, MAC: pgwDevice.HardwareAddr}}},
		MaxSessions: 16, MaxRules: 64,
	}, store)
	if err != nil {
		return result{}, err
	}
	defer backend.Close()

	enbSocket, err := openPacketEndpoint(enbDevice, cfg.socketBuffer, cfg.receiverWorkers)
	if err != nil {
		return result{}, err
	}
	defer enbSocket.close()
	pgwSocket, err := openPacketEndpoint(pgwDevice, cfg.socketBuffer, cfg.receiverWorkers)
	if err != nil {
		return result{}, err
	}
	defer pgwSocket.close()

	plans := make([]*trafficPlan, 0, 2)
	if cfg.direction == "uplink" || cfg.direction == "both" {
		plans = append(plans, newTrafficPlan("uplink", enbSocket, pgwSocket, enbDevice.HardwareAddr, accessDevice.HardwareAddr, enbIP, accessLocalIP, 100, 200))
	}
	if cfg.direction == "downlink" || cfg.direction == "both" {
		plans = append(plans, newTrafficPlan("downlink", pgwSocket, enbSocket, pgwDevice.HardwareAddr, coreDevice.HardwareAddr, pgwIP, coreLocalIP, 300, 400))
	}
	for _, plan := range plans {
		if err := warmup(plan, cfg.innerSize); err != nil {
			return result{}, fmt.Errorf("%s preflight: %w", plan.direction, err)
		}
	}
	// PACKET_STATISTICS resets when read, so the load window excludes preflight.
	_, _ = enbSocket.statistics()
	_, _ = pgwSocket.statistics()
	// Refresh URR accounting too, excluding each direction's preflight packet
	// from the measured policy counters as well as the wire/capture counters.
	_ = backend.Usage()
	baseline := backend.Counters()

	measureCtx, cancelMeasure := context.WithCancel(ctx)
	var receiverWait sync.WaitGroup
	for _, plan := range plans {
		for _, fd := range plan.receiver.receivers {
			receiverWait.Add(1)
			go func(current *trafficPlan, receiveFD int) {
				defer receiverWait.Done()
				current.receive(measureCtx, receiveFD)
			}(plan, fd)
		}
	}
	startAt := time.Now().Add(100 * time.Millisecond)
	endAt := startAt.Add(cfg.duration)
	var senderWait sync.WaitGroup
	for _, plan := range plans {
		for worker := 0; worker < cfg.workers; worker++ {
			senderWait.Add(1)
			go func(current *trafficPlan, workerID int) {
				defer senderWait.Done()
				current.send(measureCtx, cfg, workerID, startAt, endAt)
			}(plan, worker)
		}
	}
	senderWait.Wait()
	time.Sleep(2 * time.Second)
	cancelMeasure()
	receiverWait.Wait()

	enbPackets, enbDrops := enbSocket.statistics()
	pgwPackets, pgwDrops := pgwSocket.statistics()
	_ = enbPackets
	_ = pgwPackets
	streams := make([]streamResult, 0, len(plans))
	for _, plan := range plans {
		if plan.writeErrors.Load() != 0 {
			return result{}, fmt.Errorf("%s generator had %d raw-socket write errors", plan.direction, plan.writeErrors.Load())
		}
		drops := uint64(pgwDrops)
		if plan.direction == "downlink" {
			drops = uint64(enbDrops)
		}
		streams = append(streams, plan.summarize(cfg, drops))
	}
	// Refresh kernel URR snapshots before collecting the final counter set so
	// the benchmark includes the same accounting work used by live bearers.
	_ = backend.Usage()
	return result{
		Scope:   "real SGW-U eBPF TCX ingress rewrite/redirect across two disposable veth pairs in one isolated network namespace",
		Streams: streams, FastPathCounters: subtractCounters(backend.Counters(), baseline),
		ElapsedMilliseconds: float64(time.Since(started).Microseconds()) / 1000,
		GOMAXPROCS:          runtime.GOMAXPROCS(0), CPUAffinity: os.Getenv("BENCH_CPU_LIST"),
	}, nil
}

func benchmarkSession() rules.Session {
	outerCore := rules.FTEID{TEID: 200, IP: pgwIP}
	outerAccess := rules.FTEID{TEID: 400, IP: enbIP}
	return rules.Session{
		CPSEID: 1, UPSEID: 2,
		PDRs: map[uint16]rules.PDR{
			1: {ID: 1, SourceInterface: rules.SourceAccess, LocalFTEID: rules.FTEID{TEID: 100, IP: accessLocalIP}, FARID: 1, QERIDs: []uint32{1}, URRIDs: []uint32{1}},
			2: {ID: 2, SourceInterface: rules.SourceCore, LocalFTEID: rules.FTEID{TEID: 300, IP: coreLocalIP}, FARID: 2, QERIDs: []uint32{1}, URRIDs: []uint32{1}},
		},
		FARs: map[uint32]rules.FAR{
			1: {ID: 1, ApplyAction: rules.ActionForward, DestinationInterface: rules.DestinationCore, OuterHeader: &outerCore},
			2: {ID: 2, ApplyAction: rules.ActionForward, DestinationInterface: rules.DestinationAccess, OuterHeader: &outerAccess},
		},
		QERs: map[uint32]rules.QER{1: {
			ID: 1, UplinkGateOpen: true, DownlinkGateOpen: true, QCI: 9, ARP: 8,
		}},
		URRs: map[uint32]rules.URR{1: {
			ID: 1, MeasureVolume: true, ReportingThreshold: 1 << 40,
		}},
	}
}

func newTrafficPlan(direction string, source, receiver *packetEndpoint, sourceMAC, targetMAC net.HardwareAddr, sourceIP, targetIP netip.Addr, inputTEID, outputTEID uint32) *trafficPlan {
	value := &trafficPlan{
		direction: direction, source: source, receiver: receiver,
		sourceIP: sourceIP, targetIP: targetIP, inputTEID: inputTEID, outputTEID: outputTEID,
		runID: randomUint64(),
	}
	copy(value.sourceMAC[:], sourceMAC)
	copy(value.targetMAC[:], targetMAC)
	return value
}

func (p *trafficPlan) send(ctx context.Context, cfg config, worker int, startAt, endAt time.Time) {
	packet := p.packet(cfg.innerSize)
	address := &unix.SockaddrLinklayer{Ifindex: p.source.ifindex, Protocol: hostToNetwork16(unix.ETH_P_IP), Halen: 6}
	copy(address.Addr[:], p.targetMAC[:])
	waitUntil(ctx, startAt)
	var interval time.Duration
	if cfg.targetPPS > 0 {
		rate := cfg.targetPPS / cfg.workers
		if worker < cfg.targetPPS%cfg.workers {
			rate++
		}
		if rate == 0 {
			return
		}
		interval = time.Second / time.Duration(rate)
	}
	next := startAt
	for time.Now().Before(endAt) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		sequence := p.sequence.Add(1)
		payload := packet[ethernetBytes+ipv4Bytes+udpBytes+gtpuBytes:]
		binary.BigEndian.PutUint64(payload[8:16], sequence)
		if sequence&255 == 0 {
			binary.BigEndian.PutUint64(payload[16:24], uint64(time.Now().UnixNano()))
		} else {
			binary.BigEndian.PutUint64(payload[16:24], 0)
		}
		if err := unix.Sendto(p.source.sendFD, packet, unix.MSG_DONTWAIT, address); err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.ENOBUFS) {
				p.writeErrors.Add(1)
				continue
			}
			p.writeErrors.Add(1)
			return
		}
		p.sent.Add(1)
		if interval > 0 {
			next = next.Add(interval)
			waitUntil(ctx, next)
		}
	}
}

func (p *trafficPlan) receive(ctx context.Context, receiveFD int) {
	batch := newReceiveBatch(64, 2048)
	for {
		n, err := batch.read(receiveFD)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			return
		}
		for index := 0; index < n; index++ {
			p.recordReceived(batch.buffers[index][:batch.messages[index].length])
		}
	}
}

func (p *trafficPlan) recordReceived(buffer []byte) {
	if len(buffer) < ethernetBytes+ipv4Bytes+udpBytes+gtpuBytes+metadataBytes {
		return
	}
	if binary.BigEndian.Uint16(buffer[12:14]) != unix.ETH_P_IP || buffer[23] != 17 ||
		binary.BigEndian.Uint16(buffer[36:38]) != gtpuPort || buffer[43] != 255 ||
		binary.BigEndian.Uint32(buffer[46:50]) != p.outputTEID {
		return
	}
	payload := buffer[50:]
	if binary.BigEndian.Uint64(payload[0:8]) != p.runID {
		return
	}
	p.received.Add(1)
	p.histogram.record(binary.BigEndian.Uint64(payload[16:24]))
}

func newReceiveBatch(size, packetBytes int) *receiveBatch {
	value := &receiveBatch{
		buffers: make([][]byte, size), iovecs: make([]unix.Iovec, size),
		messages: make([]multiMessageHeader, size),
	}
	for index := range value.buffers {
		value.buffers[index] = make([]byte, packetBytes)
		value.iovecs[index] = unix.Iovec{Base: &value.buffers[index][0], Len: uint64(packetBytes)}
		value.messages[index].header.Iov = &value.iovecs[index]
		value.messages[index].header.Iovlen = 1
	}
	return value
}

func (b *receiveBatch) read(fd int) (int, error) {
	for index := range b.messages {
		b.messages[index].length = 0
		b.messages[index].header.Flags = 0
	}
	received, _, errno := unix.Syscall6(
		unix.SYS_RECVMMSG, uintptr(fd), uintptr(unsafe.Pointer(&b.messages[0])),
		uintptr(len(b.messages)), uintptr(unix.MSG_WAITFORONE), 0, 0,
	)
	runtime.KeepAlive(b)
	if errno != 0 {
		return 0, errno
	}
	return int(received), nil
}

func (p *trafficPlan) packet(innerSize int) []byte {
	packet := make([]byte, ethernetBytes+ipv4Bytes+udpBytes+gtpuBytes+innerSize)
	copy(packet[0:6], p.targetMAC[:])
	copy(packet[6:12], p.sourceMAC[:])
	binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IP)
	ip := packet[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipv4Bytes+udpBytes+gtpuBytes+innerSize))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], p.sourceIP.AsSlice())
	copy(ip[16:20], p.targetIP.AsSlice())
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	udp := packet[34:]
	binary.BigEndian.PutUint16(udp[0:2], 31_000)
	binary.BigEndian.PutUint16(udp[2:4], gtpuPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpBytes+gtpuBytes+innerSize))
	gtp := packet[42:]
	gtp[0] = 0x30
	gtp[1] = 255
	binary.BigEndian.PutUint16(gtp[2:4], uint16(innerSize))
	binary.BigEndian.PutUint32(gtp[4:8], p.inputTEID)
	payload := packet[50:]
	binary.BigEndian.PutUint64(payload[0:8], p.runID)
	return packet
}

func warmup(plan *trafficPlan, innerSize int) error {
	packet := plan.packet(innerSize)
	payload := packet[50:]
	binary.BigEndian.PutUint64(payload[8:16], 1)
	binary.BigEndian.PutUint64(payload[16:24], uint64(time.Now().UnixNano()))
	address := &unix.SockaddrLinklayer{Ifindex: plan.source.ifindex, Protocol: hostToNetwork16(unix.ETH_P_IP), Halen: 6}
	copy(address.Addr[:], plan.targetMAC[:])
	if err := unix.Sendto(plan.source.sendFD, packet, 0, address); err != nil {
		return err
	}
	deadline := time.Now().Add(time.Second)
	buffer := make([]byte, 65_535)
	for time.Now().Before(deadline) {
		fds := make([]unix.PollFd, len(plan.receiver.receivers))
		for index, fd := range plan.receiver.receivers {
			fds[index] = unix.PollFd{Fd: int32(fd), Events: unix.POLLIN}
		}
		if _, err := unix.Poll(fds, 100); err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		for index, poll := range fds {
			if poll.Revents&unix.POLLIN == 0 {
				continue
			}
			n, _, err := unix.Recvfrom(plan.receiver.receivers[index], buffer, unix.MSG_DONTWAIT)
			if err != nil {
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
					continue
				}
				return err
			}
			if n >= 50+metadataBytes && binary.BigEndian.Uint32(buffer[46:50]) == plan.outputTEID && binary.BigEndian.Uint64(buffer[50:58]) == plan.runID {
				return nil
			}
		}
	}
	return errors.New("timed out waiting for rewritten packet")
}

func openPacketEndpoint(device *net.Interface, bufferBytes, receiverWorkers int) (*packetEndpoint, error) {
	sendFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	endpoint := &packetEndpoint{sendFD: sendFD, ifindex: device.Index}
	closeOnError := func(cause error) (*packetEndpoint, error) {
		endpoint.close()
		return nil, cause
	}
	if err := unix.SetsockoptInt(sendFD, unix.SOL_SOCKET, unix.SO_SNDBUF, bufferBytes); err != nil {
		return closeOnError(err)
	}
	group := device.Index & 0xffff
	for worker := 0; worker < receiverWorkers; worker++ {
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(hostToNetwork16(unix.ETH_P_ALL)))
		if err != nil {
			return closeOnError(err)
		}
		endpoint.receivers = append(endpoint.receivers, fd)
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, bufferBytes); err != nil {
			return closeOnError(err)
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1); err != nil {
			return closeOnError(err)
		}
		timeout := unix.NsecToTimeval((100 * time.Millisecond).Nanoseconds())
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
			return closeOnError(err)
		}
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: hostToNetwork16(unix.ETH_P_ALL), Ifindex: device.Index}); err != nil {
			return closeOnError(err)
		}
		fanout := group | unix.PACKET_FANOUT_CPU<<16
		if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_FANOUT, fanout); err != nil {
			return closeOnError(err)
		}
	}
	return endpoint, nil
}

func (s *packetEndpoint) close() {
	if s.sendFD >= 0 {
		_ = unix.Close(s.sendFD)
		s.sendFD = -1
	}
	for _, fd := range s.receivers {
		_ = unix.Close(fd)
	}
	s.receivers = nil
}

func (s *packetEndpoint) statistics() (uint32, uint32) {
	var packets, drops uint32
	for _, fd := range s.receivers {
		value, err := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
		if err == nil {
			packets += value.Packets
			drops += value.Drops
		}
	}
	return packets, drops
}

func (p *trafficPlan) summarize(cfg config, socketDrops uint64) streamResult {
	sent := p.sent.Load()
	received := p.received.Load()
	lost := uint64(0)
	if sent > received {
		lost = sent - received
	}
	durationSeconds := cfg.duration.Seconds()
	lossPercent := float64(0)
	if sent != 0 {
		lossPercent = float64(lost) / float64(sent) * 100
	}
	return streamResult{
		Direction: p.direction, InnerPacketBytes: cfg.innerSize, Workers: cfg.workers, ReceiverWorkers: cfg.receiverWorkers,
		TargetPacketsPerSecond: cfg.targetPPS, DurationMilliseconds: float64(cfg.duration.Microseconds()) / 1000,
		SentPackets: sent, ReceivedPackets: received, ReceiverSocketDroppedPackets: socketDrops,
		LostPackets: lost, LossPercent: lossPercent,
		SentPacketsPerSecond: float64(sent) / durationSeconds, ReceivedPacketsPerSecond: float64(received) / durationSeconds,
		OfferedMbps:            float64(sent*uint64(cfg.innerSize)*8) / durationSeconds / 1_000_000,
		ReceivedMbps:           float64(received*uint64(cfg.innerSize)*8) / durationSeconds / 1_000_000,
		LatencySamples:         p.histogram.samples.Load(),
		P50LatencyMilliseconds: p.histogram.quantile(0.50), P95LatencyMilliseconds: p.histogram.quantile(0.95), P99LatencyMilliseconds: p.histogram.quantile(0.99),
	}
}

func (h *latencyHistogram) record(sentAt uint64) {
	if sentAt == 0 {
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

func validateEnvironment(cfg config) error {
	if os.Getenv(guardEnvironment) != "1" {
		return fmt.Errorf("sgwu-ebpf-bench refuses to run unless %s=1", guardEnvironment)
	}
	if os.Geteuid() != 0 {
		return errors.New("sgwu-ebpf-bench requires root inside a disposable network namespace")
	}
	selfNS, selfErr := os.Readlink("/proc/self/ns/net")
	initNS, initErr := os.Readlink("/proc/1/ns/net")
	if selfErr == nil && initErr == nil && selfNS == initNS {
		return errors.New("sgwu-ebpf-bench refuses to run in the initial network namespace")
	}
	if cfg.direction != "uplink" && cfg.direction != "downlink" && cfg.direction != "both" {
		return errors.New("direction must be uplink, downlink, or both")
	}
	if cfg.duration < 100*time.Millisecond || cfg.duration > time.Minute {
		return errors.New("duration must be between 100ms and 1m")
	}
	if cfg.innerSize < metadataBytes || cfg.innerSize > 1400 {
		return fmt.Errorf("inner-packet-bytes must be between %d and 1400", metadataBytes)
	}
	if cfg.targetPPS < 0 || cfg.targetPPS > 10_000_000 {
		return errors.New("target-pps must be between 0 and 10000000")
	}
	if cfg.workers < 1 || cfg.workers > 128 {
		return errors.New("workers must be between 1 and 128")
	}
	if cfg.receiverWorkers < 1 || cfg.receiverWorkers > 64 {
		return errors.New("receiver-workers must be between 1 and 64")
	}
	if cfg.socketBuffer < 64*1024 || cfg.socketBuffer > 1<<30 {
		return errors.New("socket-buffer-bytes must be between 65536 and 1073741824")
	}
	return nil
}

func waitUntil(ctx context.Context, deadline time.Time) {
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		if remaining > 100*time.Microsecond {
			timer := time.NewTimer(remaining - 50*time.Microsecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			}
		} else {
			runtime.Gosched()
		}
	}
}

func checksum(value []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(value); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(value[index : index+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func hostToNetwork16(value uint16) uint16 { return value<<8 | value>>8 }

func randomUint64() uint64 {
	var value [8]byte
	if _, err := rand.Read(value[:]); err == nil {
		return binary.BigEndian.Uint64(value[:])
	}
	return uint64(time.Now().UnixNano())
}

func subtractCounters(current, baseline dataplane.FastPathCounters) dataplane.FastPathCounters {
	return dataplane.FastPathCounters{
		AccessPackets:      current.AccessPackets - baseline.AccessPackets,
		CorePackets:        current.CorePackets - baseline.CorePackets,
		ForwardedPackets:   current.ForwardedPackets - baseline.ForwardedPackets,
		ForwardedBytes:     current.ForwardedBytes - baseline.ForwardedBytes,
		UplinkBytes:        current.UplinkBytes - baseline.UplinkBytes,
		DownlinkBytes:      current.DownlinkBytes - baseline.DownlinkBytes,
		DroppedPackets:     current.DroppedPackets - baseline.DroppedPackets,
		UnauthorizedPeers:  current.UnauthorizedPeers - baseline.UnauthorizedPeers,
		FallbackPackets:    current.FallbackPackets - baseline.FallbackPackets,
		RewriteErrors:      current.RewriteErrors - baseline.RewriteErrors,
		SyncFailures:       current.SyncFailures - baseline.SyncFailures,
		P95LatencyMicros:   current.P95LatencyMicros,
		URRMeteredPackets:  current.URRMeteredPackets - baseline.URRMeteredPackets,
		URRMeteredBytes:    current.URRMeteredBytes - baseline.URRMeteredBytes,
		URRThresholdEvents: current.URRThresholdEvents - baseline.URRThresholdEvents,
		URRActiveMeters:    current.URRActiveMeters,
	}
}
