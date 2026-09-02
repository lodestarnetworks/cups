//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	ethernetBytes       = 14
	outerIPv4Bytes      = 20
	udpBytes            = 8
	gtpuBytes           = 8
	innerIPv4Bytes      = 20
	innerUDPBytes       = 8
	metadataBytes       = 32
	gtpuPort            = 2152
	receiveBatchSize    = 64
	maximumEthernetSize = ethernetBytes + outerIPv4Bytes + udpBytes + gtpuBytes + maximumInnerSize
	latencySampleMask   = 1023
	wireDrainAllowance  = 250 * time.Millisecond
)

const (
	directionUplink     byte = 1
	directionDownlink   byte = 2
	streamUplinkVoice   byte = 3
	streamDownlinkVoice byte = 4
)

var latencyUpperBounds = [...]time.Duration{
	5 * time.Microsecond, 10 * time.Microsecond, 15 * time.Microsecond,
	20 * time.Microsecond, 30 * time.Microsecond, 40 * time.Microsecond,
	50 * time.Microsecond, 75 * time.Microsecond, 100 * time.Microsecond,
	150 * time.Microsecond, 200 * time.Microsecond, 300 * time.Microsecond,
	500 * time.Microsecond, 750 * time.Microsecond, time.Millisecond,
	2 * time.Millisecond, 3 * time.Millisecond, 5 * time.Millisecond,
	7_500 * time.Microsecond, 10 * time.Millisecond, 20 * time.Millisecond,
	50 * time.Millisecond, 100 * time.Millisecond,
}

type generatorResult struct {
	Scope                  string            `json:"scope"`
	CUPSChain              bool              `json:"cupsChain"`
	DedicatedBearer        bool              `json:"dedicatedBearer"`
	MixedBearers           bool              `json:"mixedBearers"`
	Direction              string            `json:"direction"`
	InstalledSessions      int               `json:"installedSessions"`
	ActiveSessions         int               `json:"activeSessions"`
	InnerPacketBytes       int               `json:"innerPacketBytes"`
	VoicePacketBytes       int               `json:"voicePacketBytes,omitempty"`
	VoicePacketsPerSecond  int               `json:"voicePacketsPerSecond,omitempty"`
	AFPacketFrameBytes     int               `json:"afPacketFrameBytes,omitempty"`
	EthernetVLANFCSBytes   int               `json:"ethernetVlanFcsBytes,omitempty"`
	PhysicalWireBytes      int               `json:"physicalWireBytesIncludingPreambleAndIfg,omitempty"`
	Streams                []streamResult    `json:"streams"`
	ReceiverSocketPackets  uint64            `json:"receiverSocketPackets"`
	ReceiverSocketDrops    uint64            `json:"receiverSocketDrops"`
	IgnoredPackets         uint64            `json:"ignoredPackets"`
	ValidationErrors       uint64            `json:"validationErrors"`
	ValidationErrorReasons map[string]uint64 `json:"validationErrorReasons,omitempty"`
	ProcessCPUPercent      float64           `json:"processCpuPercent"`
	GoMaxProcs             int               `json:"goMaxProcs"`
	GoHeapBytes            uint64            `json:"goHeapBytes"`
	GoHeapObjects          uint64            `json:"goHeapObjects"`
	GoGCCount              uint32            `json:"goGcCount"`
	CPUAffinity            string            `json:"cpuAffinity,omitempty"`
}

type headroomResult struct {
	Scope                      string  `json:"scope"`
	ActiveSessions             int     `json:"activeSessions"`
	InnerPacketBytes           int     `json:"innerPacketBytes"`
	Workers                    int     `json:"workers"`
	DurationMilliseconds       float64 `json:"durationMilliseconds"`
	SentPackets                uint64  `json:"sentPackets"`
	SendErrors                 uint64  `json:"sendErrors"`
	SentPacketsPerSecond       float64 `json:"sentPacketsPerSecond"`
	EquivalentSubscriberMbps   float64 `json:"equivalentSubscriberMbps"`
	EquivalentPhysicalWireMbps float64 `json:"equivalentPhysicalWireMbps"`
	ProcessCPUPercent          float64 `json:"processCpuPercent"`
	GoMaxProcs                 int     `json:"goMaxProcs"`
	CPUAffinity                string  `json:"cpuAffinity,omitempty"`
}

type streamResult struct {
	Direction                      string  `json:"direction"`
	TrafficClass                   string  `json:"trafficClass"`
	Bearer                         string  `json:"bearer"`
	InnerPacketBytes               int     `json:"innerPacketBytes"`
	OfferedEncapsulation           string  `json:"offeredEncapsulation"`
	ReceivedEncapsulation          string  `json:"receivedEncapsulation"`
	OfferedAFPacketFrameBytes      int     `json:"offeredAfPacketFrameBytes"`
	ReceivedAFPacketFrameBytes     int     `json:"receivedAfPacketFrameBytes"`
	OfferedPhysicalBytesPerPacket  int     `json:"offeredPhysicalWireBytesPerPacket"`
	ReceivedPhysicalBytesPerPacket int     `json:"receivedPhysicalWireBytesPerPacket"`
	TargetPacketsPerSecond         int     `json:"targetPacketsPerSecond"`
	Workers                        int     `json:"workers"`
	DurationMilliseconds           float64 `json:"durationMilliseconds"`
	SentPackets                    uint64  `json:"sentPackets"`
	ReceivedPackets                uint64  `json:"receivedPackets"`
	LostPackets                    uint64  `json:"lostPackets"`
	DuplicateOrReordered           uint64  `json:"duplicateOrReorderedPackets"`
	SendErrors                     uint64  `json:"sendErrors"`
	LossPercent                    float64 `json:"lossPercent"`
	SentPacketsPerSecond           float64 `json:"sentPacketsPerSecond"`
	ReceivedPacketsPerSecond       float64 `json:"receivedPacketsPerSecond"`
	OfferedSubscriberMbps          float64 `json:"offeredSubscriberMbps"`
	ReceivedSubscriberMbps         float64 `json:"receivedSubscriberMbps"`
	OfferedPhysicalWireMbps        float64 `json:"offeredPhysicalWireMbps"`
	ReceivedPhysicalWireMbps       float64 `json:"receivedPhysicalWireMbps"`
	LatencySamples                 uint64  `json:"latencySamples"`
	P50LatencyMilliseconds         float64 `json:"p50LatencyMilliseconds"`
	P95LatencyMilliseconds         float64 `json:"p95LatencyMilliseconds"`
	P99LatencyMilliseconds         float64 `json:"p99LatencyMilliseconds"`
	P999LatencyMilliseconds        float64 `json:"p999LatencyMilliseconds"`
	MaximumLatencyMilliseconds     float64 `json:"maximumLatencyMilliseconds"`
}

type packetEndpoint struct {
	sendFD    int
	ifindex   int
	receivers []int
}

type trafficPlan struct {
	direction        string
	directionID      byte
	networkDirection byte
	cupsChain        bool
	dedicatedBearer  bool
	voiceTraffic     bool
	trafficClass     string
	innerPacketBytes int
	targetPPS        int
	runID            uint64
	targetMAC        [6]byte
	sourceMAC        [6]byte
	expectedMAC      [6]byte
	activeFlows      int
	sent             atomic.Uint64
	received         atomic.Uint64
	duplicates       atomic.Uint64
	sendErrors       atomic.Uint64
	lastSequence     []atomic.Uint64
	latency          latencyHistogram
}

type latencyHistogram struct {
	samples atomic.Uint64
	maximum atomic.Uint64
	buckets [len(latencyUpperBounds) + 1]atomic.Uint64
}

type receiverState struct {
	plans             map[byte]*trafficPlan
	generatorMAC      [6]byte
	ignored           atomic.Uint64
	validationErrors  atomic.Uint64
	validationReasons [validationReasonCount]atomic.Uint64
}

type validationReason uint8

const (
	validationOK validationReason = iota
	validationEncapsulation
	validationMetadata
	validationEthernet
	validationGTPHeader
	validationOuterSource
	validationOuterDestination
	validationDefaultBearerTEID
	validationWrongQCI1SessionTEID
	validationTEID
	validationInnerIPv4
	validationReasonCount
)

var validationReasonNames = [...]string{
	validationEncapsulation:        "encapsulation",
	validationMetadata:             "metadata",
	validationEthernet:             "ethernet",
	validationGTPHeader:            "gtp_header",
	validationOuterSource:          "outer_source",
	validationOuterDestination:     "outer_destination",
	validationDefaultBearerTEID:    "default_bearer_teid",
	validationWrongQCI1SessionTEID: "wrong_qci1_session_teid",
	validationTEID:                 "teid",
	validationInnerIPv4:            "inner_ipv4",
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

type processUsage struct {
	user   time.Duration
	system time.Duration
}

func runGenerator(cfg options) (generatorResult, error) {
	if cfg.activeSessions == 0 {
		cfg.activeSessions = cfg.sessions
	}
	device, err := net.InterfaceByName(cfg.generatorInterface)
	if err != nil {
		return generatorResult{}, err
	}
	if device.Flags&net.FlagUp == 0 {
		return generatorResult{}, fmt.Errorf("generator interface %s is down", device.Name)
	}
	if !hardwareAddressEqual(device.HardwareAddr, cfg.generatorMAC) {
		return generatorResult{}, fmt.Errorf("generator interface MAC is %s, expected %s", device.HardwareAddr, cfg.generatorMAC)
	}
	endpoint, err := openPacketEndpoint(device, cfg.socketBufferBytes, cfg.receiverWorkers)
	if err != nil {
		return generatorResult{}, err
	}
	defer endpoint.close()

	plans := make([]*trafficPlan, 0, 4)
	if cfg.cupsChain {
		if cfg.direction == "uplink" || cfg.direction == "both" {
			data := newTrafficPlan("uplink", directionUplink, cfg.activeSessions, cfg.generatorMAC, cfg.accessMAC, cfg.sgiMAC, true)
			if cfg.mixedBearers {
				plans = append(plans,
					configureTrafficPlan(data, directionUplink, cfg.innerPacketBytes, cfg.targetPPS, "bulk-data", false, false),
					configureTrafficPlan(newTrafficPlan("uplink", streamUplinkVoice, cfg.activeSessions, cfg.generatorMAC, cfg.accessMAC, cfg.sgiMAC, true), directionUplink, cfg.voicePacketBytes, cfg.voicePPS, "qci1-voice", true, true),
				)
			} else {
				class := "bulk-data"
				if cfg.dedicatedBearer {
					class = "qci1-load"
				}
				plans = append(plans, configureTrafficPlan(data, directionUplink, cfg.innerPacketBytes, cfg.targetPPS, class, cfg.dedicatedBearer, false))
			}
		}
		if cfg.direction == "downlink" || cfg.direction == "both" {
			data := newTrafficPlan("downlink", directionDownlink, cfg.activeSessions, cfg.generatorMAC, cfg.sgiMAC, cfg.accessMAC, true)
			if cfg.mixedBearers {
				plans = append(plans,
					configureTrafficPlan(data, directionDownlink, cfg.innerPacketBytes, cfg.targetPPS, "bulk-data", false, false),
					configureTrafficPlan(newTrafficPlan("downlink", streamDownlinkVoice, cfg.activeSessions, cfg.generatorMAC, cfg.sgiMAC, cfg.accessMAC, true), directionDownlink, cfg.voicePacketBytes, cfg.voicePPS, "qci1-voice", true, true),
				)
			} else {
				class := "bulk-data"
				if cfg.dedicatedBearer {
					class = "qci1-load"
				}
				plans = append(plans, configureTrafficPlan(data, directionDownlink, cfg.innerPacketBytes, cfg.targetPPS, class, cfg.dedicatedBearer, false))
			}
		}
	} else {
		if cfg.direction == "uplink" || cfg.direction == "both" {
			plans = append(plans, configureTrafficPlan(newTrafficPlan("uplink", directionUplink, cfg.activeSessions, cfg.generatorMAC, cfg.accessMAC, cfg.coreMAC, false), directionUplink, cfg.innerPacketBytes, cfg.targetPPS, "bulk-data", false, false))
		}
		if cfg.direction == "downlink" || cfg.direction == "both" {
			plans = append(plans, configureTrafficPlan(newTrafficPlan("downlink", directionDownlink, cfg.activeSessions, cfg.generatorMAC, cfg.coreMAC, cfg.accessMAC, false), directionDownlink, cfg.innerPacketBytes, cfg.targetPPS, "bulk-data", false, false))
		}
	}
	for _, plan := range plans {
		if err := preflight(endpoint, cfg, plan); err != nil {
			return generatorResult{}, fmt.Errorf("%s preflight: %w", plan.direction, err)
		}
	}
	_, _ = endpoint.statistics()

	state := &receiverState{plans: make(map[byte]*trafficPlan, len(plans))}
	copy(state.generatorMAC[:], cfg.generatorMAC)
	for _, plan := range plans {
		state.plans[plan.directionID] = plan
	}
	ctx, cancel := context.WithCancel(context.Background())
	var receiverWait sync.WaitGroup
	for _, receiveFD := range endpoint.receivers {
		receiverWait.Add(1)
		go func(fd int) {
			defer receiverWait.Done()
			receivePackets(ctx, fd, state)
		}(receiveFD)
	}

	usageBefore := readProcessUsage()
	startAt := time.Now().Add(500 * time.Millisecond)
	endAt := startAt.Add(cfg.duration)
	var senderWait sync.WaitGroup
	for _, plan := range plans {
		for worker := 0; worker < cfg.workers; worker++ {
			senderWait.Add(1)
			go func(current *trafficPlan, workerID int) {
				defer senderWait.Done()
				current.sendWorker(ctx, endpoint, cfg, workerID, startAt, endAt)
			}(plan, worker)
		}
	}
	senderWait.Wait()
	usageAfter := readProcessUsage()
	time.Sleep(cfg.drain + wireDrainAllowance)
	cancel()
	receiverWait.Wait()
	socketPackets, socketDrops := endpoint.statistics()

	streams := make([]streamResult, 0, len(plans))
	for _, plan := range plans {
		streams = append(streams, plan.summarize(cfg))
	}
	sort.Slice(streams, func(i, j int) bool {
		if streams[i].Direction == streams[j].Direction {
			return streams[i].TrafficClass < streams[j].TrafficClass
		}
		return streams[i].Direction < streams[j].Direction
	})
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	processSeconds := (usageAfter.user - usageBefore.user + usageAfter.system - usageBefore.system).Seconds()
	wallSeconds := cfg.duration.Seconds()
	result := generatorResult{
		Scope:           "two-host physical-wire SGW-U generator and independent packet validator",
		CUPSChain:       cfg.cupsChain,
		DedicatedBearer: cfg.dedicatedBearer,
		MixedBearers:    cfg.mixedBearers,
		Direction:       cfg.direction, InstalledSessions: cfg.sessions,
		ActiveSessions: cfg.activeSessions, InnerPacketBytes: cfg.innerPacketBytes,
		Streams: streams, ReceiverSocketPackets: socketPackets,
		ReceiverSocketDrops: socketDrops, IgnoredPackets: state.ignored.Load(),
		ValidationErrors:       state.validationErrors.Load(),
		ValidationErrorReasons: state.validationReasonSnapshot(),
		ProcessCPUPercent:      processSeconds / wallSeconds * 100,
		GoMaxProcs:             runtime.GOMAXPROCS(0), GoHeapBytes: memory.HeapAlloc,
		GoHeapObjects: memory.HeapObjects, GoGCCount: memory.NumGC,
		CPUAffinity: os.Getenv("BENCH_CPU_LIST"),
	}
	if cfg.mixedBearers {
		result.VoicePacketBytes = cfg.voicePacketBytes
		result.VoicePacketsPerSecond = cfg.voicePPS
	}
	if cfg.cupsChain {
		result.Scope = "two-host physical-wire SGW-U TCX to PGW-U kernel-GTP generator and independent validator"
	} else {
		result.AFPacketFrameBytes = gtpFrameBytes(cfg.innerPacketBytes)
		result.EthernetVLANFCSBytes = gtpFrameBytes(cfg.innerPacketBytes) + 8
		result.PhysicalWireBytes = physicalWireBytes(gtpFrameBytes(cfg.innerPacketBytes))
	}
	return result, nil
}

func runHeadroom(cfg options) (headroomResult, error) {
	if cfg.activeSessions == 0 {
		cfg.activeSessions = cfg.sessions
	}
	device, err := net.InterfaceByName(cfg.generatorInterface)
	if err != nil {
		return headroomResult{}, err
	}
	if device.Flags&net.FlagUp == 0 {
		return headroomResult{}, fmt.Errorf("headroom interface %s is down", device.Name)
	}
	if !hardwareAddressEqual(device.HardwareAddr, cfg.generatorMAC) {
		return headroomResult{}, fmt.Errorf("headroom interface MAC is %s, expected %s", device.HardwareAddr, cfg.generatorMAC)
	}
	endpoint, err := openSendEndpoint(device, cfg.socketBufferBytes)
	if err != nil {
		return headroomResult{}, err
	}
	defer endpoint.close()
	plan := configureTrafficPlan(newTrafficPlan("headroom", directionUplink, cfg.activeSessions, cfg.generatorMAC, cfg.accessMAC, cfg.coreMAC, false), directionUplink, cfg.innerPacketBytes, cfg.targetPPS, "bulk-data", false, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startAt := time.Now().Add(500 * time.Millisecond)
	endAt := startAt.Add(cfg.duration)
	usageBefore := readProcessUsage()
	var senderWait sync.WaitGroup
	for worker := 0; worker < cfg.workers; worker++ {
		senderWait.Add(1)
		go func(workerID int) {
			defer senderWait.Done()
			plan.sendWorker(ctx, endpoint, cfg, workerID, startAt, endAt)
		}(worker)
	}
	senderWait.Wait()
	usageAfter := readProcessUsage()
	sent := plan.sent.Load()
	durationSeconds := cfg.duration.Seconds()
	wireBytes := uint64(ethernetBytes + 4 + outerIPv4Bytes + udpBytes + gtpuBytes + cfg.innerPacketBytes + 4 + 8 + 12)
	processSeconds := (usageAfter.user - usageBefore.user + usageAfter.system - usageBefore.system).Seconds()
	return headroomResult{
		Scope:          "same-generator unpaced AF_PACKET transmit into an isolated local veth null sink",
		ActiveSessions: cfg.activeSessions, InnerPacketBytes: cfg.innerPacketBytes,
		Workers: cfg.workers, DurationMilliseconds: float64(cfg.duration.Microseconds()) / 1000,
		SentPackets: sent, SendErrors: plan.sendErrors.Load(),
		SentPacketsPerSecond:       float64(sent) / durationSeconds,
		EquivalentSubscriberMbps:   float64(sent*uint64(cfg.innerPacketBytes)*8) / durationSeconds / 1_000_000,
		EquivalentPhysicalWireMbps: float64(sent*wireBytes*8) / durationSeconds / 1_000_000,
		ProcessCPUPercent:          processSeconds / durationSeconds * 100,
		GoMaxProcs:                 runtime.GOMAXPROCS(0), CPUAffinity: os.Getenv("BENCH_CPU_LIST"),
	}, nil
}

func newTrafficPlan(direction string, directionID byte, activeFlows int, sourceMAC, targetMAC, expectedMAC net.HardwareAddr, cupsChain bool) *trafficPlan {
	value := &trafficPlan{
		direction: direction, directionID: directionID, runID: randomUint64(),
		networkDirection: directionID, cupsChain: cupsChain, activeFlows: activeFlows,
		lastSequence: make([]atomic.Uint64, activeFlows),
	}
	copy(value.sourceMAC[:], sourceMAC)
	copy(value.targetMAC[:], targetMAC)
	copy(value.expectedMAC[:], expectedMAC)
	return value
}

func configureTrafficPlan(plan *trafficPlan, networkDirection byte, innerPacketBytes, targetPPS int, trafficClass string, dedicatedBearer, voiceTraffic bool) *trafficPlan {
	plan.networkDirection = networkDirection
	plan.innerPacketBytes = innerPacketBytes
	plan.targetPPS = targetPPS
	plan.trafficClass = trafficClass
	plan.dedicatedBearer = dedicatedBearer
	plan.voiceTraffic = voiceTraffic
	return plan
}

func (p *trafficPlan) sendWorker(ctx context.Context, endpoint *packetEndpoint, cfg options, worker int, startAt, endAt time.Time) {
	flows := workerFlows(p.activeFlows, cfg.workers, worker)
	if len(flows) == 0 {
		return
	}
	packets := make([][]byte, len(flows))
	sequences := make([]uint64, len(flows))
	for index, flow := range flows {
		packets[index] = buildPacket(p.innerPacketBytes, p, flow, worker)
	}
	address := &unix.SockaddrLinklayer{Ifindex: endpoint.ifindex, Protocol: hostToNetwork16(unix.ETH_P_IP), Halen: 6}
	copy(address.Addr[:], p.targetMAC[:])
	waitUntil(ctx, startAt)
	workerRate := workerTargetRate(p.targetPPS, cfg.workers, worker)
	if p.targetPPS > 0 && workerRate == 0 {
		return
	}
	var localSent uint64
	flowCursor := 0
	for {
		now := time.Now()
		if !now.Before(endAt) {
			return
		}
		burst := 64
		if p.targetPPS > 0 {
			expected := uint64(now.Sub(startAt).Nanoseconds()) * uint64(workerRate) / uint64(time.Second)
			if localSent >= expected {
				waitUntil(ctx, now.Add(25*time.Microsecond))
				continue
			}
			behind := expected - localSent
			if behind < uint64(burst) {
				burst = int(behind)
			}
		}
		for count := 0; count < burst; count++ {
			packetIndex := flowCursor
			flowCursor++
			if flowCursor == len(flows) {
				flowCursor = 0
			}
			sequences[packetIndex]++
			sequence := sequences[packetIndex]
			packet := packets[packetIndex]
			metadata := packet[p.sendMetadataOffset():]
			binary.BigEndian.PutUint64(metadata[8:16], sequence)
			if localSent&latencySampleMask == 0 {
				binary.BigEndian.PutUint64(metadata[16:24], uint64(time.Now().UnixNano()))
			} else {
				binary.BigEndian.PutUint64(metadata[16:24], 0)
			}
			if err := unix.Sendto(endpoint.sendFD, packet, unix.MSG_DONTWAIT, address); err != nil {
				p.sendErrors.Add(1)
				if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.ENOBUFS) && !errors.Is(err, unix.EINTR) {
					return
				}
				continue
			}
			p.sent.Add(1)
			localSent++
		}
	}
}

func workerFlows(active, workers, worker int) []int {
	result := make([]int, 0, (active+workers-1)/workers)
	for flow := worker; flow < active; flow += workers {
		result = append(result, flow)
	}
	return result
}

func workerTargetRate(target, workers, worker int) int {
	if target == 0 {
		return 0
	}
	value := target / workers
	if worker < target%workers {
		value++
	}
	return value
}

func buildPacket(innerSize int, plan *trafficPlan, flow, worker int) []byte {
	frameBytes := plainFrameBytes(innerSize)
	if plan.sendsGTP() {
		frameBytes = gtpFrameBytes(innerSize)
	}
	packet := make([]byte, frameBytes)
	copy(packet[0:6], plan.targetMAC[:])
	copy(packet[6:12], plan.sourceMAC[:])
	binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IP)

	innerOffset := ethernetBytes
	if plan.sendsGTP() {
		outerIP := packet[ethernetBytes : ethernetBytes+outerIPv4Bytes]
		outerIP[0] = 0x45
		binary.BigEndian.PutUint16(outerIP[2:4], uint16(outerIPv4Bytes+udpBytes+gtpuBytes+innerSize))
		outerIP[8] = 64
		outerIP[9] = 17
		var sourceIP, destinationIP netip.Addr
		var inputTEID uint32
		if plan.networkDirection == directionUplink {
			if plan.cupsChain {
				sourceIP, destinationIP = chainAccessPeerIP(flow), chainSGWUAccessIP
			} else {
				sourceIP, destinationIP = accessPeerIP(flow), dutAccessIP
			}
			inputTEID = accessInputTEID(flow)
			if plan.dedicatedBearer {
				inputTEID = qci1AccessInputTEID(flow)
			}
		} else {
			sourceIP, destinationIP, inputTEID = corePeerIP(flow), dutCoreIP, coreInputTEID(flow)
		}
		copy(outerIP[12:16], sourceIP.AsSlice())
		copy(outerIP[16:20], destinationIP.AsSlice())
		binary.BigEndian.PutUint16(outerIP[10:12], internetChecksum(outerIP))

		udp := packet[ethernetBytes+outerIPv4Bytes:]
		binary.BigEndian.PutUint16(udp[0:2], uint16(30_000+worker%20_000))
		binary.BigEndian.PutUint16(udp[2:4], gtpuPort)
		binary.BigEndian.PutUint16(udp[4:6], uint16(udpBytes+gtpuBytes+innerSize))
		gtp := udp[udpBytes:]
		gtp[0] = 0x30
		gtp[1] = 255
		binary.BigEndian.PutUint16(gtp[2:4], uint16(innerSize))
		binary.BigEndian.PutUint32(gtp[4:8], inputTEID)
		innerOffset = ethernetBytes + outerIPv4Bytes + udpBytes + gtpuBytes
	}

	innerIP := packet[innerOffset:]
	innerIP[0] = 0x45
	binary.BigEndian.PutUint16(innerIP[2:4], uint16(innerSize))
	innerIP[8] = 64
	innerIP[9] = 17
	innerSource, innerDestination := innerPacketEndpoints(plan, flow)
	copy(innerIP[12:16], innerSource.AsSlice())
	copy(innerIP[16:20], innerDestination.AsSlice())
	binary.BigEndian.PutUint16(innerIP[10:12], internetChecksum(innerIP[:innerIPv4Bytes]))
	innerUDP := innerIP[innerIPv4Bytes:]
	localPort, remotePort := uint16(10_000+flow%50_000), uint16(20_000+flow%40_000)
	if plan.voiceTraffic {
		localPort, remotePort = mixedVoiceLocalPort, mixedVoiceRemotePort
	}
	if plan.networkDirection == directionUplink {
		binary.BigEndian.PutUint16(innerUDP[0:2], localPort)
		binary.BigEndian.PutUint16(innerUDP[2:4], remotePort)
	} else {
		binary.BigEndian.PutUint16(innerUDP[0:2], remotePort)
		binary.BigEndian.PutUint16(innerUDP[2:4], localPort)
	}
	binary.BigEndian.PutUint16(innerUDP[4:6], uint16(innerSize-innerIPv4Bytes))
	metadata := packet[plan.sendMetadataOffset():]
	binary.BigEndian.PutUint64(metadata[0:8], plan.runID)
	binary.BigEndian.PutUint32(metadata[24:28], uint32(flow))
	metadata[28] = plan.directionID
	binary.BigEndian.PutUint16(metadata[29:31], uint16(worker))
	metadata[31] = 0xa7
	return packet
}

func receivePackets(ctx context.Context, fd int, state *receiverState) {
	batch := newReceiveBatch(receiveBatchSize, maximumEthernetSize+64)
	for {
		n, err := batch.read(fd)
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
			state.record(batch.buffers[index][:batch.messages[index].length])
		}
	}
}

func (s *receiverState) record(packet []byte) {
	if len(packet) < ethernetBytes {
		s.ignored.Add(1)
		return
	}
	if !hardwareAddressEqual(packet[0:6], s.generatorMAC[:]) {
		s.ignored.Add(1)
		return
	}
	receivedGTP, offset, ok := receivedPacketLayout(packet)
	if !ok {
		s.ignored.Add(1)
		return
	}
	metadata := packet[offset:]
	directionID := metadata[28]
	plan := s.plans[directionID]
	if plan == nil || binary.BigEndian.Uint64(metadata[0:8]) != plan.runID {
		s.ignored.Add(1)
		return
	}
	if reason := receivedPacketValidation(packet, plan, receivedGTP, offset); reason != validationOK {
		s.validationErrors.Add(1)
		s.validationReasons[reason].Add(1)
		return
	}
	flow := int(binary.BigEndian.Uint32(metadata[24:28]))
	sequence := binary.BigEndian.Uint64(metadata[8:16])
	previous := plan.lastSequence[flow].Swap(sequence)
	if previous != 0 && sequence <= previous {
		plan.duplicates.Add(1)
	}
	plan.received.Add(1)
	plan.latency.record(binary.BigEndian.Uint64(metadata[16:24]))
}

func validateReceivedPacket(packet []byte, plan *trafficPlan) bool {
	receivedGTP, offset, ok := receivedPacketLayout(packet)
	if !ok {
		return false
	}
	return validateReceivedPacketLayout(packet, plan, receivedGTP, offset)
}

func validateReceivedPacketLayout(packet []byte, plan *trafficPlan, receivedGTP bool, metadataPosition int) bool {
	return receivedPacketValidation(packet, plan, receivedGTP, metadataPosition) == validationOK
}

func receivedPacketValidation(packet []byte, plan *trafficPlan, receivedGTP bool, metadataPosition int) validationReason {
	if receivedGTP != plan.receivesGTP() {
		return validationEncapsulation
	}
	metadata := packet[metadataPosition:]
	flow := int(binary.BigEndian.Uint32(metadata[24:28]))
	if flow < 0 || flow >= plan.activeFlows || metadata[31] != 0xa7 {
		return validationMetadata
	}
	if !hardwareAddressEqual(packet[0:6], plan.sourceMAC[:]) ||
		!hardwareAddressEqual(packet[6:12], plan.expectedMAC[:]) {
		return validationEthernet
	}
	if !receivedGTP {
		expectedSource, expectedDestination := innerPacketEndpoints(plan, flow)
		if !validateInnerIPv4(packet[ethernetBytes:], expectedSource, expectedDestination) {
			return validationInnerIPv4
		}
		return validationOK
	}
	udpOffset := ethernetBytes + outerIPv4Bytes
	gtpOffset := udpOffset + udpBytes
	if binary.BigEndian.Uint16(packet[udpOffset:udpOffset+2]) != gtpuPort ||
		binary.BigEndian.Uint16(packet[udpOffset+2:udpOffset+4]) != gtpuPort ||
		packet[gtpOffset] != 0x30 || packet[gtpOffset+1] != 255 {
		return validationGTPHeader
	}
	var expectedSourceIP, expectedDestinationIP netip.Addr
	var expectedTEID uint32
	if plan.networkDirection == directionUplink {
		expectedSourceIP, expectedDestinationIP = dutCoreIP, corePeerIP(flow)
		expectedTEID = coreOutputTEID(flow)
	} else {
		if plan.cupsChain {
			expectedSourceIP, expectedDestinationIP = chainSGWUAccessIP, chainAccessPeerIP(flow)
		} else {
			expectedSourceIP, expectedDestinationIP = dutAccessIP, accessPeerIP(flow)
		}
		expectedTEID = accessOutputTEID(flow)
		if plan.dedicatedBearer {
			expectedTEID = qci1AccessOutputTEID(flow)
		}
	}
	if !bytesEqualIP(packet[ethernetBytes+12:ethernetBytes+16], expectedSourceIP) {
		return validationOuterSource
	}
	if !bytesEqualIP(packet[ethernetBytes+16:ethernetBytes+20], expectedDestinationIP) {
		return validationOuterDestination
	}
	actualTEID := binary.BigEndian.Uint32(packet[gtpOffset+4 : gtpOffset+8])
	if actualTEID != expectedTEID {
		if plan.dedicatedBearer && plan.networkDirection == directionDownlink {
			if actualTEID == accessOutputTEID(flow) {
				return validationDefaultBearerTEID
			}
			if actualTEID >= qci1AccessOutputTEIDBase && actualTEID < qci1AccessOutputTEIDBase+uint32(plan.activeFlows) {
				return validationWrongQCI1SessionTEID
			}
		}
		return validationTEID
	}
	innerOffset := gtpOffset + gtpuBytes
	expectedInnerSource, expectedInnerDestination := innerPacketEndpoints(plan, flow)
	if !validateInnerIPv4(packet[innerOffset:], expectedInnerSource, expectedInnerDestination) {
		return validationInnerIPv4
	}
	return validationOK
}

func (s *receiverState) validationReasonSnapshot() map[string]uint64 {
	result := make(map[string]uint64)
	for reason := validationReason(1); reason < validationReasonCount; reason++ {
		if value := s.validationReasons[reason].Load(); value != 0 {
			result[validationReasonNames[reason]] = value
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func preflight(endpoint *packetEndpoint, cfg options, plan *trafficPlan) error {
	packet := buildPacket(plan.innerPacketBytes, plan, 0, 0)
	metadata := packet[plan.sendMetadataOffset():]
	binary.BigEndian.PutUint64(metadata[8:16], 1)
	binary.BigEndian.PutUint64(metadata[16:24], uint64(time.Now().UnixNano()))
	address := &unix.SockaddrLinklayer{Ifindex: endpoint.ifindex, Protocol: hostToNetwork16(unix.ETH_P_IP), Halen: 6}
	copy(address.Addr[:], plan.targetMAC[:])
	if err := unix.Sendto(endpoint.sendFD, packet, 0, address); err != nil {
		return err
	}
	deadline := time.Now().Add(3 * time.Second)
	buffer := make([]byte, maximumEthernetSize+64)
	for time.Now().Before(deadline) {
		for _, fd := range endpoint.receivers {
			n, _, err := unix.Recvfrom(fd, buffer, unix.MSG_DONTWAIT)
			if err != nil {
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
					continue
				}
				return err
			}
			receivedGTP, offset, ok := receivedPacketLayout(buffer[:n])
			if ok && binary.BigEndian.Uint64(buffer[offset:offset+8]) == plan.runID &&
				validateReceivedPacketLayout(buffer[:n], plan, receivedGTP, offset) {
				return nil
			}
		}
		time.Sleep(time.Millisecond)
	}
	return errors.New("timed out waiting for a validated rewritten packet")
}

func openPacketEndpoint(device *net.Interface, bufferBytes, receiverWorkers int) (*packetEndpoint, error) {
	endpoint, err := openSendEndpoint(device, bufferBytes)
	if err != nil {
		return nil, err
	}
	closeOnError := func(cause error) (*packetEndpoint, error) {
		endpoint.close()
		return nil, cause
	}
	group := (os.Getpid() ^ device.Index) & 0xffff
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

func openSendEndpoint(device *net.Interface, bufferBytes int) (*packetEndpoint, error) {
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
	if err := unix.SetsockoptInt(sendFD, unix.SOL_PACKET, unix.PACKET_QDISC_BYPASS, 1); err != nil {
		return closeOnError(err)
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

func (s *packetEndpoint) statistics() (uint64, uint64) {
	var packets, drops uint64
	for _, fd := range s.receivers {
		value, err := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
		if err == nil {
			packets += uint64(value.Packets)
			drops += uint64(value.Drops)
		}
	}
	return packets, drops
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

func (p *trafficPlan) summarize(cfg options) streamResult {
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
	offeredFrameBytes := p.sendFrameBytes(p.innerPacketBytes)
	receivedFrameBytes := p.receiveFrameBytes(p.innerPacketBytes)
	offeredWireBytes := physicalWireBytes(offeredFrameBytes)
	receivedWireBytes := physicalWireBytes(receivedFrameBytes)
	bearer := "default"
	if p.dedicatedBearer {
		bearer = "qci1"
	}
	return streamResult{
		Direction: p.direction, TrafficClass: p.trafficClass, Bearer: bearer,
		InnerPacketBytes: p.innerPacketBytes, OfferedEncapsulation: encapsulationName(p.sendsGTP()),
		ReceivedEncapsulation:          encapsulationName(p.receivesGTP()),
		OfferedAFPacketFrameBytes:      offeredFrameBytes,
		ReceivedAFPacketFrameBytes:     receivedFrameBytes,
		OfferedPhysicalBytesPerPacket:  offeredWireBytes,
		ReceivedPhysicalBytesPerPacket: receivedWireBytes,
		TargetPacketsPerSecond:         p.targetPPS,
		Workers:                        cfg.workers, DurationMilliseconds: float64(cfg.duration.Microseconds()) / 1000,
		SentPackets: sent, ReceivedPackets: received, LostPackets: lost,
		DuplicateOrReordered: p.duplicates.Load(), SendErrors: p.sendErrors.Load(),
		LossPercent: lossPercent, SentPacketsPerSecond: float64(sent) / durationSeconds,
		ReceivedPacketsPerSecond:   float64(received) / durationSeconds,
		OfferedSubscriberMbps:      float64(sent*uint64(p.innerPacketBytes)*8) / durationSeconds / 1_000_000,
		ReceivedSubscriberMbps:     float64(received*uint64(p.innerPacketBytes)*8) / durationSeconds / 1_000_000,
		OfferedPhysicalWireMbps:    float64(sent*uint64(offeredWireBytes)*8) / durationSeconds / 1_000_000,
		ReceivedPhysicalWireMbps:   float64(received*uint64(receivedWireBytes)*8) / durationSeconds / 1_000_000,
		LatencySamples:             p.latency.samples.Load(),
		P50LatencyMilliseconds:     p.latency.quantile(0.50),
		P95LatencyMilliseconds:     p.latency.quantile(0.95),
		P99LatencyMilliseconds:     p.latency.quantile(0.99),
		P999LatencyMilliseconds:    p.latency.quantile(0.999),
		MaximumLatencyMilliseconds: float64(p.latency.maximum.Load()) / float64(time.Millisecond),
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
	nanoseconds := uint64(elapsed)
	for {
		previous := h.maximum.Load()
		if nanoseconds <= previous || h.maximum.CompareAndSwap(previous, nanoseconds) {
			break
		}
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
				return float64(h.maximum.Load()) / float64(time.Millisecond)
			}
			return float64(latencyUpperBounds[index]) / float64(time.Millisecond)
		}
	}
	return 0
}

func metadataOffset() int {
	return metadataOffsetForGTP(true)
}

func metadataOffsetForGTP(gtp bool) int {
	if gtp {
		return ethernetBytes + outerIPv4Bytes + udpBytes + gtpuBytes + innerIPv4Bytes + innerUDPBytes
	}
	return ethernetBytes + innerIPv4Bytes + innerUDPBytes
}

func (p *trafficPlan) sendsGTP() bool {
	return !p.cupsChain || p.networkDirection == directionUplink
}

func (p *trafficPlan) receivesGTP() bool {
	return !p.cupsChain || p.networkDirection == directionDownlink
}

func (p *trafficPlan) sendMetadataOffset() int {
	return metadataOffsetForGTP(p.sendsGTP())
}

func (p *trafficPlan) sendFrameBytes(innerSize int) int {
	if p.sendsGTP() {
		return gtpFrameBytes(innerSize)
	}
	return plainFrameBytes(innerSize)
}

func (p *trafficPlan) receiveFrameBytes(innerSize int) int {
	if p.receivesGTP() {
		return gtpFrameBytes(innerSize)
	}
	return plainFrameBytes(innerSize)
}

func gtpFrameBytes(innerSize int) int {
	return ethernetBytes + outerIPv4Bytes + udpBytes + gtpuBytes + innerSize
}

func plainFrameBytes(innerSize int) int {
	return ethernetBytes + innerSize
}

func physicalWireBytes(frameBytes int) int {
	// The physical benchmark uses a VLAN parent. Add the VLAN tag, FCS,
	// preamble/SFD, and inter-frame gap to the AF_PACKET frame length.
	return frameBytes + 4 + 4 + 8 + 12
}

func encapsulationName(gtp bool) string {
	if gtp {
		return "GTP-U/IPv4/UDP"
	}
	return "plain IPv4"
}

func innerPacketEndpoints(plan *trafficPlan, flow int) (netip.Addr, netip.Addr) {
	var source, destination netip.Addr
	if plan.cupsChain {
		source, destination = chainUEAddress(flow), chainServiceIP
	} else {
		source = addIPv4(netip.MustParseAddr("100.64.0.1"), flow)
		destination = addIPv4(netip.MustParseAddr("100.96.0.1"), flow)
	}
	if plan.networkDirection == directionDownlink {
		source, destination = destination, source
	}
	return source, destination
}

func receivedPacketLayout(packet []byte) (gtp bool, metadataPosition int, ok bool) {
	if len(packet) < plainFrameBytes(innerIPv4Bytes+innerUDPBytes+metadataBytes) ||
		binary.BigEndian.Uint16(packet[12:14]) != unix.ETH_P_IP {
		return false, 0, false
	}
	ip := packet[ethernetBytes:]
	if ip[0] != 0x45 || ip[9] != 17 || int(binary.BigEndian.Uint16(ip[2:4])) != len(ip) {
		return false, 0, false
	}
	if len(packet) >= metadataOffsetForGTP(true)+metadataBytes {
		udpOffset := ethernetBytes + outerIPv4Bytes
		gtpOffset := udpOffset + udpBytes
		if binary.BigEndian.Uint16(packet[udpOffset+2:udpOffset+4]) == gtpuPort &&
			packet[gtpOffset] == 0x30 && packet[gtpOffset+1] == 255 {
			inner := packet[gtpOffset+gtpuBytes:]
			if len(inner) >= innerIPv4Bytes+innerUDPBytes+metadataBytes &&
				inner[0] == 0x45 && int(binary.BigEndian.Uint16(inner[2:4])) == len(inner) {
				return true, metadataOffsetForGTP(true), true
			}
		}
	}
	return false, metadataOffsetForGTP(false), true
}

func validateInnerIPv4(packet []byte, expectedSource, expectedDestination netip.Addr) bool {
	if len(packet) < innerIPv4Bytes+innerUDPBytes+metadataBytes || packet[0] != 0x45 ||
		packet[9] != 17 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) ||
		!bytesEqualIP(packet[12:16], expectedSource) ||
		!bytesEqualIP(packet[16:20], expectedDestination) {
		return false
	}
	udp := packet[innerIPv4Bytes:]
	return int(binary.BigEndian.Uint16(udp[4:6])) == len(packet)-innerIPv4Bytes
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

func internetChecksum(value []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(value); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(value[index : index+2]))
	}
	if len(value)&1 != 0 {
		sum += uint32(value[len(value)-1]) << 8
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

func bytesEqualIP(value []byte, expected netip.Addr) bool {
	address := expected.As4()
	return len(value) == len(address) && value[0] == address[0] && value[1] == address[1] && value[2] == address[2] && value[3] == address[3]
}

func hardwareAddressEqual(left, right net.HardwareAddr) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func readProcessUsage() processUsage {
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		return processUsage{}
	}
	return processUsage{
		user:   time.Duration(usage.Utime.Sec)*time.Second + time.Duration(usage.Utime.Usec)*time.Microsecond,
		system: time.Duration(usage.Stime.Sec)*time.Second + time.Duration(usage.Stime.Usec)*time.Microsecond,
	}
}
