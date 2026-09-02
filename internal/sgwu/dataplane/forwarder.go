// Package dataplane implements the portable SGW-U GTP-U forwarding path.
package dataplane

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
	"github.com/lodestarnetworks/cups/internal/udpstats"
	"github.com/lodestarnetworks/cups/pkg/gtpu"
)

const GTPUPort uint16 = 2152

const defaultSocketBufferBytes = 16 * 1024 * 1024

const defaultPacketBatchSize = 64

const defaultQERBurstDuration = 100 * time.Millisecond

type Config struct {
	Access             netip.AddrPort
	Core               netip.AddrPort
	AllowedAccessPeers []netip.Addr
	AllowedCorePeers   []netip.Addr
	SocketBufferBytes  int
	PacketBatchSize    int
	BufferClasses      []BufferClassConfig
	QERBurstDuration   time.Duration
}

type Counters struct {
	AccessPackets            uint64
	CorePackets              uint64
	UplinkRXPackets          uint64
	UplinkRXBytes            uint64
	UplinkTXPackets          uint64
	UplinkTXBytes            uint64
	DownlinkRXPackets        uint64
	DownlinkRXBytes          uint64
	DownlinkTXPackets        uint64
	DownlinkTXBytes          uint64
	ForwardedPackets         uint64
	ForwardedBytes           uint64
	UplinkBytes              uint64
	DownlinkBytes            uint64
	DroppedPackets           uint64
	AccessSocketDrops        uint64
	CoreSocketDrops          uint64
	UnknownTEIDs             uint64
	MalformedPackets         uint64
	QueueFullDrops           uint64
	UnauthorizedPeers        uint64
	EchoRequests             uint64
	DownlinkReports          uint64
	BufferedPackets          uint64
	BufferedBytes            uint64
	BufferEnqueued           uint64
	BufferFlushed            uint64
	BufferExpired            uint64
	BufferOverflowDrops      uint64
	BufferPurged             uint64
	BufferClasses            []BufferClassCounters
	FastPathFallbacks        uint64
	FastPathForwardedPackets uint64
	FastPathForwardedBytes   uint64
	FastPathSyncFailures     uint64
	FastPathRewriteErrors    uint64
	FastPathP95Micros        uint64
	P50LatencyMicros         uint64
	P95LatencyMicros         uint64
	P99LatencyMicros         uint64
	P999LatencyMicros        uint64
	MaxLatencyMicros         uint64
	LatencyBuckets           []LatencyBucket
	QERGateDrops             uint64
	QERRateDrops             uint64
	URRMeteredPackets        uint64
	URRMeteredBytes          uint64
	URRThresholdEvents       uint64
	URRActiveMeters          uint64
}

type LatencyBucket struct {
	UpperBoundMicros uint64
	Count            uint64
}

type FastPathCounters struct {
	AccessPackets      uint64
	CorePackets        uint64
	ForwardedPackets   uint64
	ForwardedBytes     uint64
	UplinkBytes        uint64
	DownlinkBytes      uint64
	DroppedPackets     uint64
	UnauthorizedPeers  uint64
	FallbackPackets    uint64
	RewriteErrors      uint64
	SyncFailures       uint64
	P95LatencyMicros   uint64
	URRMeteredPackets  uint64
	URRMeteredBytes    uint64
	URRThresholdEvents uint64
	URRActiveMeters    uint64
}

// FastPath is an optional kernel forwarding backend. Packets it does not
// consume continue through the portable UDP path, which remains responsible
// for echo, BAR buffering, DDN, and unsupported packet forms.
type FastPath interface {
	Mode() string
	Counters() FastPathCounters
	Usage() []UsageMeasurement
	SessionChanged(upSEID uint64)
	SessionDeleted(upSEID uint64)
	Close() error
}

type counterSet struct {
	accessPackets     atomic.Uint64
	corePackets       atomic.Uint64
	accessBytes       atomic.Uint64
	coreBytes         atomic.Uint64
	accessTXPackets   atomic.Uint64
	accessTXBytes     atomic.Uint64
	coreTXPackets     atomic.Uint64
	coreTXBytes       atomic.Uint64
	forwardedPackets  atomic.Uint64
	forwardedBytes    atomic.Uint64
	uplinkBytes       atomic.Uint64
	downlinkBytes     atomic.Uint64
	droppedPackets    atomic.Uint64
	accessSocketDrops atomic.Uint64
	coreSocketDrops   atomic.Uint64
	unknownTEIDs      atomic.Uint64
	malformedPackets  atomic.Uint64
	queueFullDrops    atomic.Uint64
	unauthorizedPeers atomic.Uint64
	echoRequests      atomic.Uint64
	downlinkReports   atomic.Uint64
	latencyBuckets    [13]atomic.Uint64
	latencyMaxMicros  atomic.Uint64
}

type DownlinkReporter interface {
	QueueDownlinkReport(upSEID uint64, pdrID uint16, qci, arp uint8, delay time.Duration) bool
}

type Forwarder struct {
	access          *net.UDPConn
	core            *net.UDPConn
	accessReader    *udpstats.Reader
	coreReader      *udpstats.Reader
	rules           *rules.Store
	buffers         *packetBuffer
	reporter        DownlinkReporter
	allowedAccess   map[netip.Addr]struct{}
	allowedCore     map[netip.Addr]struct{}
	packetBatchSize int
	fastPath        FastPath
	policy          *policyEngine

	metrics   counterSet
	closed    chan struct{}
	closeOnce sync.Once
}

type packetOutput struct {
	wire         []byte
	destination  netip.AddrPort
	side         rules.DestinationInterface
	payloadBytes int
	source       rules.SourceInterface
	started      time.Time
	forwarded    bool
	matched      rules.PacketRule
}

type outputBatch struct {
	wire    *udpstats.SendBatch
	records []packetOutput
}

// SetDownlinkReporter wires the PFCP Session Report producer. It must be
// called before Serve starts.
func (f *Forwarder) SetDownlinkReporter(reporter DownlinkReporter) {
	f.reporter = reporter
}

// SetFastPath installs an already-reconciled kernel fast path. It must be
// called before Serve starts.
func (f *Forwarder) SetFastPath(value FastPath) {
	f.fastPath = value
}

func (f *Forwarder) Mode() string {
	if f.fastPath != nil {
		return f.fastPath.Mode() + "+portable-fallback"
	}
	return "portable-go/udp"
}

func Listen(config Config, store *rules.Store) (*Forwarder, error) {
	if store == nil {
		return nil, errors.New("sgwu dataplane: nil rule store")
	}
	if !config.Access.Addr().IsValid() || config.Access.Port() == 0 || !config.Core.Addr().IsValid() || config.Core.Port() == 0 {
		return nil, errors.New("sgwu dataplane: both bind addresses are required")
	}
	if !config.Access.Addr().Is4() || !config.Core.Addr().Is4() {
		return nil, errors.New("sgwu dataplane: this LTE release supports IPv4 GTP-U outer addresses only")
	}
	if len(config.AllowedAccessPeers) == 0 || len(config.AllowedCorePeers) == 0 {
		return nil, errors.New("sgwu dataplane: access and core peer allowlists are required")
	}
	if config.SocketBufferBytes < 0 || config.SocketBufferBytes > 1<<30 {
		return nil, errors.New("sgwu dataplane: socket buffer bytes must be between 0 and 1073741824")
	}
	if config.SocketBufferBytes == 0 {
		config.SocketBufferBytes = defaultSocketBufferBytes
	}
	if config.PacketBatchSize < 0 || config.PacketBatchSize > 1024 {
		return nil, errors.New("sgwu dataplane: packet batch size must be between 1 and 1024 when set")
	}
	if config.PacketBatchSize == 0 {
		config.PacketBatchSize = defaultPacketBatchSize
	}
	if config.QERBurstDuration < 0 || config.QERBurstDuration > time.Second {
		return nil, errors.New("sgwu dataplane: QER burst duration must be between 0 and 1 second")
	}
	if config.QERBurstDuration == 0 {
		config.QERBurstDuration = defaultQERBurstDuration
	}
	if config.QERBurstDuration < time.Millisecond {
		return nil, errors.New("sgwu dataplane: QER burst duration must be at least 1 millisecond")
	}
	if len(config.BufferClasses) == 0 {
		config.BufferClasses = []BufferClassConfig{
			{QCI: 0, MaxPackets: 65_536, MaxBytes: 64 * 1024 * 1024, MaxPacketsPerBearer: 32, HoldTime: 5 * time.Second},
			{QCI: 5, MaxPackets: 16_384, MaxBytes: 16 * 1024 * 1024, MaxPacketsPerBearer: 64, HoldTime: 10 * time.Second},
		}
	}
	buffers, err := newPacketBuffer(config.BufferClasses)
	if err != nil {
		return nil, err
	}
	allowedAccess, err := peerSet(config.AllowedAccessPeers)
	if err != nil {
		return nil, fmt.Errorf("sgwu dataplane: access peers: %w", err)
	}
	allowedCore, err := peerSet(config.AllowedCorePeers)
	if err != nil {
		return nil, fmt.Errorf("sgwu dataplane: core peers: %w", err)
	}
	accessConn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(config.Access))
	if err != nil {
		return nil, fmt.Errorf("listen S1-U on %s: %w", config.Access, err)
	}
	coreConn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(config.Core))
	if err != nil {
		_ = accessConn.Close()
		return nil, fmt.Errorf("listen S5-U on %s: %w", config.Core, err)
	}
	for _, conn := range []*net.UDPConn{accessConn, coreConn} {
		if err := conn.SetReadBuffer(config.SocketBufferBytes); err != nil {
			_ = accessConn.Close()
			_ = coreConn.Close()
			return nil, fmt.Errorf("set GTP-U receive buffer: %w", err)
		}
		if err := conn.SetWriteBuffer(config.SocketBufferBytes); err != nil {
			_ = accessConn.Close()
			_ = coreConn.Close()
			return nil, fmt.Errorf("set GTP-U transmit buffer: %w", err)
		}
	}
	accessReader, err := udpstats.NewReader(accessConn)
	if err != nil {
		_ = accessConn.Close()
		_ = coreConn.Close()
		return nil, fmt.Errorf("enable S1-U receive overflow accounting: %w", err)
	}
	coreReader, err := udpstats.NewReader(coreConn)
	if err != nil {
		_ = accessConn.Close()
		_ = coreConn.Close()
		return nil, fmt.Errorf("enable S5-U receive overflow accounting: %w", err)
	}
	return &Forwarder{
		access: accessConn, core: coreConn, accessReader: accessReader, coreReader: coreReader, rules: store,
		buffers:       buffers,
		allowedAccess: allowedAccess, allowedCore: allowedCore,
		packetBatchSize: config.PacketBatchSize,
		policy:          newPolicyEngine(config.QERBurstDuration),
		closed:          make(chan struct{}),
	}, nil
}

func (f *Forwarder) AccessAddr() netip.AddrPort {
	return f.access.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (f *Forwarder) CoreAddr() netip.AddrPort {
	return f.core.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Serve forwards packets until the context is cancelled, Close is called, or
// either UDP socket encounters a fatal error.
func (f *Forwarder) Serve(ctx context.Context) error {
	errCh := make(chan error, 2)
	go func() { errCh <- f.readLoop(rules.SourceAccess) }()
	go func() { errCh <- f.readLoop(rules.SourceCore) }()
	go f.expireBuffers(ctx)
	select {
	case <-ctx.Done():
		_ = f.Close()
		<-errCh
		<-errCh
		return nil
	case <-f.closed:
		<-errCh
		<-errCh
		return nil
	case err := <-errCh:
		_ = f.Close()
		<-errCh
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

func (f *Forwarder) Close() error {
	var result error
	f.closeOnce.Do(func() {
		close(f.closed)
		// Release the UDP listeners before detaching the optional fast path.
		// Fast-path teardown can wait on a concurrent rule synchronization;
		// keeping the listeners open during that wait prevents systemd from
		// starting a replacement process after an overloaded shutdown.
		if err := f.access.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
		if err := f.core.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
		if f.fastPath != nil {
			result = errors.Join(result, f.fastPath.Close())
		}
	})
	return result
}

func (f *Forwarder) Counters() Counters {
	bufferCounters := f.buffers.counters()
	policy := f.policy.counters()
	fast := FastPathCounters{}
	if f.fastPath != nil {
		fast = f.fastPath.Counters()
	}
	p50Latency := f.latencyPercentileMicros(500)
	p95Latency := f.latencyPercentileMicros(950)
	p99Latency := f.latencyPercentileMicros(990)
	p999Latency := f.latencyPercentileMicros(999)
	if fast.P95LatencyMicros > p95Latency {
		p95Latency = fast.P95LatencyMicros
	}
	return Counters{
		AccessPackets:            f.metrics.accessPackets.Load() + fast.AccessPackets,
		CorePackets:              f.metrics.corePackets.Load() + fast.CorePackets,
		UplinkRXPackets:          f.metrics.accessPackets.Load() + fast.AccessPackets,
		UplinkRXBytes:            f.metrics.accessBytes.Load(),
		UplinkTXPackets:          f.metrics.coreTXPackets.Load(),
		UplinkTXBytes:            f.metrics.coreTXBytes.Load(),
		DownlinkRXPackets:        f.metrics.corePackets.Load() + fast.CorePackets,
		DownlinkRXBytes:          f.metrics.coreBytes.Load(),
		DownlinkTXPackets:        f.metrics.accessTXPackets.Load(),
		DownlinkTXBytes:          f.metrics.accessTXBytes.Load(),
		ForwardedPackets:         f.metrics.forwardedPackets.Load() + fast.ForwardedPackets,
		ForwardedBytes:           f.metrics.forwardedBytes.Load() + fast.ForwardedBytes,
		UplinkBytes:              f.metrics.uplinkBytes.Load() + fast.UplinkBytes,
		DownlinkBytes:            f.metrics.downlinkBytes.Load() + fast.DownlinkBytes,
		DroppedPackets:           f.metrics.droppedPackets.Load() + fast.DroppedPackets + bufferCounters.Expired + bufferCounters.OverflowDrops + bufferCounters.Purged,
		AccessSocketDrops:        f.metrics.accessSocketDrops.Load(),
		CoreSocketDrops:          f.metrics.coreSocketDrops.Load(),
		UnknownTEIDs:             f.metrics.unknownTEIDs.Load(),
		MalformedPackets:         f.metrics.malformedPackets.Load(),
		QueueFullDrops:           f.metrics.queueFullDrops.Load(),
		UnauthorizedPeers:        f.metrics.unauthorizedPeers.Load() + fast.UnauthorizedPeers,
		EchoRequests:             f.metrics.echoRequests.Load(),
		DownlinkReports:          f.metrics.downlinkReports.Load(),
		BufferedPackets:          bufferCounters.CurrentPackets,
		BufferedBytes:            bufferCounters.CurrentBytes,
		BufferEnqueued:           bufferCounters.Enqueued,
		BufferFlushed:            bufferCounters.Flushed,
		BufferExpired:            bufferCounters.Expired,
		BufferOverflowDrops:      bufferCounters.OverflowDrops,
		BufferPurged:             bufferCounters.Purged,
		BufferClasses:            bufferCounters.Classes,
		FastPathFallbacks:        fast.FallbackPackets,
		FastPathForwardedPackets: fast.ForwardedPackets,
		FastPathForwardedBytes:   fast.ForwardedBytes,
		FastPathSyncFailures:     fast.SyncFailures,
		FastPathRewriteErrors:    fast.RewriteErrors,
		FastPathP95Micros:        fast.P95LatencyMicros,
		P50LatencyMicros:         p50Latency,
		P95LatencyMicros:         p95Latency,
		P99LatencyMicros:         p99Latency,
		P999LatencyMicros:        p999Latency,
		MaxLatencyMicros:         f.metrics.latencyMaxMicros.Load(),
		LatencyBuckets:           f.latencyBucketSnapshot(),
		QERGateDrops:             policy.QERGateDrops,
		QERRateDrops:             policy.QERRateDrops,
		URRMeteredPackets:        policy.URRMeteredPackets + fast.URRMeteredPackets,
		URRMeteredBytes:          policy.URRMeteredBytes + fast.URRMeteredBytes,
		URRThresholdEvents:       policy.URRThresholdEvents + fast.URRThresholdEvents,
		URRActiveMeters:          policy.URRActiveMeters + fast.URRActiveMeters,
	}
}

// Usage returns point-in-time, telemetry-only PFCP URR measurements. Usage
// never gates forwarding and is intentionally separate from QER policing.
func (f *Forwarder) Usage() []UsageMeasurement {
	portable := f.policy.usageSnapshot()
	if f.fastPath == nil {
		return portable
	}
	return mergeUsageMeasurements(portable, f.fastPath.Usage())
}

func mergeUsageMeasurements(left, right []UsageMeasurement) []UsageMeasurement {
	type key struct {
		upSEID uint64
		urrID  uint32
	}
	merged := make(map[key]UsageMeasurement, len(left)+len(right))
	for _, values := range [][]UsageMeasurement{left, right} {
		for _, measurement := range values {
			currentKey := key{upSEID: measurement.UPSEID, urrID: measurement.URRID}
			current := merged[currentKey]
			current.UPSEID = measurement.UPSEID
			current.URRID = measurement.URRID
			current.UplinkPackets = saturatingAdd(current.UplinkPackets, measurement.UplinkPackets)
			current.DownlinkPackets = saturatingAdd(current.DownlinkPackets, measurement.DownlinkPackets)
			current.UplinkBytes = saturatingAdd(current.UplinkBytes, measurement.UplinkBytes)
			current.DownlinkBytes = saturatingAdd(current.DownlinkBytes, measurement.DownlinkBytes)
			current.ThresholdEvents = saturatingAdd(current.ThresholdEvents, measurement.ThresholdEvents)
			if current.FirstPacket.IsZero() || !measurement.FirstPacket.IsZero() && measurement.FirstPacket.Before(current.FirstPacket) {
				current.FirstPacket = measurement.FirstPacket
			}
			if measurement.LastPacket.After(current.LastPacket) {
				current.LastPacket = measurement.LastPacket
			}
			merged[currentKey] = current
		}
	}
	out := make([]UsageMeasurement, 0, len(merged))
	for _, measurement := range merged {
		out = append(out, measurement)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UPSEID == out[j].UPSEID {
			return out[i].URRID < out[j].URRID
		}
		return out[i].UPSEID < out[j].UPSEID
	})
	return out
}

func (f *Forwarder) readLoop(source rules.SourceInterface) error {
	reader := f.coreReader
	if source == rules.SourceAccess {
		reader = f.accessReader
	}
	batch, err := reader.NewBatch(f.packetBatchSize, 65_535)
	if err != nil {
		return err
	}
	accessWire, err := udpstats.NewSendBatch(f.packetBatchSize)
	if err != nil {
		return err
	}
	coreWire, err := udpstats.NewSendBatch(f.packetBatchSize)
	if err != nil {
		return err
	}
	accessOutput := outputBatch{wire: accessWire, records: make([]packetOutput, 0, f.packetBatchSize)}
	coreOutput := outputBatch{wire: coreWire, records: make([]packetOutput, 0, f.packetBatchSize)}
	for {
		n, socketDrops, err := reader.ReadBatch(batch)
		if err != nil {
			return err
		}
		if socketDrops != 0 {
			f.metrics.droppedPackets.Add(socketDrops)
			if source == rules.SourceAccess {
				f.metrics.accessSocketDrops.Add(socketDrops)
			} else {
				f.metrics.coreSocketDrops.Add(socketDrops)
			}
		}
		if source == rules.SourceAccess {
			f.metrics.accessPackets.Add(uint64(n))
		} else {
			f.metrics.corePackets.Add(uint64(n))
		}
		accessOutput.reset()
		coreOutput.reset()
		for index := 0; index < n; index++ {
			datagram := &batch.Datagrams[index]
			if source == rules.SourceAccess {
				f.metrics.accessBytes.Add(uint64(datagram.N))
			} else {
				f.metrics.coreBytes.Add(uint64(datagram.N))
			}
			output, ok := f.prepare(source, datagram.Peer, datagram.Buffer[:datagram.N])
			if !ok {
				continue
			}
			switch output.side {
			case rules.DestinationAccess:
				if !accessOutput.append(output) && output.forwarded {
					f.metrics.queueFullDrops.Add(1)
					f.metrics.droppedPackets.Add(1)
				}
			case rules.DestinationCore:
				if !coreOutput.append(output) && output.forwarded {
					f.metrics.queueFullDrops.Add(1)
					f.metrics.droppedPackets.Add(1)
				}
			default:
				if output.forwarded {
					f.metrics.droppedPackets.Add(1)
				}
			}
		}
		f.writeOutputBatch(f.accessReader, &accessOutput, rules.DestinationAccess)
		f.writeOutputBatch(f.coreReader, &coreOutput, rules.DestinationCore)
	}
}

func (b *outputBatch) reset() {
	b.wire.Reset()
	b.records = b.records[:0]
}

func (b *outputBatch) append(output packetOutput) bool {
	if b.wire.Append(output.wire, output.destination) {
		b.records = append(b.records, output)
		return true
	}
	return false
}

func (f *Forwarder) writeOutputBatch(writer *udpstats.Reader, batch *outputBatch, destination rules.DestinationInterface) {
	sent, _ := writer.WriteBatch(batch.wire)
	for index, output := range batch.records {
		if index >= sent {
			if output.forwarded {
				f.metrics.queueFullDrops.Add(1)
				f.metrics.droppedPackets.Add(1)
			}
			continue
		}
		if destination == rules.DestinationAccess {
			f.metrics.accessTXPackets.Add(1)
			f.metrics.accessTXBytes.Add(uint64(len(output.wire)))
		} else {
			f.metrics.coreTXPackets.Add(1)
			f.metrics.coreTXBytes.Add(uint64(len(output.wire)))
		}
		if !output.forwarded {
			continue
		}
		f.metrics.forwardedPackets.Add(1)
		f.metrics.forwardedBytes.Add(uint64(output.payloadBytes))
		if output.source == rules.SourceAccess {
			f.metrics.uplinkBytes.Add(uint64(output.payloadBytes))
		} else {
			f.metrics.downlinkBytes.Add(uint64(output.payloadBytes))
		}
		f.policy.recordUsage(output.matched, output.source, output.payloadBytes, time.Now())
		f.recordLatency(time.Since(output.started))
	}
}

func (f *Forwarder) prepare(source rules.SourceInterface, peer netip.AddrPort, packet []byte) (packetOutput, bool) {
	started := time.Now()
	if !f.peerAllowed(source, peer.Addr()) {
		f.metrics.unauthorizedPeers.Add(1)
		f.metrics.droppedPackets.Add(1)
		return packetOutput{}, false
	}
	header, payload, err := gtpu.Parse(packet)
	if err != nil || header.FrameLength != len(packet) {
		f.metrics.malformedPackets.Add(1)
		f.metrics.droppedPackets.Add(1)
		return packetOutput{}, false
	}
	switch header.MessageType {
	case gtpu.MessageEchoRequest:
		f.metrics.echoRequests.Add(1)
		response, err := gtpu.Marshal(gtpu.Header{
			Version:        gtpu.Version,
			ProtocolType:   true,
			Sequence:       true,
			MessageType:    gtpu.MessageEchoResponse,
			SequenceNumber: header.SequenceNumber,
		}, []byte{14, 0})
		if err != nil {
			return packetOutput{}, false
		}
		side := rules.DestinationCore
		if source == rules.SourceAccess {
			side = rules.DestinationAccess
		}
		return packetOutput{wire: response, destination: peer, side: side}, true
	case gtpu.MessageEchoResponse:
		return packetOutput{}, false
	case gtpu.MessageGPDU, gtpu.MessageEndMarker:
	default:
		f.metrics.droppedPackets.Add(1)
		return packetOutput{}, false
	}

	matched, ok := f.rules.LookupPacket(source, header.TEID)
	if !ok {
		f.metrics.unknownTEIDs.Add(1)
		f.metrics.droppedPackets.Add(1)
		return packetOutput{}, false
	}
	if f.policy.checkGates(matched, source) != policyAllow {
		f.metrics.droppedPackets.Add(1)
		return packetOutput{}, false
	}
	if source == rules.SourceCore && matched.FAR.ApplyAction&rules.ActionBuffer != 0 {
		key := bufferKey{upSEID: matched.UPSEID, pdrID: matched.PDR.ID}
		qci := matched.QER.QCI
		if qci == 0 {
			// In the standards-only Sxa profile the per-session BAR ID is the
			// default bearer QCI. This keeps IMS and bulk pools independent even
			// before an operator has registered a PEN for per-bearer metadata.
			qci = matched.FAR.BARID
		}
		if matched.FAR.ApplyAction&rules.ActionNotifyControlPlane != 0 && f.reporter != nil && f.reporter.QueueDownlinkReport(matched.UPSEID, matched.PDR.ID, qci, matched.QER.ARP, matched.BAR.DownlinkNotificationDelay) {
			f.metrics.downlinkReports.Add(1)
		}
		_ = f.buffers.enqueue(key, qci, packet, len(payload), time.Now())
		// Close the lookup/update race: if PFCP activated the FAR immediately
		// before the enqueue, this second lookup drains the packet now.
		f.flushBuffered(key)
		return packetOutput{}, false
	}
	if matched.FAR.ApplyAction&rules.ActionDrop != 0 || matched.FAR.ApplyAction&rules.ActionForward == 0 || matched.FAR.OuterHeader == nil {
		f.metrics.droppedPackets.Add(1)
		return packetOutput{}, false
	}
	if f.policy.allowRate(matched, source, len(payload), started) != policyAllow {
		f.metrics.droppedPackets.Add(1)
		return packetOutput{}, false
	}

	// Parse has validated the complete frame and GTP-U always stores its TEID
	// at bytes 4..7. Rewriting those bytes in the receive buffer preserves all
	// optional and extension headers while avoiding a packet-sized allocation
	// and copy in the forwarding hot path. sendmmsg consumes the batch before
	// the receive buffers are reused.
	binary.BigEndian.PutUint32(packet[4:8], matched.FAR.OuterHeader.TEID)
	destination := netip.AddrPortFrom(matched.FAR.OuterHeader.IP, GTPUPort)
	var side rules.DestinationInterface
	switch matched.FAR.DestinationInterface {
	case rules.DestinationAccess:
		side = rules.DestinationAccess
	case rules.DestinationCore:
		side = rules.DestinationCore
	default:
		f.metrics.droppedPackets.Add(1)
		return packetOutput{}, false
	}
	return packetOutput{
		wire: packet, destination: destination, side: side,
		payloadBytes: len(payload), source: source, started: started, forwarded: true, matched: matched,
	}, true
}

// SessionChanged is called after an atomic PFCP rule commit. When an idle
// downlink FAR becomes forwarding, every packet retained for that bearer is
// released to the newly installed eNodeB tunnel.
func (f *Forwarder) SessionChanged(upSEID uint64) {
	if current, ok := f.rules.FindByUPSEID(upSEID); ok {
		f.policy.reconcileSession(current)
	}
	if f.fastPath != nil {
		f.fastPath.SessionChanged(upSEID)
	}
	for _, key := range f.buffers.keys(upSEID) {
		f.flushBuffered(key)
	}
}

// SessionDeleted discards packets whose PFCP ownership no longer exists.
func (f *Forwarder) SessionDeleted(upSEID uint64) {
	f.policy.deleteSession(upSEID)
	if f.fastPath != nil {
		f.fastPath.SessionDeleted(upSEID)
	}
	f.buffers.purgeSession(upSEID)
}

func (f *Forwarder) flushBuffered(key bufferKey) {
	matched, ok := f.rules.LookupByPDR(key.upSEID, key.pdrID)
	if !ok || matched.FAR.ApplyAction&rules.ActionForward == 0 || matched.FAR.ApplyAction&rules.ActionDrop != 0 || matched.FAR.OuterHeader == nil || matched.FAR.DestinationInterface != rules.DestinationAccess {
		return
	}
	drained := f.buffers.drain(key)
	if len(drained.frames) == 0 {
		return
	}
	destination := netip.AddrPortFrom(matched.FAR.OuterHeader.IP, GTPUPort)
	for index, frame := range drained.frames {
		if len(frame.wire) < 8 {
			f.metrics.droppedPackets.Add(1)
			continue
		}
		// Re-read the FAR for every packet so a concurrent release/handover does
		// not drain the remainder toward an endpoint that has just been removed.
		current, exists := f.rules.LookupByPDR(key.upSEID, key.pdrID)
		if exists && current.FAR.ApplyAction&rules.ActionBuffer != 0 && current.FAR.ApplyAction&rules.ActionDrop == 0 {
			qci := current.QER.QCI
			if qci == 0 {
				qci = current.FAR.BARID
			}
			f.buffers.restore(key, drained.pool, qci, drained.frames[index:])
			return
		}
		if !exists || current.FAR.ApplyAction&rules.ActionForward == 0 || current.FAR.OuterHeader == nil || current.FAR.DestinationInterface != rules.DestinationAccess {
			f.metrics.droppedPackets.Add(1)
			continue
		}
		if f.policy.authorize(current, rules.SourceCore, frame.payloadBytes, time.Now()) != policyAllow {
			f.metrics.droppedPackets.Add(1)
			continue
		}
		destination = netip.AddrPortFrom(current.FAR.OuterHeader.IP, GTPUPort)
		binary.BigEndian.PutUint32(frame.wire[4:8], current.FAR.OuterHeader.TEID)
		started := time.Now()
		if _, err := f.access.WriteToUDPAddrPort(frame.wire, destination); err != nil {
			f.metrics.droppedPackets.Add(1)
			continue
		}
		f.metrics.accessTXPackets.Add(1)
		f.metrics.accessTXBytes.Add(uint64(len(frame.wire)))
		f.metrics.forwardedPackets.Add(1)
		f.metrics.forwardedBytes.Add(uint64(frame.payloadBytes))
		f.metrics.downlinkBytes.Add(uint64(frame.payloadBytes))
		f.policy.recordUsage(current, rules.SourceCore, frame.payloadBytes, time.Now())
		f.recordLatency(time.Since(started))
	}
}

func (f *Forwarder) expireBuffers(ctx context.Context) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			f.buffers.expire(now)
		case <-ctx.Done():
			return
		case <-f.closed:
			return
		}
	}
}

func peerSet(peers []netip.Addr) (map[netip.Addr]struct{}, error) {
	out := make(map[netip.Addr]struct{}, len(peers))
	for index, peer := range peers {
		if !peer.IsValid() {
			return nil, fmt.Errorf("invalid address at index %d", index)
		}
		out[peer.Unmap()] = struct{}{}
	}
	return out, nil
}

func (f *Forwarder) peerAllowed(source rules.SourceInterface, peer netip.Addr) bool {
	peer = peer.Unmap()
	var allowed map[netip.Addr]struct{}
	if source == rules.SourceAccess {
		allowed = f.allowedAccess
	} else {
		allowed = f.allowedCore
	}
	_, ok := allowed[peer]
	return ok
}

var latencyBounds = [...]time.Duration{
	10 * time.Microsecond,
	25 * time.Microsecond,
	50 * time.Microsecond,
	100 * time.Microsecond,
	250 * time.Microsecond,
	500 * time.Microsecond,
	time.Millisecond,
	2 * time.Millisecond,
	5 * time.Millisecond,
	10 * time.Millisecond,
	25 * time.Millisecond,
	50 * time.Millisecond,
}

func (f *Forwarder) recordLatency(elapsed time.Duration) {
	micros := uint64(elapsed / time.Microsecond)
	for current := f.metrics.latencyMaxMicros.Load(); micros > current && !f.metrics.latencyMaxMicros.CompareAndSwap(current, micros); current = f.metrics.latencyMaxMicros.Load() {
	}
	for index, bound := range latencyBounds {
		if elapsed <= bound {
			f.metrics.latencyBuckets[index].Add(1)
			return
		}
	}
	f.metrics.latencyBuckets[len(f.metrics.latencyBuckets)-1].Add(1)
}

func (f *Forwarder) latencyPercentileMicros(perThousand uint64) uint64 {
	var total uint64
	for index := range f.metrics.latencyBuckets {
		total += f.metrics.latencyBuckets[index].Load()
	}
	if total == 0 {
		return 0
	}
	target := (total*perThousand + 999) / 1000
	var cumulative uint64
	for index, bound := range latencyBounds {
		cumulative += f.metrics.latencyBuckets[index].Load()
		if cumulative >= target {
			return uint64(bound / time.Microsecond)
		}
	}
	return uint64(latencyBounds[len(latencyBounds)-1] / time.Microsecond)
}

func (f *Forwarder) latencyBucketSnapshot() []LatencyBucket {
	out := make([]LatencyBucket, len(f.metrics.latencyBuckets))
	for index := range f.metrics.latencyBuckets {
		upper := uint64(latencyBounds[len(latencyBounds)-1] / time.Microsecond)
		if index < len(latencyBounds) {
			upper = uint64(latencyBounds[index] / time.Microsecond)
		}
		out[index] = LatencyBucket{UpperBoundMicros: upper, Count: f.metrics.latencyBuckets[index].Load()}
	}
	return out
}
