// Package dataplane implements the portable PGW-U S5-U to SGi forwarding path.
package dataplane

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpu"
)

const (
	GTPUPort                 uint16 = 2152
	defaultSocketBufferBytes        = 16 * 1024 * 1024
	defaultMaxPacketSize            = 65_535
)

type Config struct {
	S5                netip.AddrPort
	AllowedSGWPeers   []netip.Addr
	TunnelName        string
	SocketBufferBytes int
	MaxPacketSize     int
	QERBurstDuration  time.Duration
}

type Counters struct {
	UplinkPackets          uint64
	DownlinkPackets        uint64
	UplinkRXPackets        uint64
	UplinkRXBytes          uint64
	UplinkTXPackets        uint64
	UplinkTXBytes          uint64
	DownlinkRXPackets      uint64
	DownlinkRXBytes        uint64
	DownlinkTXPackets      uint64
	DownlinkTXBytes        uint64
	DefaultUplinkPackets   uint64
	DefaultUplinkBytes     uint64
	DefaultDownlinkPackets uint64
	DefaultDownlinkBytes   uint64
	QCI1UplinkPackets      uint64
	QCI1UplinkBytes        uint64
	QCI1DownlinkPackets    uint64
	QCI1DownlinkBytes      uint64
	QCI1RoutePackets       uint64
	ActiveTFTFilters       uint64
	ActiveQCI1Sessions     uint64
	ActiveQCI1Contexts     uint64
	TFTSyncErrors          uint64
	ForwardedPackets       uint64
	ForwardedBytes         uint64
	UplinkBytes            uint64
	DownlinkBytes          uint64
	DroppedPackets         uint64
	UnknownTEIDs           uint64
	TFTUnmatched           uint64
	FragmentDrops          uint64
	UnknownUEAddresses     uint64
	UnauthorizedPeers      uint64
	MalformedGTP           uint64
	MalformedIP            uint64
	SpoofedSources         uint64
	ClosedGates            uint64
	QERGateDrops           uint64
	QERRateDrops           uint64
	URRMeteredPackets      uint64
	URRMeteredBytes        uint64
	URRThresholdEvents     uint64
	URRActiveMeters        uint64
	WriteErrors            uint64
	QueueFullDrops         uint64
	EchoRequests           uint64
	EndMarkers             uint64
	P50LatencyMicros       uint64
	P95LatencyMicros       uint64
	P99LatencyMicros       uint64
	P999LatencyMicros      uint64
	MaxLatencyMicros       uint64
	LatencyBuckets         []LatencyBucket
	RecoveredGTPLinks      uint64
	RecoveredFirewalls     uint64
	RecoveredPolicyRules   uint64
}

type LatencyBucket struct {
	UpperBoundMicros uint64
	Count            uint64
}

type counterSet struct {
	uplinkPackets      atomic.Uint64
	downlinkPackets    atomic.Uint64
	uplinkRXBytes      atomic.Uint64
	uplinkTXPackets    atomic.Uint64
	uplinkTXBytes      atomic.Uint64
	downlinkRXBytes    atomic.Uint64
	downlinkTXPackets  atomic.Uint64
	downlinkTXBytes    atomic.Uint64
	forwardedPackets   atomic.Uint64
	forwardedBytes     atomic.Uint64
	uplinkBytes        atomic.Uint64
	downlinkBytes      atomic.Uint64
	droppedPackets     atomic.Uint64
	unknownTEIDs       atomic.Uint64
	tftUnmatched       atomic.Uint64
	unknownUEAddresses atomic.Uint64
	unauthorizedPeers  atomic.Uint64
	malformedGTP       atomic.Uint64
	malformedIP        atomic.Uint64
	spoofedSources     atomic.Uint64
	closedGates        atomic.Uint64
	writeErrors        atomic.Uint64
	echoRequests       atomic.Uint64
	endMarkers         atomic.Uint64
	latencyBuckets     [13]atomic.Uint64
	latencyMaxMicros   atomic.Uint64
}

type packetDevice interface {
	io.ReadWriteCloser
	Name() string
}

type Forwarder struct {
	s5      *net.UDPConn
	tun     packetDevice
	rules   *rules.Store
	allowed map[netip.Addr]struct{}
	maxSize int
	sendGTP func([]byte, netip.AddrPort) error
	policy  *policyEngine

	metrics   counterSet
	closed    chan struct{}
	closeOnce sync.Once
}

func Listen(config Config, store *rules.Store) (*Forwarder, error) {
	if store == nil {
		return nil, errors.New("pgwu dataplane: nil rule store")
	}
	if !config.S5.Addr().IsValid() || config.S5.Port() == 0 {
		return nil, errors.New("pgwu dataplane: S5-U bind address is required")
	}
	if len(config.AllowedSGWPeers) == 0 {
		return nil, errors.New("pgwu dataplane: at least one allowed SGW-U peer is required")
	}
	if config.SocketBufferBytes < 0 || config.SocketBufferBytes > 1<<30 {
		return nil, errors.New("pgwu dataplane: socket buffer bytes must be between 0 and 1073741824")
	}
	if config.SocketBufferBytes == 0 {
		config.SocketBufferBytes = defaultSocketBufferBytes
	}
	if config.MaxPacketSize < 0 || config.MaxPacketSize > 65_535 {
		return nil, errors.New("pgwu dataplane: max packet size must be between 0 and 65535")
	}
	if config.MaxPacketSize == 0 {
		config.MaxPacketSize = defaultMaxPacketSize
	}
	if config.MaxPacketSize < 1500 {
		return nil, errors.New("pgwu dataplane: max packet size must be at least 1500")
	}
	allowed, err := peerSet(config.AllowedSGWPeers)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(config.S5))
	if err != nil {
		return nil, fmt.Errorf("listen S5-U on %s: %w", config.S5, err)
	}
	if err := conn.SetReadBuffer(config.SocketBufferBytes); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set S5-U receive buffer: %w", err)
	}
	if err := conn.SetWriteBuffer(config.SocketBufferBytes); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set S5-U transmit buffer: %w", err)
	}
	tun, err := openPacketDevice(config.TunnelName)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	f := &Forwarder{
		s5: conn, tun: tun, rules: store, allowed: allowed, maxSize: config.MaxPacketSize,
		policy: newPolicyEngine(config.QERBurstDuration), closed: make(chan struct{}),
	}
	f.sendGTP = func(packet []byte, destination netip.AddrPort) error {
		_, err := f.s5.WriteToUDPAddrPort(packet, destination)
		return err
	}
	return f, nil
}

func (f *Forwarder) S5Addr() netip.AddrPort {
	return f.s5.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (f *Forwarder) TunnelName() string { return f.tun.Name() }

func (f *Forwarder) Serve(ctx context.Context) error {
	errCh := make(chan error, 2)
	go func() { errCh <- f.readGTP() }()
	go func() { errCh <- f.readTunnel() }()
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
		if errors.Is(err, net.ErrClosed) || errors.Is(err, osErrClosed) {
			return nil
		}
		return err
	}
}

func (f *Forwarder) Close() error {
	var result error
	f.closeOnce.Do(func() {
		close(f.closed)
		if err := f.s5.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = err
		}
		if err := f.tun.Close(); err != nil && !errors.Is(err, osErrClosed) && result == nil {
			result = err
		}
	})
	return result
}

func (f *Forwarder) Counters() Counters {
	policy := f.policy.counters()
	return Counters{
		UplinkPackets: f.metrics.uplinkPackets.Load(), DownlinkPackets: f.metrics.downlinkPackets.Load(),
		UplinkRXPackets: f.metrics.uplinkPackets.Load(), UplinkRXBytes: f.metrics.uplinkRXBytes.Load(),
		UplinkTXPackets: f.metrics.uplinkTXPackets.Load(), UplinkTXBytes: f.metrics.uplinkTXBytes.Load(),
		DownlinkRXPackets: f.metrics.downlinkPackets.Load(), DownlinkRXBytes: f.metrics.downlinkRXBytes.Load(),
		DownlinkTXPackets: f.metrics.downlinkTXPackets.Load(), DownlinkTXBytes: f.metrics.downlinkTXBytes.Load(),
		ForwardedPackets: f.metrics.forwardedPackets.Load(), ForwardedBytes: f.metrics.forwardedBytes.Load(),
		UplinkBytes: f.metrics.uplinkBytes.Load(), DownlinkBytes: f.metrics.downlinkBytes.Load(),
		DroppedPackets: f.metrics.droppedPackets.Load(), UnknownTEIDs: f.metrics.unknownTEIDs.Load(),
		TFTUnmatched:       f.metrics.tftUnmatched.Load(),
		UnknownUEAddresses: f.metrics.unknownUEAddresses.Load(), UnauthorizedPeers: f.metrics.unauthorizedPeers.Load(),
		MalformedGTP: f.metrics.malformedGTP.Load(), MalformedIP: f.metrics.malformedIP.Load(),
		SpoofedSources: f.metrics.spoofedSources.Load(), ClosedGates: f.metrics.closedGates.Load(),
		QERGateDrops: policy.QERGateDrops, QERRateDrops: policy.QERRateDrops,
		URRMeteredPackets: policy.URRMeteredPackets, URRMeteredBytes: policy.URRMeteredBytes,
		URRThresholdEvents: policy.URRThresholdEvents, URRActiveMeters: policy.URRActiveMeters,
		WriteErrors: f.metrics.writeErrors.Load(), EchoRequests: f.metrics.echoRequests.Load(),
		EndMarkers:       f.metrics.endMarkers.Load(),
		P50LatencyMicros: f.latencyPercentileMicros(500), P95LatencyMicros: f.latencyPercentileMicros(950),
		P99LatencyMicros: f.latencyPercentileMicros(990), P999LatencyMicros: f.latencyPercentileMicros(999),
		MaxLatencyMicros: f.metrics.latencyMaxMicros.Load(), LatencyBuckets: f.latencyBucketSnapshot(),
	}
}

func (f *Forwarder) readGTP() error {
	buffer := make([]byte, f.maxSize)
	for {
		n, peer, err := f.s5.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return err
		}
		f.metrics.uplinkPackets.Add(1)
		f.metrics.uplinkRXBytes.Add(uint64(n))
		f.handleGTP(netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()), buffer[:n])
	}
}

func (f *Forwarder) readTunnel() error {
	buffer := make([]byte, f.maxSize)
	gtpBuffer := make([]byte, f.maxSize+8)
	for {
		n, err := f.tun.Read(buffer)
		if err != nil {
			return err
		}
		f.metrics.downlinkPackets.Add(1)
		f.metrics.downlinkRXBytes.Add(uint64(n))
		f.handleTunnelInto(buffer[:n], gtpBuffer)
	}
}

func (f *Forwarder) handleGTP(peer netip.AddrPort, packet []byte) {
	started := time.Now()
	if _, ok := f.allowed[peer.Addr().Unmap()]; !ok {
		f.drop(&f.metrics.unauthorizedPeers)
		return
	}
	header, payload, err := gtpu.Parse(packet)
	if err != nil || header.FrameLength != len(packet) {
		f.drop(&f.metrics.malformedGTP)
		return
	}
	switch header.MessageType {
	case gtpu.MessageEchoRequest:
		f.metrics.echoRequests.Add(1)
		response, err := gtpu.Marshal(gtpu.Header{
			Version: gtpu.Version, ProtocolType: true, Sequence: true,
			MessageType: gtpu.MessageEchoResponse, SequenceNumber: header.SequenceNumber,
		}, []byte{14, 0})
		if err == nil && f.sendGTP(response, peer) != nil {
			f.drop(&f.metrics.writeErrors)
		}
		return
	case gtpu.MessageEchoResponse:
		return
	case gtpu.MessageEndMarker:
		f.metrics.endMarkers.Add(1)
		return
	case gtpu.MessageGPDU:
	default:
		f.drop(&f.metrics.malformedGTP)
		return
	}
	source, _, _, err := parseIPv4(payload)
	if err != nil {
		f.drop(&f.metrics.malformedIP)
		return
	}
	current, ok := f.rules.LookupUplinkPacket(header.TEID, payload)
	if !ok {
		if _, known := f.rules.LookupUplink(header.TEID); known {
			f.drop(&f.metrics.tftUnmatched)
		} else {
			f.drop(&f.metrics.unknownTEIDs)
		}
		return
	}
	if peer.Addr().Unmap() != current.Remote.IP.Unmap() {
		f.drop(&f.metrics.unauthorizedPeers)
		return
	}
	switch f.policy.authorize(current, true, len(payload), time.Now()) {
	case policyGateClosed:
		f.drop(&f.metrics.closedGates)
		return
	case policyRateExceeded:
		f.metrics.droppedPackets.Add(1)
		return
	}
	if source != current.UEIPv4 {
		f.drop(&f.metrics.spoofedSources)
		return
	}
	if _, err := f.tun.Write(payload); err != nil {
		f.drop(&f.metrics.writeErrors)
		return
	}
	f.metrics.uplinkTXPackets.Add(1)
	f.metrics.uplinkTXBytes.Add(uint64(len(payload)))
	f.policy.recordUsage(current, true, len(payload), time.Now())
	f.forwarded(len(payload), true, time.Since(started))
}

func (f *Forwarder) handleTunnel(packet []byte) {
	f.handleTunnelInto(packet, make([]byte, len(packet)+8))
}

func (f *Forwarder) handleTunnelInto(packet, gtpBuffer []byte) {
	started := time.Now()
	_, destination, _, err := parseIPv4(packet)
	if err != nil {
		f.drop(&f.metrics.malformedIP)
		return
	}
	current, ok := f.rules.LookupDownlinkPacket(destination, packet)
	if !ok {
		f.drop(&f.metrics.unknownUEAddresses)
		return
	}
	switch f.policy.authorize(current, false, len(packet), time.Now()) {
	case policyGateClosed:
		f.drop(&f.metrics.closedGates)
		return
	case policyRateExceeded:
		f.metrics.droppedPackets.Add(1)
		return
	}
	n, err := gtpu.MarshalTo(gtpBuffer, gtpu.Header{
		Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: current.Remote.TEID,
	}, packet)
	if err != nil {
		f.drop(&f.metrics.malformedGTP)
		return
	}
	if err := f.sendGTP(gtpBuffer[:n], netip.AddrPortFrom(current.Remote.IP, GTPUPort)); err != nil {
		f.drop(&f.metrics.writeErrors)
		return
	}
	f.metrics.downlinkTXPackets.Add(1)
	f.metrics.downlinkTXBytes.Add(uint64(n))
	f.policy.recordUsage(current, false, len(packet), time.Now())
	f.forwarded(len(packet), false, time.Since(started))
}

// ReconcileSession and DeleteSession implement rules.Observer for portable
// token-bucket and usage-meter lifecycle.
func (f *Forwarder) ReconcileSession(current rules.Session) { f.policy.reconcileSession(current) }
func (f *Forwarder) DeleteSession(upSEID uint64)            { f.policy.deleteSession(upSEID) }

func (f *Forwarder) Usage() []UsageMeasurement { return f.policy.usageSnapshot() }

func (f *Forwarder) drop(reason *atomic.Uint64) {
	reason.Add(1)
	f.metrics.droppedPackets.Add(1)
}

func (f *Forwarder) forwarded(payloadBytes int, uplink bool, elapsed time.Duration) {
	f.metrics.forwardedPackets.Add(1)
	f.metrics.forwardedBytes.Add(uint64(payloadBytes))
	if uplink {
		f.metrics.uplinkBytes.Add(uint64(payloadBytes))
	} else {
		f.metrics.downlinkBytes.Add(uint64(payloadBytes))
	}
	f.recordLatency(elapsed)
}

func parseIPv4(packet []byte) (source, destination netip.Addr, totalLength int, err error) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, 0, errors.New("invalid IPv4 header")
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(packet) {
		return netip.Addr{}, netip.Addr{}, 0, errors.New("invalid IPv4 IHL")
	}
	totalLength = int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength < headerLength || totalLength != len(packet) {
		return netip.Addr{}, netip.Addr{}, 0, errors.New("invalid IPv4 total length")
	}
	var sourceRaw, destinationRaw [4]byte
	copy(sourceRaw[:], packet[12:16])
	copy(destinationRaw[:], packet[16:20])
	source = netip.AddrFrom4(sourceRaw)
	destination = netip.AddrFrom4(destinationRaw)
	if source.IsUnspecified() || source.IsMulticast() || destination.IsUnspecified() || destination.IsMulticast() {
		return netip.Addr{}, netip.Addr{}, 0, errors.New("unusable IPv4 endpoint")
	}
	return source, destination, totalLength, nil
}

func peerSet(peers []netip.Addr) (map[netip.Addr]struct{}, error) {
	out := make(map[netip.Addr]struct{}, len(peers))
	for index, peer := range peers {
		if !peer.Is4() {
			return nil, fmt.Errorf("pgwu dataplane: SGW peer %d is not IPv4", index)
		}
		out[peer.Unmap()] = struct{}{}
	}
	return out, nil
}

var latencyBounds = [...]time.Duration{
	10 * time.Microsecond, 25 * time.Microsecond, 50 * time.Microsecond,
	100 * time.Microsecond, 250 * time.Microsecond, 500 * time.Microsecond,
	time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond,
	10 * time.Millisecond, 25 * time.Millisecond, 50 * time.Millisecond,
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
