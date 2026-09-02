package dataplane

import (
	"encoding/binary"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpu"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

type memoryDevice struct {
	mu      sync.Mutex
	written [][]byte
}

func (*memoryDevice) Read([]byte) (int, error) { return 0, io.EOF }
func (d *memoryDevice) Write(packet []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.written = append(d.written, append([]byte(nil), packet...))
	return len(packet), nil
}
func (*memoryDevice) Close() error { return nil }
func (*memoryDevice) Name() string { return "test0" }

type sentPacket struct {
	wire []byte
	peer netip.AddrPort
}

func TestBidirectionalForwardingAndAntiSpoofing(t *testing.T) {
	store := rules.NewStore()
	_, err := store.Create(rules.Session{
		CPSEID: 1, UPSEID: 2, UEIPv4: netip.MustParseAddr("10.90.0.2"),
		Local:          rules.Tunnel{TEID: 100, IP: netip.MustParseAddr("10.200.0.20")},
		Remote:         rules.Tunnel{TEID: 200, IP: netip.MustParseAddr("10.200.0.10")},
		UplinkGateOpen: true, DownlinkGateOpen: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	device := &memoryDevice{}
	var sent []sentPacket
	forwarder := &Forwarder{
		tun: device, rules: store, allowed: map[netip.Addr]struct{}{netip.MustParseAddr("10.200.0.10"): {}},
		policy: newPolicyEngine(100 * time.Millisecond),
		sendGTP: func(wire []byte, peer netip.AddrPort) error {
			sent = append(sent, sentPacket{wire: append([]byte(nil), wire...), peer: peer})
			return nil
		},
	}
	uplinkIP := ipv4Packet(netip.MustParseAddr("10.90.0.2"), netip.MustParseAddr("192.0.2.1"), []byte{1, 2, 3})
	uplinkGTP, _ := gtpu.Marshal(gtpu.Header{MessageType: gtpu.MessageGPDU, TEID: 100}, uplinkIP)
	forwarder.handleGTP(netip.MustParseAddrPort("10.200.0.10:2152"), uplinkGTP)
	if len(device.written) != 1 || string(device.written[0]) != string(uplinkIP) {
		t.Fatalf("uplink was not decapsulated: %#v", device.written)
	}

	downlinkIP := ipv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("10.90.0.2"), []byte{4, 5, 6})
	forwarder.handleTunnel(downlinkIP)
	if len(sent) != 1 || sent[0].peer.String() != "10.200.0.10:2152" {
		t.Fatalf("unexpected downlink destination: %#v", sent)
	}
	header, payload, err := gtpu.Parse(sent[0].wire)
	if err != nil || header.TEID != 200 || string(payload) != string(downlinkIP) {
		t.Fatalf("downlink GTP = %#v %x, %v", header, payload, err)
	}

	spoofed := ipv4Packet(netip.MustParseAddr("10.90.0.99"), netip.MustParseAddr("192.0.2.1"), nil)
	spoofedGTP, _ := gtpu.Marshal(gtpu.Header{MessageType: gtpu.MessageGPDU, TEID: 100}, spoofed)
	forwarder.handleGTP(netip.MustParseAddrPort("10.200.0.10:2152"), spoofedGTP)
	counters := forwarder.Counters()
	if counters.ForwardedPackets != 2 || counters.UplinkBytes != uint64(len(uplinkIP)) || counters.DownlinkBytes != uint64(len(downlinkIP)) || counters.SpoofedSources != 1 || counters.DroppedPackets != 1 {
		t.Fatalf("unexpected counters: %#v", counters)
	}
}

func TestClassifiedDrops(t *testing.T) {
	store := rules.NewStore()
	device := &memoryDevice{}
	forwarder := &Forwarder{
		tun: device, rules: store, allowed: map[netip.Addr]struct{}{netip.MustParseAddr("10.200.0.10"): {}},
		policy:  newPolicyEngine(100 * time.Millisecond),
		sendGTP: func([]byte, netip.AddrPort) error { return nil },
	}
	packet, _ := gtpu.Marshal(gtpu.Header{MessageType: gtpu.MessageGPDU, TEID: 999}, ipv4Packet(netip.MustParseAddr("10.90.0.2"), netip.MustParseAddr("192.0.2.1"), nil))
	forwarder.handleGTP(netip.MustParseAddrPort("10.200.0.99:2152"), packet)
	forwarder.handleGTP(netip.MustParseAddrPort("10.200.0.10:2152"), packet)
	forwarder.handleGTP(netip.MustParseAddrPort("10.200.0.10:2152"), []byte{1, 2, 3})
	forwarder.handleTunnel(ipv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("10.90.0.99"), nil))
	counters := forwarder.Counters()
	if counters.UnauthorizedPeers != 1 || counters.UnknownTEIDs != 1 || counters.MalformedGTP != 1 || counters.UnknownUEAddresses != 1 || counters.DroppedPackets != 4 {
		t.Fatalf("unexpected classified drops: %#v", counters)
	}
}

func TestForwarderEnforcesBitrateThenMetersSuccessfulPackets(t *testing.T) {
	store := rules.NewStore()
	created, err := store.Create(rules.Session{
		CPSEID: 10, UPSEID: 20, UEIPv4: netip.MustParseAddr("10.90.0.2"),
		Local:          rules.Tunnel{TEID: 100, IP: netip.MustParseAddr("10.200.0.20")},
		Remote:         rules.Tunnel{TEID: 200, IP: netip.MustParseAddr("10.200.0.10")},
		UplinkGateOpen: true, DownlinkGateOpen: true, MaxUplinkBitsPerSecond: 80_000,
		QERID: 1, URRID: 1, MeasureVolume: true, MeasureDuration: true, UsageReportingThreshold: 1_500,
	})
	if err != nil {
		t.Fatal(err)
	}
	device := &memoryDevice{}
	forwarder := &Forwarder{
		tun: device, rules: store, allowed: map[netip.Addr]struct{}{netip.MustParseAddr("10.200.0.10"): {}},
		policy: newPolicyEngine(100 * time.Millisecond), sendGTP: func([]byte, netip.AddrPort) error { return nil },
	}
	store.SetObserver(forwarder)
	payload := ipv4Packet(netip.MustParseAddr("10.90.0.2"), netip.MustParseAddr("192.0.2.1"), make([]byte, 980))
	wire, _ := gtpu.Marshal(gtpu.Header{MessageType: gtpu.MessageGPDU, TEID: 100}, payload)
	peer := netip.MustParseAddrPort("10.200.0.10:2152")
	forwarder.handleGTP(peer, wire)
	forwarder.handleGTP(peer, wire)
	time.Sleep(110 * time.Millisecond)
	forwarder.handleGTP(peer, wire)
	counters := forwarder.Counters()
	if len(device.written) != 2 || counters.ForwardedPackets != 2 || counters.DroppedPackets != 1 ||
		counters.QERRateDrops != 1 || counters.URRMeteredPackets != 2 || counters.URRMeteredBytes != 2_000 ||
		counters.URRThresholdEvents != 1 || counters.URRActiveMeters != 1 {
		t.Fatalf("forwarding state: writes=%d counters=%#v usage=%#v", len(device.written), counters, forwarder.Usage())
	}
	if err := store.Delete(created.UPSEID, created.Revision); err != nil {
		t.Fatal(err)
	}
	if forwarder.Counters().URRActiveMeters != 0 || len(forwarder.Usage()) != 0 {
		t.Fatal("session deletion retained a usage meter")
	}
}

func TestForwarderEnforcesDedicatedBearerTFTAndUsesBearerTunnel(t *testing.T) {
	store := rules.NewStore()
	voiceFilter := func(pdrID uint16, direction gtpv2.TFTDirection) rules.FlowFilter {
		return rules.FlowFilter{
			PDRID: pdrID, Precedence: 50, Direction: direction,
			Filter: gtpv2.IPv4PacketFilter{
				Direction: direction, HasProtocol: true, Protocol: 17,
				HasLocalPort: true, LocalPortLow: 5060, LocalPortHigh: 5060,
			},
		}
	}
	created, err := store.Create(rules.Session{
		CPSEID: 100, UPSEID: 200, UEIPv4: netip.MustParseAddr("10.90.0.2"),
		Local:          rules.Tunnel{TEID: 100, IP: netip.MustParseAddr("10.200.0.20")},
		Remote:         rules.Tunnel{TEID: 200, IP: netip.MustParseAddr("10.200.0.10")},
		UplinkGateOpen: true, DownlinkGateOpen: true,
		QERID: 1, URRID: 1, MeasureVolume: true,
		DedicatedBearers: []rules.Bearer{{
			Local:       rules.Tunnel{TEID: 101, IP: netip.MustParseAddr("10.200.0.20")},
			Remote:      rules.Tunnel{TEID: 201, IP: netip.MustParseAddr("10.200.0.10")},
			UplinkFARID: 11, DownlinkFARID: 12,
			UplinkGateOpen: true, DownlinkGateOpen: true,
			QERID: 2, URRID: 2, MeasureVolume: true, QCI: 1, ARP: 2,
			Filters: []rules.FlowFilter{
				voiceFilter(21, gtpv2.TFTDirectionUplink),
				voiceFilter(22, gtpv2.TFTDirectionDownlink),
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	device := &memoryDevice{}
	var sent []sentPacket
	forwarder := &Forwarder{
		tun: device, rules: store, allowed: map[netip.Addr]struct{}{netip.MustParseAddr("10.200.0.10"): {}},
		policy: newPolicyEngine(100 * time.Millisecond),
		sendGTP: func(wire []byte, peer netip.AddrPort) error {
			sent = append(sent, sentPacket{wire: append([]byte(nil), wire...), peer: peer})
			return nil
		},
	}
	store.SetObserver(forwarder)
	ue := created.UEIPv4
	remote := netip.MustParseAddr("203.0.113.9")
	uplinkVoice := ipv4TransportPacket(ue, remote, 5060, 5061)
	uplinkGTP, _ := gtpu.Marshal(gtpu.Header{MessageType: gtpu.MessageGPDU, TEID: 101}, uplinkVoice)
	peer := netip.MustParseAddrPort("10.200.0.10:2152")
	forwarder.handleGTP(peer, uplinkGTP)
	wrongFlow := ipv4TransportPacket(ue, remote, 6000, 443)
	wrongGTP, _ := gtpu.Marshal(gtpu.Header{MessageType: gtpu.MessageGPDU, TEID: 101}, wrongFlow)
	forwarder.handleGTP(peer, wrongGTP)

	forwarder.handleTunnel(ipv4TransportPacket(remote, ue, 5061, 5060))
	forwarder.handleTunnel(ipv4TransportPacket(remote, ue, 443, 49152))
	if len(device.written) != 1 || len(sent) != 2 {
		t.Fatalf("writes=%d sent=%d", len(device.written), len(sent))
	}
	voiceHeader, _, err := gtpu.Parse(sent[0].wire)
	if err != nil || voiceHeader.TEID != 201 {
		t.Fatalf("voice downlink header=%#v err=%v", voiceHeader, err)
	}
	defaultHeader, _, err := gtpu.Parse(sent[1].wire)
	if err != nil || defaultHeader.TEID != 200 {
		t.Fatalf("bulk downlink header=%#v err=%v", defaultHeader, err)
	}
	counters := forwarder.Counters()
	if counters.ForwardedPackets != 3 || counters.TFTUnmatched != 1 || counters.DroppedPackets != 1 ||
		counters.URRMeteredPackets != 3 || counters.URRActiveMeters != 2 {
		t.Fatalf("dedicated forwarding counters = %#v usage=%#v", counters, forwarder.Usage())
	}
}

func ipv4Packet(source, destination netip.Addr, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	sourceRaw := source.As4()
	destinationRaw := destination.As4()
	copy(packet[12:16], sourceRaw[:])
	copy(packet[16:20], destinationRaw[:])
	copy(packet[20:], payload)
	return packet
}

func ipv4TransportPacket(source, destination netip.Addr, sourcePort, destinationPort uint16) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:2], sourcePort)
	binary.BigEndian.PutUint16(payload[2:4], destinationPort)
	return ipv4Packet(source, destination, payload)
}
