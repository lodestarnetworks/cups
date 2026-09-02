package dataplane

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpu"
)

func BenchmarkForwardSGWU(b *testing.B) {
	benchmarkForwardSGWU(b, false)
}

func BenchmarkForwardSGWUPolicy(b *testing.B) {
	benchmarkForwardSGWU(b, true)
}

func benchmarkForwardSGWU(b *testing.B, withPolicy bool) {
	accessIP := netip.MustParseAddr("10.200.0.10")
	coreIP := netip.MustParseAddr("10.200.0.20")
	enbIP := netip.MustParseAddr("10.200.0.30")
	pgwIP := netip.MustParseAddr("10.200.0.40")
	outer := rules.FTEID{TEID: 200, IP: pgwIP}
	store := rules.NewStoreWithLimit(1)
	pdr := rules.PDR{ID: 1, SourceInterface: rules.SourceAccess, LocalFTEID: rules.FTEID{TEID: 100, IP: accessIP}, FARID: 1}
	qers := map[uint32]rules.QER{}
	urrs := map[uint32]rules.URR{}
	if withPolicy {
		pdr.QERIDs = []uint32{1}
		pdr.URRIDs = []uint32{1}
		qers[1] = rules.QER{
			ID: 1, UplinkGateOpen: true, DownlinkGateOpen: true,
			MaxUplinkBitsPerSecond: 100_000_000_000, MaxDownlinkBitsPerSecond: 100_000_000_000,
			QCI: 9, ARP: 9,
		}
		urrs[1] = rules.URR{ID: 1, MeasureVolume: true, MeasureDuration: true, ReportingThreshold: 1 << 60}
	}
	_, err := store.Create(rules.Session{
		CPSEID: 1, UPSEID: 2,
		PDRs: map[uint16]rules.PDR{
			1: pdr,
		},
		FARs: map[uint32]rules.FAR{
			1: {ID: 1, ApplyAction: rules.ActionForward, DestinationInterface: rules.DestinationCore, OuterHeader: &outer},
		},
		QERs: qers, URRs: urrs,
	})
	if err != nil {
		b.Fatal(err)
	}
	forwarder := &Forwarder{
		rules: store, allowedAccess: map[netip.Addr]struct{}{enbIP: {}}, allowedCore: map[netip.Addr]struct{}{pgwIP: {}},
		policy: newPolicyEngine(100 * time.Millisecond),
	}
	wire, err := gtpu.Marshal(gtpu.Header{ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: 100}, make([]byte, 512))
	if err != nil {
		b.Fatal(err)
	}
	peer := netip.AddrPortFrom(enbIP, GTPUPort)
	if withPolicy {
		output, ok := forwarder.prepare(rules.SourceAccess, peer, wire)
		if !ok || !output.forwarded {
			b.Fatal("policy warm-up packet was not forwarded")
		}
		forwarder.policy.recordUsage(output.matched, output.source, output.payloadBytes, time.Now())
	}
	b.ReportAllocs()
	b.SetBytes(512)
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		binary.BigEndian.PutUint32(wire[4:8], 100)
		output, ok := forwarder.prepare(rules.SourceAccess, peer, wire)
		if !ok || !output.forwarded || output.destination.Addr() != pgwIP || output.side != rules.DestinationCore {
			b.Fatal("packet was not forwarded")
		}
		if withPolicy {
			forwarder.metrics.forwardedPackets.Add(1)
			forwarder.metrics.forwardedBytes.Add(uint64(output.payloadBytes))
			forwarder.metrics.uplinkBytes.Add(uint64(output.payloadBytes))
			forwarder.policy.recordUsage(output.matched, output.source, output.payloadBytes, time.Now())
			forwarder.recordLatency(time.Since(output.started))
		}
	}
	_ = coreIP
}
