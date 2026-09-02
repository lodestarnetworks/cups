package dataplane

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
)

func BenchmarkForward(b *testing.B) {
	benchmarkForward(b, false)
}

func BenchmarkForwardPolicy(b *testing.B) {
	benchmarkForward(b, true)
}

func benchmarkForward(b *testing.B, withPolicy bool) {
	store := rules.NewStoreWithLimit(1)
	session := rules.Session{
		CPSEID: 1, UPSEID: 2, UEIPv4: netip.MustParseAddr("10.90.0.2"),
		Local:          rules.Tunnel{TEID: 100, IP: netip.MustParseAddr("10.200.0.20")},
		Remote:         rules.Tunnel{TEID: 200, IP: netip.MustParseAddr("10.200.0.10")},
		UplinkGateOpen: true, DownlinkGateOpen: true,
	}
	if withPolicy {
		session.MaxUplinkBitsPerSecond = 100_000_000_000
		session.MaxDownlinkBitsPerSecond = 100_000_000_000
		session.QERID = 1
		session.URRID = 1
		session.MeasureVolume = true
		session.MeasureDuration = true
		session.UsageReportingThreshold = 1 << 60
	}
	_, err := store.Create(session)
	if err != nil {
		b.Fatal(err)
	}
	forwarder := &Forwarder{
		rules: store, policy: newPolicyEngine(100 * time.Millisecond),
		sendGTP: func([]byte, netip.AddrPort) error { return nil },
	}
	packet := ipv4Packet(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("10.90.0.2"), make([]byte, 492))
	gtpBuffer := make([]byte, len(packet)+8)
	if withPolicy {
		forwarder.handleTunnelInto(packet, gtpBuffer)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		forwarder.handleTunnelInto(packet, gtpBuffer)
	}
}
