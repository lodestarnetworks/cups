package live

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	pfcptransport "github.com/lodestarnetworks/cups/internal/pfcp/transport"
	"github.com/lodestarnetworks/cups/internal/sgwu/dataplane"
	"github.com/lodestarnetworks/cups/internal/sgwu/pfcpserver"
	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpu"
)

func TestCounterDeltaRejectsCounterReset(t *testing.T) {
	if got := counterDelta(3, 9); got != 0 {
		t.Fatalf("counterDelta after reset = %d, want 0", got)
	}
	if got := counterDelta(12, 9); got != 3 {
		t.Fatalf("counterDelta = %d, want 3", got)
	}
}

func TestLatestTrafficAtOnlyAdvancesForForwarding(t *testing.T) {
	previousSample := time.Unix(100, 0).UTC()
	currentSample := time.Unix(101, 0).UTC()
	if got := latestTrafficAt(previousSample, 8, 8, currentSample); !got.Equal(previousSample) {
		t.Fatalf("idle sample changed last traffic to %s", got)
	}
	if got := latestTrafficAt(previousSample, 8, 9, currentSample); !got.Equal(currentSample) {
		t.Fatalf("forwarding sample left last traffic at %s", got)
	}
}

func TestUserProviderReportsLiveRatesCumulativeTrafficAndIdleTimestamp(t *testing.T) {
	accessIP := netip.MustParseAddr("127.126.0.2")
	coreIP := netip.MustParseAddr("127.126.0.3")
	enodebIP := netip.MustParseAddr("127.126.0.4")
	pgwIP := netip.MustParseAddr("127.126.0.5")
	enodeb := listenGTPUPeer(t, enodebIP)
	defer enodeb.Close()
	pgw := listenGTPUPeer(t, pgwIP)
	defer pgw.Close()

	ruleStore := rules.NewStore()
	outerCore := rules.FTEID{TEID: 200, IP: pgwIP}
	outerAccess := rules.FTEID{TEID: 400, IP: enodebIP}
	if _, err := ruleStore.Create(rules.Session{
		CPSEID: 1, UPSEID: 2,
		PDRs: map[uint16]rules.PDR{
			1: {ID: 1, SourceInterface: rules.SourceAccess, LocalFTEID: rules.FTEID{TEID: 100, IP: accessIP}, FARID: 1},
			2: {ID: 2, SourceInterface: rules.SourceCore, LocalFTEID: rules.FTEID{TEID: 300, IP: coreIP}, FARID: 2},
		},
		FARs: map[uint32]rules.FAR{
			1: {ID: 1, ApplyAction: rules.ActionForward, DestinationInterface: rules.DestinationCore, OuterHeader: &outerCore},
			2: {ID: 2, ApplyAction: rules.ActionForward, DestinationInterface: rules.DestinationAccess, OuterHeader: &outerAccess},
		},
		QERs: map[uint32]rules.QER{}, URRs: map[uint32]rules.URR{},
	}); err != nil {
		t.Fatal(err)
	}
	forwarder, err := dataplane.Listen(dataplane.Config{
		Access: netip.AddrPortFrom(accessIP, dataplane.GTPUPort), Core: netip.AddrPortFrom(coreIP, dataplane.GTPUPort),
		AllowedAccessPeers: []netip.Addr{enodebIP}, AllowedCorePeers: []netip.Addr{pgwIP},
	}, ruleStore)
	if err != nil {
		t.Fatal(err)
	}
	server, err := pfcpserver.New(pfcpserver.Config{
		Listen: netip.MustParseAddrPort("127.126.0.6:0"), Advertise: netip.MustParseAddr("127.126.0.6"),
		AccessUserIP: accessIP, CoreUserIP: coreIP, AllowedCP: []netip.Addr{netip.MustParseAddr("127.126.0.7")},
		Transport: pfcptransport.DefaultConfig(),
	}, ruleStore)
	if err != nil {
		_ = forwarder.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- forwarder.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		_ = forwarder.Close()
		<-done
	})
	provider := NewUserProvider(time.Now().UTC().Add(-time.Minute), server, ruleStore, forwarder, nil)
	payload := []byte{0x45, 0, 0, 20, 1, 2, 3, 4}
	sendAndReceiveGTPU(t, enodeb, forwarder.AccessAddr(), pgw, 100, 200, payload)
	sendAndReceiveGTPU(t, pgw, forwarder.CoreAddr(), enodeb, 300, 400, payload)
	waitForForwardedPackets(t, forwarder, 2)

	sampledAt := provider.last.Add(time.Second)
	provider.sample(sampledAt)
	snapshot := provider.Snapshot()
	wantRate := uint64(len(payload) * 8)
	if snapshot.SGWU.UplinkBitsPerSecond != wantRate || snapshot.SGWU.DownlinkBitsPerSecond != wantRate ||
		snapshot.SGWU.ForwardedPackets != 2 || snapshot.SGWU.ForwardedBytes != uint64(len(payload)*2) {
		t.Fatalf("live traffic snapshot = %#v", snapshot.SGWU)
	}
	if snapshot.SGWU.LastTrafficAt == nil || !snapshot.SGWU.LastTrafficAt.Equal(sampledAt) {
		t.Fatalf("last traffic timestamp = %v, want %s", snapshot.SGWU.LastTrafficAt, sampledAt)
	}
	if len(snapshot.History) == 0 || snapshot.History[len(snapshot.History)-1].UplinkBitsPerSecond != wantRate {
		t.Fatalf("live traffic history = %#v", snapshot.History)
	}

	provider.sample(sampledAt.Add(time.Second))
	idle := provider.Snapshot()
	if idle.SGWU.UplinkBitsPerSecond != 0 || idle.SGWU.DownlinkBitsPerSecond != 0 ||
		idle.SGWU.ForwardedBytes != snapshot.SGWU.ForwardedBytes || idle.SGWU.LastTrafficAt == nil ||
		!idle.SGWU.LastTrafficAt.Equal(sampledAt) {
		t.Fatalf("idle sample lost cumulative traffic state: %#v", idle.SGWU)
	}
}

func waitForForwardedPackets(t *testing.T, forwarder *dataplane.Forwarder, expected uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if forwarder.Counters().ForwardedPackets >= expected {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("forwarded packets = %d, want at least %d", forwarder.Counters().ForwardedPackets, expected)
}

func listenGTPUPeer(t *testing.T, address netip.Addr) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, dataplane.GTPUPort)))
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func sendAndReceiveGTPU(t *testing.T, sender *net.UDPConn, destination netip.AddrPort, receiver *net.UDPConn, incomingTEID, outgoingTEID uint32, payload []byte) {
	t.Helper()
	wire, err := gtpu.Marshal(gtpu.Header{Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: incomingTEID}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.WriteToUDPAddrPort(wire, destination); err != nil {
		t.Fatal(err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2_000)
	n, _, err := receiver.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	header, gotPayload, err := gtpu.Parse(buffer[:n])
	if err != nil || header.TEID != outgoingTEID || string(gotPayload) != string(payload) {
		t.Fatalf("forwarded GTP-U packet header=%#v payload=%x error=%v", header, gotPayload, err)
	}
}
