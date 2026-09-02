package dataplane

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpu"
)

type blockingCloseFastPath struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (*blockingCloseFastPath) Mode() string               { return "blocking-test" }
func (*blockingCloseFastPath) Counters() FastPathCounters { return FastPathCounters{} }
func (*blockingCloseFastPath) Usage() []UsageMeasurement  { return nil }
func (*blockingCloseFastPath) SessionChanged(uint64)      {}
func (*blockingCloseFastPath) SessionDeleted(uint64)      {}
func (f *blockingCloseFastPath) Close() error {
	f.once.Do(func() { close(f.entered) })
	<-f.release
	return nil
}

func TestCloseReleasesUDPListenersBeforeFastPathTeardown(t *testing.T) {
	access, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	core, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = access.Close()
		t.Fatal(err)
	}
	accessAddress := access.LocalAddr().(*net.UDPAddr)
	coreAddress := core.LocalAddr().(*net.UDPAddr)
	fast := &blockingCloseFastPath{entered: make(chan struct{}), release: make(chan struct{})}
	forwarder := &Forwarder{access: access, core: core, fastPath: fast, closed: make(chan struct{})}

	done := make(chan error, 1)
	go func() { done <- forwarder.Close() }()
	select {
	case <-fast.entered:
	case <-time.After(time.Second):
		t.Fatal("fast-path teardown was not entered")
	}

	reboundAccess, err := net.ListenUDP("udp4", accessAddress)
	if err != nil {
		close(fast.release)
		t.Fatalf("access listener was retained during fast-path teardown: %v", err)
	}
	_ = reboundAccess.Close()
	reboundCore, err := net.ListenUDP("udp4", coreAddress)
	if err != nil {
		close(fast.release)
		t.Fatalf("core listener was retained during fast-path teardown: %v", err)
	}
	_ = reboundCore.Close()
	close(fast.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestBidirectionalGTPUForwarding(t *testing.T) {
	accessIP := netip.MustParseAddr("127.77.0.2")
	coreIP := netip.MustParseAddr("127.77.0.3")
	enbIP := netip.MustParseAddr("127.77.0.4")
	pgwIP := netip.MustParseAddr("127.77.0.5")

	enb := listenTestUDP(t, enbIP)
	defer enb.Close()
	pgw := listenTestUDP(t, pgwIP)
	defer pgw.Close()

	store := rules.NewStore()
	outerCore := rules.FTEID{TEID: 200, IP: pgwIP}
	outerAccess := rules.FTEID{TEID: 400, IP: enbIP}
	_, err := store.Create(rules.Session{
		CPSEID: 1,
		UPSEID: 2,
		PDRs: map[uint16]rules.PDR{
			1: {ID: 1, SourceInterface: rules.SourceAccess, LocalFTEID: rules.FTEID{TEID: 100, IP: accessIP}, FARID: 1},
			2: {ID: 2, SourceInterface: rules.SourceCore, LocalFTEID: rules.FTEID{TEID: 300, IP: coreIP}, FARID: 2},
		},
		FARs: map[uint32]rules.FAR{
			1: {ID: 1, ApplyAction: rules.ActionForward, DestinationInterface: rules.DestinationCore, OuterHeader: &outerCore},
			2: {ID: 2, ApplyAction: rules.ActionForward, DestinationInterface: rules.DestinationAccess, OuterHeader: &outerAccess},
		},
		QERs: map[uint32]rules.QER{},
		URRs: map[uint32]rules.URR{},
	})
	if err != nil {
		t.Fatal(err)
	}

	forwarder, err := Listen(Config{
		Access: netip.AddrPortFrom(accessIP, GTPUPort), Core: netip.AddrPortFrom(coreIP, GTPUPort),
		AllowedAccessPeers: []netip.Addr{enbIP}, AllowedCorePeers: []netip.Addr{pgwIP},
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- forwarder.Serve(ctx) }()

	uplink := mustGPDU(t, 100, []byte{0x45, 0, 0, 20, 1, 2, 3, 4})
	if _, err := enb.WriteToUDPAddrPort(uplink, forwarder.AccessAddr()); err != nil {
		t.Fatal(err)
	}
	assertForwarded(t, pgw, 200, uplinkPayload(t, uplink))

	downlink := mustGPDU(t, 300, []byte{0x45, 0, 0, 20, 5, 6, 7, 8})
	if _, err := pgw.WriteToUDPAddrPort(downlink, forwarder.CoreAddr()); err != nil {
		t.Fatal(err)
	}
	assertForwarded(t, enb, 400, uplinkPayload(t, downlink))

	deadline := time.Now().Add(time.Second)
	var counters Counters
	for time.Now().Before(deadline) {
		counters = forwarder.Counters()
		if counters.ForwardedPackets == 2 && counters.UplinkBytes > 0 && counters.DownlinkBytes > 0 && counters.P95LatencyMicros > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if counters.ForwardedPackets != 2 || counters.ForwardedBytes == 0 || counters.UplinkBytes == 0 || counters.DownlinkBytes == 0 || counters.P95LatencyMicros == 0 || counters.DroppedPackets != 0 {
		t.Fatalf("unexpected counters after forwarding completion: %#v", counters)
	}

	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("forwarder did not stop")
	}
}

func TestForwardingPreservesOptionalAndExtensionHeaders(t *testing.T) {
	accessIP := netip.MustParseAddr("127.77.4.2")
	coreIP := netip.MustParseAddr("127.77.4.3")
	enbIP := netip.MustParseAddr("127.77.4.4")
	pgwIP := netip.MustParseAddr("127.77.4.5")
	pgw := listenTestUDP(t, pgwIP)
	defer pgw.Close()

	store := rules.NewStore()
	outerCore := rules.FTEID{TEID: 0xaabbccdd, IP: pgwIP}
	if _, err := store.Create(rules.Session{
		CPSEID: 1, UPSEID: 2,
		PDRs: map[uint16]rules.PDR{
			1: {ID: 1, SourceInterface: rules.SourceAccess, LocalFTEID: rules.FTEID{TEID: 100, IP: accessIP}, FARID: 1},
		},
		FARs: map[uint32]rules.FAR{
			1: {ID: 1, ApplyAction: rules.ActionForward, DestinationInterface: rules.DestinationCore, OuterHeader: &outerCore},
		},
		QERs: map[uint32]rules.QER{}, URRs: map[uint32]rules.URR{},
	}); err != nil {
		t.Fatal(err)
	}
	forwarder, err := Listen(Config{
		Access: netip.AddrPortFrom(accessIP, GTPUPort), Core: netip.AddrPortFrom(coreIP, GTPUPort),
		AllowedAccessPeers: []netip.Addr{enbIP}, AllowedCorePeers: []netip.Addr{pgwIP},
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- forwarder.Serve(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	enb, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(enbIP, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer enb.Close()
	payload := []byte{0x45, 0, 0, 20, 1, 2, 3, 4}
	wire, err := gtpu.Marshal(gtpu.Header{
		Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: 100,
		Sequence: true, SequenceNumber: 0x1234, NPDU: true, NPDUNumber: 9,
		ExtensionHeaders: []gtpu.ExtensionHeader{{Type: 0x85, Content: []byte{7, 8}}},
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), wire...)
	binary.BigEndian.PutUint32(want[4:8], outerCore.TEID)
	if _, err := enb.WriteToUDPAddrPort(wire, forwarder.AccessAddr()); err != nil {
		t.Fatal(err)
	}
	_ = pgw.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, 1500)
	n, _, err := pgw.ReadFromUDPAddrPort(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], want) {
		t.Fatalf("forwarded frame changed outside TEID\ngot  %x\nwant %x", got[:n], want)
	}
}

func TestQERBitrateAndURRTelemetryOnForwardingPath(t *testing.T) {
	accessIP := netip.MustParseAddr("127.77.5.2")
	coreIP := netip.MustParseAddr("127.77.5.3")
	enbIP := netip.MustParseAddr("127.77.5.4")
	pgwIP := netip.MustParseAddr("127.77.5.5")
	enb := listenTestUDP(t, enbIP)
	defer enb.Close()
	pgw := listenTestUDP(t, pgwIP)
	defer pgw.Close()

	store := rules.NewStore()
	outer := rules.FTEID{TEID: 200, IP: pgwIP}
	if _, err := store.Create(rules.Session{
		CPSEID: 1, UPSEID: 2,
		PDRs: map[uint16]rules.PDR{1: {
			ID: 1, SourceInterface: rules.SourceAccess,
			LocalFTEID: rules.FTEID{TEID: 100, IP: accessIP}, FARID: 1,
			QERIDs: []uint32{1}, URRIDs: []uint32{1},
		}},
		FARs: map[uint32]rules.FAR{1: {
			ID: 1, ApplyAction: rules.ActionForward,
			DestinationInterface: rules.DestinationCore, OuterHeader: &outer,
		}},
		QERs: map[uint32]rules.QER{1: {
			ID: 1, UplinkGateOpen: true, DownlinkGateOpen: true,
			MaxUplinkBitsPerSecond: 80_000,
		}},
		URRs: map[uint32]rules.URR{1: {
			ID: 1, MeasureVolume: true, MeasureDuration: true, ReportingThreshold: 1_500,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	forwarder, err := Listen(Config{
		Access: netip.AddrPortFrom(accessIP, GTPUPort), Core: netip.AddrPortFrom(coreIP, GTPUPort),
		AllowedAccessPeers: []netip.Addr{enbIP}, AllowedCorePeers: []netip.Addr{pgwIP},
		QERBurstDuration: 100 * time.Millisecond,
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- forwarder.Serve(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	payload := make([]byte, 1_000)
	wire := mustGPDU(t, 100, payload)
	if _, err := enb.WriteToUDPAddrPort(wire, forwarder.AccessAddr()); err != nil {
		t.Fatal(err)
	}
	assertForwarded(t, pgw, 200, payload)
	if _, err := enb.WriteToUDPAddrPort(wire, forwarder.AccessAddr()); err != nil {
		t.Fatal(err)
	}
	_ = pgw.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err := pgw.ReadFromUDPAddrPort(make([]byte, 2_000)); err == nil {
		t.Fatal("over-limit QER packet was forwarded")
	}
	time.Sleep(110 * time.Millisecond)
	if _, err := enb.WriteToUDPAddrPort(wire, forwarder.AccessAddr()); err != nil {
		t.Fatal(err)
	}
	assertForwarded(t, pgw, 200, payload)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		counters := forwarder.Counters()
		if counters.ForwardedPackets == 2 && counters.QERRateDrops == 1 && counters.URRMeteredPackets == 2 {
			if counters.URRMeteredBytes != 2_000 || counters.URRThresholdEvents != 1 || counters.URRActiveMeters != 1 || counters.DroppedPackets != 1 {
				t.Fatalf("unexpected policy counters: %+v", counters)
			}
			usage := forwarder.Usage()
			if len(usage) != 1 || usage[0].UplinkBytes != 2_000 || usage[0].ThresholdEvents != 1 {
				t.Fatalf("unexpected usage telemetry: %+v", usage)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("policy counters did not settle: %+v", forwarder.Counters())
}

func TestEchoAndUnknownTEID(t *testing.T) {
	accessIP := netip.MustParseAddr("127.77.1.2")
	coreIP := netip.MustParseAddr("127.77.1.3")
	peerIP := netip.MustParseAddr("127.77.1.4")
	store := rules.NewStore()
	forwarder, err := Listen(Config{
		Access: netip.AddrPortFrom(accessIP, GTPUPort), Core: netip.AddrPortFrom(coreIP, GTPUPort),
		AllowedAccessPeers: []netip.Addr{peerIP}, AllowedCorePeers: []netip.Addr{peerIP},
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- forwarder.Serve(ctx) }()
	defer func() {
		cancel()
		<-serveDone
	}()

	peer, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerIP, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	echo, err := gtpu.Marshal(gtpu.Header{Version: gtpu.Version, ProtocolType: true, Sequence: true, MessageType: gtpu.MessageEchoRequest, SequenceNumber: 99}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDPAddrPort(echo, forwarder.AccessAddr()); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1500)
	n, _, err := peer.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := gtpu.Parse(buffer[:n])
	if err != nil || header.MessageType != gtpu.MessageEchoResponse || header.SequenceNumber != 99 || len(payload) != 2 {
		t.Fatalf("unexpected echo response header=%#v payload=%x err=%v", header, payload, err)
	}

	unknown := mustGPDU(t, 0xdeadbeef, []byte{0x45, 0, 0, 20})
	if _, err := peer.WriteToUDPAddrPort(unknown, forwarder.AccessAddr()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if forwarder.Counters().UnknownTEIDs == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("unknown TEID was not counted")
}

func TestRejectsGTPUFromNonAllowlistedPeer(t *testing.T) {
	accessIP := netip.MustParseAddr("127.77.2.2")
	coreIP := netip.MustParseAddr("127.77.2.3")
	attackerIP := netip.MustParseAddr("127.77.2.4")
	allowedIP := netip.MustParseAddr("127.77.2.5")
	forwarder, err := Listen(Config{
		Access: netip.AddrPortFrom(accessIP, GTPUPort), Core: netip.AddrPortFrom(coreIP, GTPUPort),
		AllowedAccessPeers: []netip.Addr{allowedIP}, AllowedCorePeers: []netip.Addr{allowedIP},
	}, rules.NewStore())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- forwarder.Serve(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	attacker, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(attackerIP, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	echo, err := gtpu.Marshal(gtpu.Header{
		Version: gtpu.Version, ProtocolType: true, Sequence: true,
		MessageType: gtpu.MessageEchoRequest, SequenceNumber: 7,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attacker.WriteToUDPAddrPort(echo, forwarder.AccessAddr()); err != nil {
		t.Fatal(err)
	}
	_ = attacker.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := attacker.ReadFromUDPAddrPort(make([]byte, 256)); err == nil {
		t.Fatal("non-allowlisted peer received an echo response")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		counters := forwarder.Counters()
		if counters.UnauthorizedPeers == 1 && counters.DroppedPackets == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("unauthorized packet was not counted: %#v", forwarder.Counters())
}

func listenTestUDP(t *testing.T, addr netip.Addr) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, GTPUPort)))
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func mustGPDU(t *testing.T, teid uint32, payload []byte) []byte {
	t.Helper()
	wire, err := gtpu.Marshal(gtpu.Header{Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: teid}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func uplinkPayload(t *testing.T, packet []byte) []byte {
	t.Helper()
	_, payload, err := gtpu.Parse(packet)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func assertForwarded(t *testing.T, conn *net.UDPConn, wantTEID uint32, wantPayload []byte) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 65_535)
	n, _, err := conn.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := gtpu.Parse(buffer[:n])
	if err != nil {
		t.Fatal(err)
	}
	if header.TEID != wantTEID || string(payload) != string(wantPayload) {
		t.Fatalf("unexpected forwarded packet: header=%#v payload=%x", header, payload)
	}
}
