//go:build linux

package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/lodestarnetworks/cups/internal/kernelgtp"
	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
	"github.com/lodestarnetworks/cups/pkg/gtpu"
	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

// TestKernelPolicyDedicatedBearerIntegration exercises the complete hybrid
// datapath in a disposable namespace: kernel-GTP contexts on two devices,
// nftables/FIB TFT routing, TCX wrong-bearer rejection,
// directional gates, QER rate enforcement, and per-bearer URR counters.
func TestKernelPolicyDedicatedBearerIntegration(t *testing.T) {
	if os.Getenv("SGW_NEXT_KERNEL_GTP_TEST") != "1" {
		t.Skip("kernel policy integration test requires a disposable network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel policy integration test requires root")
	}

	defaultOuter := netip.MustParseAddr("10.254.77.1")
	peerOuter := netip.MustParseAddr("10.254.77.2")
	serviceIP := netip.MustParseAddr("10.254.77.3")
	qci1Outer := netip.MustParseAddr("10.254.77.4")
	ueIP := netip.MustParseAddr("10.254.200.7")
	suffix := os.Getpid() % 100_000
	forwarder, err := OpenKernel(KernelConfig{
		S5:              netip.AddrPortFrom(defaultOuter, kernelgtp.GTPUPort),
		QCI1S5:          netip.AddrPortFrom(qci1Outer, kernelgtp.GTPUPort),
		AllowedSGWPeers: []netip.Addr{peerOuter},
		TunnelName:      fmt.Sprintf("lodpd%d", suffix), QCI1TunnelName: fmt.Sprintf("lodp1%d", suffix),
		OwnershipFile: filepath.Join(t.TempDir(), "default.owner"), QCI1OwnershipFile: filepath.Join(t.TempDir(), "qci1.owner"),
		UEPoolPrefix: netip.MustParsePrefix("10.254.200.0/24"), UEGateway: netip.MustParseAddr("10.254.200.1"),
		HashSize: 4_096, MTU: 1_400, SocketBufferBytes: 4 * 1024 * 1024,
		MaxSessions: 100, MaxPolicyFilters: 1_024, QERBurstDuration: 100 * time.Millisecond,
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Fatalf("%-100v", verifier)
		}
		t.Fatal(err)
	}
	defer forwarder.Close()

	store := rules.NewStoreWithApplier(100, forwarder)
	session := kernelPolicyTestSession(defaultOuter, qci1Outer, peerOuter, ueIP)
	created, err := store.Create(session)
	if err != nil {
		t.Fatal(err)
	}

	peer, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerOuter, kernelgtp.GTPUPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	service, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(serviceIP, 5_061)))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	assertDownlink := func(localPort uint16, payloadBytes int, expectedSource netip.Addr, expectedTEID uint32) {
		t.Helper()
		payload := make([]byte, payloadBytes)
		copy(payload, "lodestar-kernel-policy")
		if _, err := service.WriteToUDPAddrPort(payload, netip.AddrPortFrom(ueIP, localPort)); err != nil {
			t.Fatal(err)
		}
		if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 2_048)
		n, source, err := peer.ReadFromUDPAddrPort(buffer)
		if err != nil {
			t.Fatal(err)
		}
		header, inner, err := gtpu.Parse(buffer[:n])
		if err != nil {
			t.Fatal(err)
		}
		if source.Addr().Unmap() != expectedSource || header.TEID != expectedTEID {
			t.Fatalf("downlink local port %d source=%s TEID=%d, want %s/%d", localPort, source.Addr(), header.TEID, expectedSource, expectedTEID)
		}
		if len(inner) != 20+8+payloadBytes {
			t.Fatalf("downlink inner length=%d, want %d", len(inner), 20+8+payloadBytes)
		}
	}
	assertNoDownlink := func(localPort uint16, payloadBytes int) {
		t.Helper()
		payload := make([]byte, payloadBytes)
		copy(payload, "must-be-dropped")
		_, writeErr := service.WriteToUDPAddrPort(payload, netip.AddrPortFrom(ueIP, localPort))
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		if err := peer.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 2_048)
		if _, _, err := peer.ReadFromUDPAddrPort(buffer); err == nil {
			t.Fatal("closed QCI 1 downlink gate forwarded a packet")
		} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatalf("wait for closed-gate drop: %v", err)
		}
	}
	assertFragmentedDownlink := func() {
		t.Helper()
		payload := make([]byte, 3_000)
		copy(payload, "fragmented-qci1-downlink")
		if _, err := service.WriteToUDPAddrPort(payload, netip.AddrPortFrom(ueIP, 5_060)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 4_096)
		fragments := 0
		var identification uint16
		for {
			if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			n, source, err := peer.ReadFromUDPAddrPort(buffer)
			if err != nil {
				t.Fatalf("fragment %d read: %v counters=%+v", fragments, err, forwarder.Counters())
			}
			header, inner, err := gtpu.Parse(buffer[:n])
			if err != nil {
				t.Fatal(err)
			}
			if source.Addr().Unmap() != qci1Outer || header.TEID != 2_002 || len(inner) < 20 {
				t.Fatalf("fragmented downlink escaped QCI 1: source=%s TEID=%d inner=%d", source.Addr(), header.TEID, len(inner))
			}
			currentID := binary.BigEndian.Uint16(inner[4:6])
			fragmentBits := binary.BigEndian.Uint16(inner[6:8])
			if fragments == 0 {
				identification = currentID
				if fragmentBits&0x1fff != 0 || fragmentBits&0x2000 == 0 {
					t.Fatalf("first downlink fragment flags=%#x", fragmentBits)
				}
			} else if currentID != identification || fragmentBits&0x1fff == 0 {
				t.Fatalf("downlink fragment %d id=%d flags=%#x, want id=%d non-zero offset", fragments, currentID, fragmentBits, identification)
			}
			fragments++
			if fragmentBits&0x2000 == 0 {
				break
			}
		}
		if fragments < 2 {
			t.Fatalf("large QCI 1 downlink produced %d fragment", fragments)
		}
	}

	assertDownlink(5_060, 32, qci1Outer, 2_002)
	assertDownlink(6_000, 32, defaultOuter, 2_001)
	assertFragmentedDownlink()

	// A missing route selector must never let a TFT-matched packet escape on
	// the default TEID. TCX on the default GTP egress is the independent
	// fail-closed guard for nftables/FIB drift.
	if err := forwarder.policy.ApplyRouting(&created, nil); err != nil {
		t.Fatal(err)
	}
	assertNoDownlink(5_060, 32)
	if err := forwarder.policy.ApplyRouting(nil, &created); err != nil {
		t.Fatal(err)
	}
	assertDownlink(5_060, 32, qci1Outer, 2_002)

	changedTFT, err := store.Update(created.UPSEID, created.Revision, func(candidate *rules.Session) error {
		for index := range candidate.DedicatedBearers[0].Filters {
			filter := &candidate.DedicatedBearers[0].Filters[index]
			if filter.Filter.AppliesTo(gtpv2.TFTDirectionDownlink) {
				filter.Filter.LocalPortLow, filter.Filter.LocalPortHigh = 5_070, 5_070
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertDownlink(5_060, 32, defaultOuter, 2_001)
	assertDownlink(5_070, 32, qci1Outer, 2_002)
	created, err = store.Update(changedTFT.UPSEID, changedTFT.Revision, func(candidate *rules.Session) error {
		for index := range candidate.DedicatedBearers[0].Filters {
			filter := &candidate.DedicatedBearers[0].Filters[index]
			if filter.Filter.AppliesTo(gtpv2.TFTDirectionDownlink) {
				filter.Filter.LocalPortLow, filter.Filter.LocalPortHigh = 5_060, 5_060
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertDownlink(5_060, 32, qci1Outer, 2_002)

	voiceUplink := kernelPolicyIPv4UDP(ueIP, serviceIP, 5_060, 5_061, []byte("voice-uplink"))
	voiceGTP, err := gtpu.Marshal(gtpu.Header{Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: 1_002}, voiceUplink)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDPAddrPort(voiceGTP, netip.AddrPortFrom(qci1Outer, kernelgtp.GTPUPort)); err != nil {
		t.Fatal(err)
	}
	if err := service.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	uplinkBuffer := make([]byte, 256)
	if n, _, err := service.ReadFromUDPAddrPort(uplinkBuffer); err != nil || string(uplinkBuffer[:n]) != "voice-uplink" {
		t.Fatalf("QCI 1 uplink payload=%q err=%v counters=%+v", uplinkBuffer[:max(n, 0)], err, forwarder.Counters())
	}

	fragmentedPayload := make([]byte, 3_000)
	copy(fragmentedPayload, "fragmented-qci1-uplink")
	fragmentedUplink := kernelPolicyIPv4UDP(ueIP, serviceIP, 5_060, 5_061, fragmentedPayload)
	binary.BigEndian.PutUint16(fragmentedUplink[4:6], 78)
	uplinkFragments := kernelPolicyIPv4Fragments(fragmentedUplink, 1_376)
	orphanGTP, err := gtpu.Marshal(gtpu.Header{Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: 1_002}, uplinkFragments[1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDPAddrPort(orphanGTP, netip.AddrPortFrom(qci1Outer, kernelgtp.GTPUPort)); err != nil {
		t.Fatal(err)
	}
	if err := service.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.ReadFromUDPAddrPort(make([]byte, 4_096)); err == nil {
		t.Fatal("orphan non-initial QCI 1 fragment reached the IP stack")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("wait for orphan-fragment drop: %v", err)
	}
	for _, inner := range uplinkFragments {
		packet, err := gtpu.Marshal(gtpu.Header{Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: 1_002}, inner)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := peer.WriteToUDPAddrPort(packet, netip.AddrPortFrom(qci1Outer, kernelgtp.GTPUPort)); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	fragmentedReceived := make([]byte, 4_096)
	const fragmentedPrefix = "fragmented-qci1-uplink"
	if n, _, err := service.ReadFromUDPAddrPort(fragmentedReceived); err != nil || n != len(fragmentedPayload) || string(fragmentedReceived[:min(max(n, 0), len(fragmentedPrefix))]) != fragmentedPrefix {
		t.Fatalf("fragmented QCI 1 uplink bytes=%d prefix=%q err=%v", n, fragmentedReceived[:min(max(n, 0), len(fragmentedPrefix))], err)
	}

	wrongBearerGTP, err := gtpu.Marshal(gtpu.Header{Version: gtpu.Version, ProtocolType: true, MessageType: gtpu.MessageGPDU, TEID: 1_001}, voiceUplink)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDPAddrPort(wrongBearerGTP, netip.AddrPortFrom(defaultOuter, kernelgtp.GTPUPort)); err != nil {
		t.Fatal(err)
	}
	if err := service.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.ReadFromUDPAddrPort(uplinkBuffer); err == nil {
		t.Fatal("voice TFT packet bypassed QCI 1 on the default uplink bearer")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("wait for wrong-bearer drop: %v", err)
	}

	closed, err := store.Update(created.UPSEID, created.Revision, func(candidate *rules.Session) error {
		candidate.DedicatedBearers[0].DownlinkGateOpen = false
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertNoDownlink(5_060, 32)

	rateLimited, err := store.Update(closed.UPSEID, closed.Revision, func(candidate *rules.Session) error {
		candidate.DedicatedBearers[0].DownlinkGateOpen = true
		candidate.DedicatedBearers[0].MaxDownlinkBitsPerSecond = 8_000
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertDownlink(5_060, 1_000, qci1Outer, 2_002)
	assertNoDownlink(5_060, 1_000)
	if rateLimited.Revision <= created.Revision {
		t.Fatalf("policy revision did not advance: %d -> %d", created.Revision, rateLimited.Revision)
	}

	counters := forwarder.Counters()
	if counters.QERGateDrops == 0 || counters.QERRateDrops == 0 || counters.TFTUnmatched == 0 || counters.FragmentDrops == 0 || counters.URRMeteredPackets == 0 || counters.URRActiveMeters != 2 {
		t.Fatalf("kernel policy counters = %+v", counters)
	}
	usage := forwarder.Usage()
	if len(usage) != 2 || usage[1].QCI != 1 || usage[1].DownlinkPackets == 0 || usage[1].UplinkPackets == 0 {
		t.Fatalf("kernel policy usage = %+v", usage)
	}
}

func TestKernelPolicyDedicatedBearerChurnIntegration(t *testing.T) {
	if os.Getenv("SGW_NEXT_KERNEL_GTP_TEST") != "1" {
		t.Skip("kernel policy churn test requires a disposable network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel policy churn test requires root")
	}
	const sessionCount = 512
	defaultOuter := netip.MustParseAddr("10.254.77.1")
	peerOuter := netip.MustParseAddr("10.254.77.2")
	qci1Outer := netip.MustParseAddr("10.254.77.4")
	suffix := os.Getpid() % 100_000
	forwarder, err := OpenKernel(KernelConfig{
		S5:              netip.AddrPortFrom(defaultOuter, kernelgtp.GTPUPort),
		QCI1S5:          netip.AddrPortFrom(qci1Outer, kernelgtp.GTPUPort),
		AllowedSGWPeers: []netip.Addr{peerOuter},
		TunnelName:      fmt.Sprintf("lodcd%d", suffix), QCI1TunnelName: fmt.Sprintf("lodc1%d", suffix),
		OwnershipFile: filepath.Join(t.TempDir(), "default.owner"), QCI1OwnershipFile: filepath.Join(t.TempDir(), "qci1.owner"),
		UEPoolPrefix: netip.MustParsePrefix("10.254.200.0/16"), UEGateway: netip.MustParseAddr("10.254.200.1"),
		HashSize: 4_096, MTU: 1_400, SocketBufferBytes: 4 * 1024 * 1024,
		MaxSessions: sessionCount, MaxPolicyFilters: sessionCount * 4, QERBurstDuration: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer forwarder.Close()
	store := rules.NewStoreWithApplier(sessionCount, forwarder)
	installed := make([]rules.Session, 0, sessionCount)
	started := time.Now()
	for index := 0; index < sessionCount; index++ {
		raw := [4]byte{10, 254, byte(200 + index/254), byte(index%254 + 2)}
		candidate := kernelPolicyTestSession(defaultOuter, qci1Outer, peerOuter, netip.AddrFrom4(raw))
		candidate.CPSEID, candidate.UPSEID = uint64(index)*2+1, uint64(index)*2+2
		candidate.Local.TEID, candidate.Remote.TEID = uint32(10_000+index), uint32(20_000+index)
		candidate.DedicatedBearers[0].Local.TEID = uint32(30_000 + index)
		candidate.DedicatedBearers[0].Remote.TEID = uint32(40_000 + index)
		created, err := store.Create(candidate)
		if err != nil {
			t.Fatalf("create session %d: %v", index, err)
		}
		installed = append(installed, created)
	}
	createDuration := time.Since(started)
	started = time.Now()
	for index := range installed {
		updated, err := store.Update(installed[index].UPSEID, installed[index].Revision, func(candidate *rules.Session) error {
			candidate.DedicatedBearers[0].DownlinkGateOpen = false
			candidate.DedicatedBearers[0].MaxUplinkBitsPerSecond += 1_000
			return nil
		})
		if err != nil {
			t.Fatalf("update session %d: %v", index, err)
		}
		installed[index] = updated
	}
	updateDuration := time.Since(started)
	started = time.Now()
	for index := len(installed) - 1; index >= 0; index-- {
		if err := store.Delete(installed[index].UPSEID, installed[index].Revision); err != nil {
			t.Fatalf("delete session %d: %v", index, err)
		}
	}
	deleteDuration := time.Since(started)
	if store.Count() != 0 || len(forwarder.Usage()) != 0 || forwarder.Counters().URRActiveMeters != 0 {
		t.Fatalf("dedicated-bearer churn leaked state: sessions=%d usage=%+v counters=%+v", store.Count(), forwarder.Usage(), forwarder.Counters())
	}
	t.Logf("512 dual-bearer sessions: create=%.3f ms update=%.3f ms delete=%.3f ms", float64(createDuration.Microseconds())/1_000, float64(updateDuration.Microseconds())/1_000, float64(deleteDuration.Microseconds())/1_000)
}

func kernelPolicyTestSession(defaultOuter, qci1Outer, peerOuter, ueIP netip.Addr) rules.Session {
	filter := func(id uint8, direction gtpv2.TFTDirection, pdr uint16) rules.FlowFilter {
		return rules.FlowFilter{
			PDRID: pdr, Precedence: 10, Direction: direction,
			Filter: gtpv2.IPv4PacketFilter{
				ID: id, Direction: direction, Precedence: 10,
				HasProtocol: true, Protocol: 17,
				HasLocalPort: true, LocalPortLow: 5_060, LocalPortHigh: 5_060,
				HasRemotePort: true, RemotePortLow: 5_061, RemotePortHigh: 5_061,
			},
		}
	}
	return rules.Session{
		CPSEID: 1, UPSEID: 2, Revision: 1, UEIPv4: ueIP,
		Local: rules.Tunnel{TEID: 1_001, IP: defaultOuter}, Remote: rules.Tunnel{TEID: 2_001, IP: peerOuter},
		UplinkPDRID: 1, DownlinkPDRID: 2, UplinkFARID: 1, DownlinkFARID: 2,
		UplinkGateOpen: true, DownlinkGateOpen: true, QERID: 1, URRID: 1,
		MeasureVolume: true, MeasureDuration: true, UsageReportingThreshold: 1 << 30,
		DedicatedBearers: []rules.Bearer{{
			Local: rules.Tunnel{TEID: 1_002, IP: qci1Outer}, Remote: rules.Tunnel{TEID: 2_002, IP: peerOuter},
			UplinkFARID: 11, DownlinkFARID: 12, UplinkGateOpen: true, DownlinkGateOpen: true,
			MaxUplinkBitsPerSecond: 10_000_000, MaxDownlinkBitsPerSecond: 10_000_000,
			QERID: 2, URRID: 2, MeasureVolume: true, MeasureDuration: true,
			UsageReportingThreshold: 1 << 20, QCI: 1, ARP: 2,
			Filters: []rules.FlowFilter{filter(1, gtpv2.TFTDirectionUplink, 21), filter(2, gtpv2.TFTDirectionDownlink, 22)},
		}},
		ControlPeer: netip.MustParseAddrPort("10.254.78.1:8805"),
	}
}

func kernelPolicyIPv4UDP(source, destination netip.Addr, sourcePort, destinationPort uint16, payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], 1)
	sourceRaw, destinationRaw := source.As4(), destination.As4()
	copy(packet[12:16], sourceRaw[:])
	copy(packet[16:20], destinationRaw[:])
	binary.BigEndian.PutUint16(packet[10:12], kernelPolicyIPv4Checksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet
}

func kernelPolicyIPv4Checksum(header []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[index : index+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func kernelPolicyIPv4Fragments(packet []byte, maxPayload int) [][]byte {
	headerLength := int(packet[0]&0x0f) * 4
	payload := packet[headerLength:]
	out := make([][]byte, 0, (len(payload)+maxPayload-1)/maxPayload)
	for offset := 0; offset < len(payload); {
		length := min(maxPayload, len(payload)-offset)
		if offset+length < len(payload) {
			length &^= 7
		}
		fragment := make([]byte, headerLength+length)
		copy(fragment[:headerLength], packet[:headerLength])
		copy(fragment[headerLength:], payload[offset:offset+length])
		binary.BigEndian.PutUint16(fragment[2:4], uint16(len(fragment)))
		fragmentBits := uint16(offset / 8)
		if offset+length < len(payload) {
			fragmentBits |= 0x2000
		}
		binary.BigEndian.PutUint16(fragment[6:8], fragmentBits)
		binary.BigEndian.PutUint16(fragment[10:12], 0)
		binary.BigEndian.PutUint16(fragment[10:12], kernelPolicyIPv4Checksum(fragment[:headerLength]))
		out = append(out, fragment)
		offset += length
	}
	return out
}
