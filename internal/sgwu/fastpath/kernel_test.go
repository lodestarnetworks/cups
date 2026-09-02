//go:build linux

package fastpath

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/lodestarnetworks/cups/internal/sgwu/rules"
)

func TestKernelRewriteAndRevisionFlip(t *testing.T) {
	objects := loadKernelTestObjects(t)
	configureKernelTestSide(t, &objects, true)
	installKernelTestRule(t, &objects, 1, 200)

	input := kernelTestPacket(t, true)
	returnValue, output, err := objects.SgwuAccessIngress.Test(input)
	if err != nil {
		t.Fatal(err)
	}
	if returnValue != 0 {
		t.Fatalf("unexpected TC action %d", returnValue)
	}
	assertKernelRewrite(t, output, 200, true)

	installKernelTestRule(t, &objects, 2, 201)
	returnValue, output, err = objects.SgwuAccessIngress.Test(input)
	if err != nil {
		t.Fatal(err)
	}
	if returnValue != 0 {
		t.Fatalf("unexpected TC action after revision flip %d", returnValue)
	}
	assertKernelRewrite(t, output, 201, true)

	if got := kernelCounter(t, objects.Counters, counterForwardedPackets); got != 2 {
		t.Fatalf("forwarded counter=%d, want 2", got)
	}
	if got := kernelCounter(t, objects.Counters, counterUplinkBytes); got != 64 {
		t.Fatalf("uplink bytes=%d, want 64", got)
	}
}

func TestKernelURRAccounting(t *testing.T) {
	objects := loadKernelTestObjects(t)
	configureKernelTestSide(t, &objects, true)
	installKernelTestRule(t, &objects, 1, 200)
	ruleKey := bpfRuleKey{UpSeid: 10, Revision: 1, Source: sideAccess, Teid: 100}
	var rule bpfRuleValue
	if err := objects.PacketRules.Lookup(&ruleKey, &rule); err != nil {
		t.Fatal(err)
	}
	rule.UrrCount = 1
	rule.UrrIds[0] = 7
	if err := objects.PacketRules.Update(&ruleKey, &rule, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	usageKey := bpfUsageKey{UpSeid: 10, UrrId: 7}
	zero := bpfUsageValue{}
	if err := objects.UsageCounters.Update(&usageKey, &zero, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if _, _, err := objects.SgwuAccessIngress.Test(kernelTestPacket(t, false)); err != nil {
		t.Fatal(err)
	}
	var usage bpfUsageValue
	if err := objects.UsageCounters.Lookup(&usageKey, &usage); err != nil {
		t.Fatal(err)
	}
	if usage.UplinkPackets != 1 || usage.UplinkBytes != 32 || usage.DownlinkPackets != 0 || usage.DownlinkBytes != 0 {
		t.Fatalf("unexpected kernel usage counters %#v", usage)
	}
}

func TestKernelUnauthorizedPeerIsDropped(t *testing.T) {
	objects := loadKernelTestObjects(t)
	configureKernelTestSide(t, &objects, false)
	input := kernelTestPacket(t, false)
	returnValue, _, err := objects.SgwuAccessIngress.Test(input)
	if err != nil {
		t.Fatal(err)
	}
	if returnValue != 2 {
		t.Fatalf("TC action=%d, want TC_ACT_SHOT", returnValue)
	}
	if got := kernelCounter(t, objects.Counters, counterUnauthorized); got != 1 {
		t.Fatalf("unauthorized counter=%d, want 1", got)
	}
}

func TestKernelUnknownTunnelFallsBackUnchanged(t *testing.T) {
	objects := loadKernelTestObjects(t)
	configureKernelTestSide(t, &objects, true)
	input := kernelTestPacket(t, false)
	returnValue, output, err := objects.SgwuAccessIngress.Test(input)
	if err != nil {
		t.Fatal(err)
	}
	if returnValue != 0 || !bytes.Equal(output, input) {
		t.Fatalf("unknown tunnel did not fall back unchanged: action=%d", returnValue)
	}
	if got := kernelCounter(t, objects.Counters, counterFallbackPackets); got != 1 {
		t.Fatalf("fallback counter=%d, want 1", got)
	}
}

func TestKernelTruncatedKnownTunnelFallsBackUnchanged(t *testing.T) {
	objects := loadKernelTestObjects(t)
	configureKernelTestSide(t, &objects, true)
	installKernelTestRule(t, &objects, 1, 200)
	packet := kernelTestPacket(t, false)
	input := packet[:len(packet)-1]
	returnValue, output, err := objects.SgwuAccessIngress.Test(input)
	if err != nil {
		t.Fatal(err)
	}
	if returnValue != 0 || !bytes.Equal(output, input) {
		t.Fatalf("truncated tunnel did not fall back unchanged: action=%d", returnValue)
	}
	if got := kernelCounter(t, objects.Counters, counterFallbackPackets); got != 1 {
		t.Fatalf("fallback counter=%d, want 1", got)
	}
}

func TestBackendSessionLifecycleFailsBackForBufferedBearer(t *testing.T) {
	objects := loadKernelTestObjects(t)
	store := rules.NewStoreWithLimit(16)
	outerCore := rules.FTEID{TEID: 200, IP: mustTestAddr("10.253.2.2")}
	outerAccess := rules.FTEID{TEID: 400, IP: mustTestAddr("10.253.1.2")}
	created, err := store.Create(rules.Session{
		CPSEID: 1, UPSEID: 10,
		PDRs: map[uint16]rules.PDR{
			1: {ID: 1, SourceInterface: rules.SourceAccess, LocalFTEID: rules.FTEID{TEID: 100, IP: mustTestAddr("10.253.1.1")}, FARID: 1, URRIDs: []uint32{1}},
			2: {ID: 2, SourceInterface: rules.SourceCore, LocalFTEID: rules.FTEID{TEID: 300, IP: mustTestAddr("10.253.2.1")}, FARID: 2, URRIDs: []uint32{1}},
		},
		FARs: map[uint32]rules.FAR{
			1: {ID: 1, ApplyAction: rules.ActionForward, DestinationInterface: rules.DestinationCore, OuterHeader: &outerCore},
			2: {ID: 2, ApplyAction: rules.ActionForward, DestinationInterface: rules.DestinationAccess, OuterHeader: &outerAccess},
		},
		QERs: map[uint32]rules.QER{}, URRs: map[uint32]rules.URR{1: {ID: 1, MeasureVolume: true, ReportingThreshold: 64}},
	})
	if err != nil {
		t.Fatal(err)
	}
	backend := &Backend{
		store: store, objects: objects, installed: make(map[uint64]installedSession),
		access: resolvedSide{localIP: ipv4Native(mustTestAddr("10.253.1.1")), neighbours: map[netip.Addr]endpoint{
			mustTestAddr("10.253.1.2"): {ifindex: 11, localIP: ipv4Native(mustTestAddr("10.253.1.1")), remoteIP: ipv4Native(mustTestAddr("10.253.1.2")), localMAC: [6]byte{2, 0, 0, 0, 1, 1}, remoteMAC: [6]byte{2, 0, 0, 0, 1, 2}},
		}},
		core: resolvedSide{localIP: ipv4Native(mustTestAddr("10.253.2.1")), neighbours: map[netip.Addr]endpoint{
			mustTestAddr("10.253.2.2"): {ifindex: 12, localIP: ipv4Native(mustTestAddr("10.253.2.1")), remoteIP: ipv4Native(mustTestAddr("10.253.2.2")), localMAC: [6]byte{2, 0, 0, 0, 2, 1}, remoteMAC: [6]byte{2, 0, 0, 0, 2, 2}},
		}},
	}
	for source, localIP := range map[uint32]netip.Addr{sideAccess: mustTestAddr("10.253.1.1"), sideCore: mustTestAddr("10.253.2.1")} {
		side := bpfSideConfiguration{LocalIp: ipv4Native(localIP), Flags: 1}
		if err := objects.SideConfigurations.Update(&source, &side, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	for source, peer := range map[uint32]netip.Addr{sideAccess: mustTestAddr("10.253.1.2"), sideCore: mustTestAddr("10.253.2.2")} {
		key := bpfPeerKey{Source: source, Ip: ipv4Native(peer)}
		allowed := uint8(1)
		if err := objects.AllowedPeers.Update(&key, &allowed, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	backend.SessionChanged(created.UPSEID)
	input := kernelTestPacket(t, false)
	_, output, err := objects.SgwuAccessIngress.Test(input)
	if err != nil {
		t.Fatal(err)
	}
	assertKernelRewrite(t, output, 200, false)
	usage := backend.Usage()
	if len(usage) != 1 || usage[0].UplinkPackets != 1 || usage[0].UplinkBytes != 32 || usage[0].ThresholdEvents != 0 {
		t.Fatalf("unexpected first usage snapshot %#v", usage)
	}

	updated, err := store.Update(created.UPSEID, created.Revision, func(session *rules.Session) error {
		far := session.FARs[1]
		outer := *far.OuterHeader
		outer.TEID = 201
		far.OuterHeader = &outer
		session.FARs[1] = far
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	backend.SessionChanged(updated.UPSEID)
	_, output, err = objects.SgwuAccessIngress.Test(input)
	if err != nil {
		t.Fatal(err)
	}
	assertKernelRewrite(t, output, 201, false)
	usage = backend.Usage()
	if len(usage) != 1 || usage[0].UplinkPackets != 2 || usage[0].UplinkBytes != 64 || usage[0].ThresholdEvents != 1 {
		t.Fatalf("usage did not survive revision flip %#v", usage)
	}

	buffering, err := store.Update(updated.UPSEID, updated.Revision, func(session *rules.Session) error {
		far := session.FARs[1]
		far.ApplyAction = rules.ActionBuffer | rules.ActionNotifyControlPlane
		session.FARs[1] = far
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	backend.SessionChanged(buffering.UPSEID)
	_, output, err = objects.SgwuAccessIngress.Test(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output, input) {
		t.Fatal("buffering bearer did not fall back to the portable path unchanged")
	}
	if err := store.Delete(buffering.UPSEID, buffering.Revision); err != nil {
		t.Fatal(err)
	}
	backend.SessionDeleted(buffering.UPSEID)
	if got := backend.Counters().SyncFailures; got != 0 {
		t.Fatalf("sync failures=%d, want 0", got)
	}
	if counters := backend.Counters(); counters.URRMeteredPackets != 2 || counters.URRMeteredBytes != 64 || counters.URRThresholdEvents != 1 || counters.URRActiveMeters != 0 {
		t.Fatalf("unexpected retired usage counters %#v", counters)
	}
}

func TestBackendBatchUsageSnapshot(t *testing.T) {
	objects := loadKernelTestObjects(t)
	backend := &Backend{objects: objects, usage: make(map[bpfUsageKey]*usageTracker)}
	const meters = 129
	var expectedPackets uint64
	for index := uint64(1); index <= meters; index++ {
		key := bpfUsageKey{UpSeid: index, UrrId: 1}
		value := bpfUsageValue{UplinkPackets: index, UplinkBytes: index * 32}
		if err := objects.UsageCounters.Update(&key, &value, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		backend.usage[key] = &usageTracker{rule: rules.URR{ID: 1, MeasureVolume: true}}
		expectedPackets += index
	}

	usage := backend.Usage()
	if len(usage) != meters {
		t.Fatalf("usage meters=%d, want %d", len(usage), meters)
	}
	if usage[0].UPSEID != 1 || usage[len(usage)-1].UPSEID != meters {
		t.Fatalf("usage snapshot is not deterministically sorted: first=%d last=%d", usage[0].UPSEID, usage[len(usage)-1].UPSEID)
	}
	counters := backend.Counters()
	if counters.URRActiveMeters != meters || counters.URRMeteredPackets != expectedPackets || counters.URRMeteredBytes != expectedPackets*32 {
		t.Fatalf("unexpected batched usage counters %#v", counters)
	}
}

func loadKernelTestObjects(t *testing.T) bpfObjects {
	t.Helper()
	if os.Getenv("SGW_NEXT_EBPF_TEST") != "1" {
		t.Skip("set SGW_NEXT_EBPF_TEST=1 as root to run kernel eBPF tests")
	}
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{bpfMapAllowedPeers, bpfMapTunnelSessions, bpfMapActiveRevisions, bpfMapUsageCounters} {
		spec.Maps[name].MaxEntries = 256
	}
	spec.Maps[bpfMapPacketRules].MaxEntries = 512
	var objects bpfObjects
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objects.Close() })
	return objects
}

func configureKernelTestSide(t *testing.T, objects *bpfObjects, allow bool) {
	t.Helper()
	source := sideAccess
	side := bpfSideConfiguration{LocalIp: ipv4Native(mustTestAddr("10.253.1.1")), Flags: 1}
	if err := objects.SideConfigurations.Update(&source, &side, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if allow {
		key := bpfPeerKey{Source: source, Ip: ipv4Native(mustTestAddr("10.253.1.2"))}
		value := uint8(1)
		if err := objects.AllowedPeers.Update(&key, &value, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
}

func installKernelTestRule(t *testing.T, objects *bpfObjects, revision uint64, outputTEID uint32) {
	t.Helper()
	tunnel := bpfTunnelKey{Source: sideAccess, Teid: 100}
	upSEID := uint64(10)
	if err := objects.TunnelSessions.Update(&tunnel, &upSEID, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	key := bpfRuleKey{UpSeid: upSEID, Revision: revision, Source: sideAccess, Teid: 100}
	value := bpfRuleValue{
		EgressIfindex: 99,
		SourceIp:      ipv4Native(mustTestAddr("10.253.2.1")), DestinationIp: ipv4Native(mustTestAddr("10.253.2.2")),
		Teid: outputTEID, SourceMac: [6]byte{0x02, 0, 0, 0, 2, 1}, DestinationMac: [6]byte{0x02, 0, 0, 0, 2, 2},
	}
	if err := objects.PacketRules.Update(&key, &value, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := objects.ActiveRevisions.Update(&upSEID, &revision, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
}

func kernelTestPacket(t *testing.T, udpChecksum bool) []byte {
	t.Helper()
	const payloadLength = 32
	packet := make([]byte, 14+20+8+8+payloadLength)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 1, 1})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 1, 2})
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	ip := packet[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(packet)-14))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], mustTestAddr("10.253.1.2").AsSlice())
	copy(ip[16:20], mustTestAddr("10.253.1.1").AsSlice())
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip))
	udp := packet[34:]
	binary.BigEndian.PutUint16(udp[0:2], 31_000)
	binary.BigEndian.PutUint16(udp[2:4], 2152)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	gtp := udp[8:]
	gtp[0] = 0x30
	gtp[1] = 255
	binary.BigEndian.PutUint16(gtp[2:4], payloadLength)
	binary.BigEndian.PutUint32(gtp[4:8], 100)
	for index := 0; index < payloadLength; index++ {
		gtp[8+index] = byte(index + 1)
	}
	if udpChecksum {
		binary.BigEndian.PutUint16(udp[6:8], udpIPv4Checksum(ip[12:16], ip[16:20], udp))
	}
	return packet
}

func assertKernelRewrite(t *testing.T, packet []byte, teid uint32, udpChecksum bool) {
	t.Helper()
	if !bytes.Equal(packet[0:6], []byte{0x02, 0, 0, 0, 2, 2}) || !bytes.Equal(packet[6:12], []byte{0x02, 0, 0, 0, 2, 1}) {
		t.Fatalf("unexpected Ethernet rewrite %x", packet[:14])
	}
	ip := packet[14:34]
	if !bytes.Equal(ip[12:16], mustTestAddr("10.253.2.1").AsSlice()) || !bytes.Equal(ip[16:20], mustTestAddr("10.253.2.2").AsSlice()) {
		t.Fatalf("unexpected IPv4 rewrite %v -> %v", ip[12:16], ip[16:20])
	}
	if internetChecksum(ip) != 0 {
		t.Fatal("invalid rewritten IPv4 checksum")
	}
	udp := packet[34:]
	if binary.BigEndian.Uint16(udp[0:2]) != 2152 || binary.BigEndian.Uint16(udp[2:4]) != 2152 {
		t.Fatalf("unexpected UDP ports %d -> %d", binary.BigEndian.Uint16(udp[0:2]), binary.BigEndian.Uint16(udp[2:4]))
	}
	if binary.BigEndian.Uint32(udp[12:16]) != teid {
		t.Fatalf("TEID=%d, want %d", binary.BigEndian.Uint32(udp[12:16]), teid)
	}
	if udpChecksum && udpIPv4ChecksumValid(ip[12:16], ip[16:20], udp) == false {
		t.Fatal("invalid rewritten UDP checksum")
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

func udpIPv4Checksum(source, destination, udp []byte) uint16 {
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[0:4], source)
	copy(pseudo[4:8], destination)
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	pseudo[18] = 0
	pseudo[19] = 0
	value := internetChecksum(pseudo)
	if value == 0 {
		return 0xffff
	}
	return value
}

func udpIPv4ChecksumValid(source, destination, udp []byte) bool {
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[0:4], source)
	copy(pseudo[4:8], destination)
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	return internetChecksum(pseudo) == 0
}

func kernelCounter(t *testing.T, values *ebpf.Map, index uint32) uint64 {
	t.Helper()
	perCPU := make([]uint64, 0)
	if err := values.Lookup(&index, &perCPU); err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, value := range perCPU {
		total += value
	}
	return total
}
