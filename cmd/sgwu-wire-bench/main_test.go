package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

func TestWireSessionMapsBothDirections(t *testing.T) {
	const index = 1234
	session := wireSession(index)
	if session.PDRs[1].LocalFTEID.TEID != accessInputTEID(index) {
		t.Fatalf("uplink input TEID = %x", session.PDRs[1].LocalFTEID.TEID)
	}
	if session.FARs[1].OuterHeader == nil || session.FARs[1].OuterHeader.TEID != coreOutputTEID(index) || session.FARs[1].OuterHeader.IP != corePeerIP(index) {
		t.Fatalf("unexpected uplink FAR: %+v", session.FARs[1])
	}
	if session.PDRs[2].LocalFTEID.TEID != coreInputTEID(index) {
		t.Fatalf("downlink input TEID = %x", session.PDRs[2].LocalFTEID.TEID)
	}
	if session.FARs[2].OuterHeader == nil || session.FARs[2].OuterHeader.TEID != accessOutputTEID(index) || session.FARs[2].OuterHeader.IP != accessPeerIP(index) {
		t.Fatalf("unexpected downlink FAR: %+v", session.FARs[2])
	}
}

func TestCUPSWireSessionsAlignBothGateways(t *testing.T) {
	const index = 4321
	sgwu := cupsWireSGWUSession(index)
	pgwu := cupsWirePGWUSession(index)
	if sgwu.FARs[1].OuterHeader == nil ||
		sgwu.FARs[1].OuterHeader.TEID != pgwu.Local.TEID ||
		sgwu.FARs[1].OuterHeader.IP != pgwu.Local.IP {
		t.Fatalf("SGW-U uplink output does not match PGW-U input: SGW-U=%+v PGW-U=%+v", sgwu.FARs[1], pgwu.Local)
	}
	if sgwu.PDRs[2].LocalFTEID.TEID != pgwu.Remote.TEID ||
		sgwu.PDRs[2].LocalFTEID.IP != pgwu.Remote.IP {
		t.Fatalf("PGW-U downlink output does not match SGW-U input: PGW-U=%+v SGW-U=%+v", pgwu.Remote, sgwu.PDRs[2])
	}
	if pgwu.UEIPv4 != chainUEAddress(index) || pgwu.UEIPv4 == chainUEGateway {
		t.Fatalf("unexpected UE address %s", pgwu.UEIPv4)
	}
	if sgwu.FARs[2].OuterHeader == nil ||
		sgwu.FARs[2].OuterHeader.TEID != accessOutputTEID(index) ||
		sgwu.FARs[2].OuterHeader.IP != chainAccessPeerIP(index) {
		t.Fatalf("unexpected SGW-U access output: %+v", sgwu.FARs[2])
	}
}

func TestCUPSWireDedicatedBearerAlignsBothGateways(t *testing.T) {
	const index = 4321
	sgwu := cupsWireDedicatedSGWUSession(index)
	pgwu := cupsWireDedicatedPGWUSession(index)
	if len(pgwu.DedicatedBearers) != 1 {
		t.Fatalf("PGW-U dedicated bearers = %d", len(pgwu.DedicatedBearers))
	}
	bearer := pgwu.DedicatedBearers[0]
	if sgwu.FARs[3].OuterHeader == nil ||
		sgwu.FARs[3].OuterHeader.TEID != bearer.Local.TEID ||
		sgwu.FARs[3].OuterHeader.IP != bearer.Local.IP {
		t.Fatalf("dedicated SGW-U uplink output does not match PGW-U input: SGW-U=%+v PGW-U=%+v", sgwu.FARs[3], bearer.Local)
	}
	if sgwu.PDRs[4].LocalFTEID.TEID != bearer.Remote.TEID ||
		sgwu.PDRs[4].LocalFTEID.IP != bearer.Remote.IP {
		t.Fatalf("dedicated PGW-U downlink output does not match SGW-U input: PGW-U=%+v SGW-U=%+v", bearer.Remote, sgwu.PDRs[4])
	}
	if bearer.QCI != 1 || bearer.ARP != 2 || len(bearer.Filters) != 1 || !bearer.Filters[0].Filter.HasProtocol || bearer.Filters[0].Filter.Protocol != 17 {
		t.Fatalf("unexpected dedicated policy: %+v", bearer)
	}
}

func TestBuildAndValidateRewrittenPackets(t *testing.T) {
	accessMAC := mustMAC(t, defaultAccessMAC)
	coreMAC := mustMAC(t, defaultCoreMAC)
	generatorMAC := mustMAC(t, defaultGeneratorMAC)
	tests := []struct {
		name      string
		plan      *trafficPlan
		sourceMAC net.HardwareAddr
		sourceIP  [4]byte
		targetIP  [4]byte
		teid      uint32
	}{
		{
			name:      "uplink",
			plan:      newTrafficPlan("uplink", directionUplink, 16, generatorMAC, accessMAC, coreMAC, false),
			sourceMAC: coreMAC, sourceIP: dutCoreIP.As4(), targetIP: corePeerIP(7).As4(), teid: coreOutputTEID(7),
		},
		{
			name:      "downlink",
			plan:      newTrafficPlan("downlink", directionDownlink, 16, generatorMAC, coreMAC, accessMAC, false),
			sourceMAC: accessMAC, sourceIP: dutAccessIP.As4(), targetIP: accessPeerIP(7).As4(), teid: accessOutputTEID(7),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet := buildPacket(1400, test.plan, 7, 2)
			copy(packet[0:6], generatorMAC)
			copy(packet[6:12], test.sourceMAC)
			copy(packet[ethernetBytes+12:ethernetBytes+16], test.sourceIP[:])
			copy(packet[ethernetBytes+16:ethernetBytes+20], test.targetIP[:])
			udpOffset := ethernetBytes + outerIPv4Bytes
			binary.BigEndian.PutUint16(packet[udpOffset:udpOffset+2], gtpuPort)
			binary.BigEndian.PutUint32(packet[udpOffset+udpBytes+4:udpOffset+udpBytes+8], test.teid)
			if !validateReceivedPacket(packet, test.plan) {
				t.Fatal("rewritten packet rejected")
			}
			packet[metadataOffset()+31] = 0
			if validateReceivedPacket(packet, test.plan) {
				t.Fatal("corrupt packet accepted")
			}
		})
	}
}

func TestBuildAndValidateCUPSChainPackets(t *testing.T) {
	accessMAC := mustMAC(t, defaultAccessMAC)
	generatorMAC := mustMAC(t, defaultGeneratorMAC)
	sgiMAC := mustMAC(t, defaultSGiMAC)
	const flow = 7
	const innerSize = 1400

	uplink := newTrafficPlan(
		"uplink", directionUplink, 16,
		generatorMAC, accessMAC, sgiMAC, true,
	)
	uplinkInput := buildPacket(innerSize, uplink, flow, 2)
	if len(uplinkInput) != gtpFrameBytes(innerSize) || !uplink.sendsGTP() || uplink.receivesGTP() {
		t.Fatalf("unexpected uplink layout: bytes=%d sendGTP=%t receiveGTP=%t", len(uplinkInput), uplink.sendsGTP(), uplink.receivesGTP())
	}
	uplinkOutput := make([]byte, plainFrameBytes(innerSize))
	copy(uplinkOutput[0:6], generatorMAC)
	copy(uplinkOutput[6:12], sgiMAC)
	binary.BigEndian.PutUint16(uplinkOutput[12:14], 0x0800)
	copy(uplinkOutput[ethernetBytes:], uplinkInput[ethernetBytes+outerIPv4Bytes+udpBytes+gtpuBytes:])
	if !validateReceivedPacket(uplinkOutput, uplink) {
		t.Fatal("decapsulated CUPS uplink packet was rejected")
	}
	if validateReceivedPacket(uplinkInput, uplink) {
		t.Fatal("CUPS uplink accepted GTP-U where plain IPv4 was required")
	}

	downlink := newTrafficPlan(
		"downlink", directionDownlink, 16,
		generatorMAC, sgiMAC, accessMAC, true,
	)
	downlinkInput := buildPacket(innerSize, downlink, flow, 2)
	if len(downlinkInput) != plainFrameBytes(innerSize) || downlink.sendsGTP() || !downlink.receivesGTP() {
		t.Fatalf("unexpected downlink layout: bytes=%d sendGTP=%t receiveGTP=%t", len(downlinkInput), downlink.sendsGTP(), downlink.receivesGTP())
	}
	downlinkOutput := buildAccessOutputPacket(downlinkInput, generatorMAC, accessMAC, flow)
	if !validateReceivedPacket(downlinkOutput, downlink) {
		t.Fatal("encapsulated CUPS downlink packet was rejected")
	}
	if validateReceivedPacket(downlinkInput, downlink) {
		t.Fatal("CUPS downlink accepted plain IPv4 where GTP-U was required")
	}
}

func TestBuildAndValidateCUPSDedicatedBearerPackets(t *testing.T) {
	accessMAC := mustMAC(t, defaultAccessMAC)
	generatorMAC := mustMAC(t, defaultGeneratorMAC)
	sgiMAC := mustMAC(t, defaultSGiMAC)
	const flow = 7
	const innerSize = 1400

	uplink := newTrafficPlan("uplink", directionUplink, 16, generatorMAC, accessMAC, sgiMAC, true)
	uplink.dedicatedBearer = true
	uplinkInput := buildPacket(innerSize, uplink, flow, 2)
	gtpOffset := ethernetBytes + outerIPv4Bytes + udpBytes
	if got := binary.BigEndian.Uint32(uplinkInput[gtpOffset+4 : gtpOffset+8]); got != qci1AccessInputTEID(flow) {
		t.Fatalf("dedicated uplink input TEID = %#x", got)
	}
	uplinkOutput := make([]byte, plainFrameBytes(innerSize))
	copy(uplinkOutput[0:6], generatorMAC)
	copy(uplinkOutput[6:12], sgiMAC)
	binary.BigEndian.PutUint16(uplinkOutput[12:14], 0x0800)
	copy(uplinkOutput[ethernetBytes:], uplinkInput[ethernetBytes+outerIPv4Bytes+udpBytes+gtpuBytes:])
	if !validateReceivedPacket(uplinkOutput, uplink) {
		t.Fatal("dedicated CUPS uplink packet was rejected")
	}

	downlink := newTrafficPlan("downlink", directionDownlink, 16, generatorMAC, sgiMAC, accessMAC, true)
	downlink.dedicatedBearer = true
	downlinkInput := buildPacket(innerSize, downlink, flow, 2)
	downlinkOutput := buildAccessOutputPacket(downlinkInput, generatorMAC, accessMAC, flow)
	binary.BigEndian.PutUint32(downlinkOutput[gtpOffset+4:gtpOffset+8], qci1AccessOutputTEID(flow))
	if !validateReceivedPacket(downlinkOutput, downlink) {
		t.Fatal("dedicated CUPS downlink packet was rejected")
	}
}

func TestCUPSWireMixedBearerClassifiesVoiceAndDataSeparately(t *testing.T) {
	const flow = 7
	accessMAC := mustMAC(t, defaultAccessMAC)
	generatorMAC := mustMAC(t, defaultGeneratorMAC)
	sgiMAC := mustMAC(t, defaultSGiMAC)
	session := cupsWireMixedPGWUSession(flow)
	filter := session.DedicatedBearers[0].Filters[0].Filter
	if !filter.HasProtocol || filter.Protocol != 17 || !filter.HasLocalPort ||
		filter.LocalPortLow != mixedVoiceLocalPort || filter.LocalPortHigh != mixedVoiceLocalPort {
		t.Fatalf("unexpected mixed-bearer TFT: %+v", filter)
	}

	uplinkData := configureTrafficPlan(newTrafficPlan("uplink", directionUplink, 16, generatorMAC, accessMAC, sgiMAC, true), directionUplink, 1400, 1000, "bulk-data", false, false)
	uplinkVoice := configureTrafficPlan(newTrafficPlan("uplink", streamUplinkVoice, 16, generatorMAC, accessMAC, sgiMAC, true), directionUplink, 200, 50, "qci1-voice", true, true)
	dataPacket := buildPacket(uplinkData.innerPacketBytes, uplinkData, flow, 2)
	voicePacket := buildPacket(uplinkVoice.innerPacketBytes, uplinkVoice, flow, 2)
	gtpOffset := ethernetBytes + outerIPv4Bytes + udpBytes
	if got := binary.BigEndian.Uint32(dataPacket[gtpOffset+4 : gtpOffset+8]); got != accessInputTEID(flow) {
		t.Fatalf("mixed uplink data TEID = %#x", got)
	}
	if got := binary.BigEndian.Uint32(voicePacket[gtpOffset+4 : gtpOffset+8]); got != qci1AccessInputTEID(flow) {
		t.Fatalf("mixed uplink voice TEID = %#x", got)
	}
	innerOffset := gtpOffset + gtpuBytes
	if filter.Matches(dataPacket[innerOffset:], gtpv2.TFTDirectionUplink) {
		t.Fatal("bulk uplink matched the QCI 1 voice TFT")
	}
	if !filter.Matches(voicePacket[innerOffset:], gtpv2.TFTDirectionUplink) {
		t.Fatal("voice uplink did not match the QCI 1 TFT")
	}

	downlinkData := configureTrafficPlan(newTrafficPlan("downlink", directionDownlink, 16, generatorMAC, sgiMAC, accessMAC, true), directionDownlink, 1400, 1000, "bulk-data", false, false)
	downlinkVoice := configureTrafficPlan(newTrafficPlan("downlink", streamDownlinkVoice, 16, generatorMAC, sgiMAC, accessMAC, true), directionDownlink, 200, 50, "qci1-voice", true, true)
	downlinkDataInput := buildPacket(downlinkData.innerPacketBytes, downlinkData, flow, 2)
	downlinkVoiceInput := buildPacket(downlinkVoice.innerPacketBytes, downlinkVoice, flow, 2)
	if filter.Matches(downlinkDataInput[ethernetBytes:], gtpv2.TFTDirectionDownlink) {
		t.Fatal("bulk downlink matched the QCI 1 voice TFT")
	}
	if !filter.Matches(downlinkVoiceInput[ethernetBytes:], gtpv2.TFTDirectionDownlink) {
		t.Fatal("voice downlink did not match the QCI 1 TFT")
	}
	dataOutput := buildAccessOutputPacket(downlinkDataInput, generatorMAC, accessMAC, flow)
	if !validateReceivedPacket(dataOutput, downlinkData) {
		t.Fatal("mixed default-bearer downlink was rejected")
	}
	voiceOutput := buildAccessOutputPacket(downlinkVoiceInput, generatorMAC, accessMAC, flow)
	binary.BigEndian.PutUint32(voiceOutput[gtpOffset+4:gtpOffset+8], qci1AccessOutputTEID(flow))
	if !validateReceivedPacket(voiceOutput, downlinkVoice) {
		t.Fatal("mixed QCI 1 voice downlink was rejected")
	}
	binary.BigEndian.PutUint32(voiceOutput[gtpOffset+4:gtpOffset+8], accessOutputTEID(flow))
	if validateReceivedPacket(voiceOutput, downlinkVoice) {
		t.Fatal("voice packet returned on default bearer was accepted")
	}
}

func TestCUPSChainFrameAccounting(t *testing.T) {
	generatorMAC := mustMAC(t, defaultGeneratorMAC)
	accessMAC := mustMAC(t, defaultAccessMAC)
	sgiMAC := mustMAC(t, defaultSGiMAC)
	uplink := newTrafficPlan("uplink", directionUplink, 1, generatorMAC, accessMAC, sgiMAC, true)
	downlink := newTrafficPlan("downlink", directionDownlink, 1, generatorMAC, sgiMAC, accessMAC, true)
	if got, want := uplink.sendFrameBytes(1400), 1450; got != want {
		t.Fatalf("uplink offered frame = %d, want %d", got, want)
	}
	if got, want := uplink.receiveFrameBytes(1400), 1414; got != want {
		t.Fatalf("uplink received frame = %d, want %d", got, want)
	}
	if got, want := downlink.sendFrameBytes(1400), 1414; got != want {
		t.Fatalf("downlink offered frame = %d, want %d", got, want)
	}
	if got, want := downlink.receiveFrameBytes(1400), 1450; got != want {
		t.Fatalf("downlink received frame = %d, want %d", got, want)
	}
	if got, want := metadataOffsetForGTP(true)-metadataOffsetForGTP(false), outerIPv4Bytes+udpBytes+gtpuBytes; got != want {
		t.Fatalf("metadata offset difference = %d, want %d", got, want)
	}
}

func TestWorkerFlowsCoverEachFlowOnce(t *testing.T) {
	const active = 1003
	seen := make([]int, active)
	for worker := 0; worker < 16; worker++ {
		for _, flow := range workerFlows(active, 16, worker) {
			seen[flow]++
		}
	}
	for flow, count := range seen {
		if count != 1 {
			t.Fatalf("flow %d appears %d times", flow, count)
		}
	}
}

func TestPacketSizesAndInnerIPv4Length(t *testing.T) {
	plan := newTrafficPlan(
		"uplink", directionUplink, 1,
		mustMAC(t, defaultGeneratorMAC), mustMAC(t, defaultAccessMAC), mustMAC(t, defaultCoreMAC), false,
	)
	for _, innerSize := range []int{64, 128, 256, 512, 1024, 1400} {
		packet := buildPacket(innerSize, plan, 0, 0)
		if got, want := len(packet), ethernetBytes+outerIPv4Bytes+udpBytes+gtpuBytes+innerSize; got != want {
			t.Fatalf("inner %d: frame length %d, want %d", innerSize, got, want)
		}
		innerOffset := ethernetBytes + outerIPv4Bytes + udpBytes + gtpuBytes
		if got := int(binary.BigEndian.Uint16(packet[innerOffset+2 : innerOffset+4])); got != innerSize {
			t.Fatalf("inner %d: IPv4 total length %d", innerSize, got)
		}
	}
}

func buildAccessOutputPacket(innerFrame []byte, generatorMAC, accessMAC net.HardwareAddr, flow int) []byte {
	innerSize := len(innerFrame) - ethernetBytes
	packet := make([]byte, gtpFrameBytes(innerSize))
	copy(packet[0:6], generatorMAC)
	copy(packet[6:12], accessMAC)
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	outerIP := packet[ethernetBytes : ethernetBytes+outerIPv4Bytes]
	outerIP[0] = 0x45
	binary.BigEndian.PutUint16(outerIP[2:4], uint16(outerIPv4Bytes+udpBytes+gtpuBytes+innerSize))
	outerIP[8] = 64
	outerIP[9] = 17
	source := chainSGWUAccessIP.As4()
	destination := chainAccessPeerIP(flow).As4()
	copy(outerIP[12:16], source[:])
	copy(outerIP[16:20], destination[:])
	binary.BigEndian.PutUint16(outerIP[10:12], internetChecksum(outerIP))
	udp := packet[ethernetBytes+outerIPv4Bytes:]
	binary.BigEndian.PutUint16(udp[0:2], gtpuPort)
	binary.BigEndian.PutUint16(udp[2:4], gtpuPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpBytes+gtpuBytes+innerSize))
	gtp := udp[udpBytes:]
	gtp[0] = 0x30
	gtp[1] = 255
	binary.BigEndian.PutUint16(gtp[2:4], uint16(innerSize))
	binary.BigEndian.PutUint32(gtp[4:8], accessOutputTEID(flow))
	copy(gtp[gtpuBytes:], innerFrame[ethernetBytes:])
	return packet
}

func TestLatencyHistogram(t *testing.T) {
	var histogram latencyHistogram
	histogram.record(uint64(time.Now().Add(-50 * time.Microsecond).UnixNano()))
	histogram.record(uint64(time.Now().Add(-2 * time.Millisecond).UnixNano()))
	if histogram.samples.Load() != 2 {
		t.Fatalf("samples = %d", histogram.samples.Load())
	}
	if histogram.quantile(.50) <= 0 || histogram.maximum.Load() == 0 {
		t.Fatal("latency summary was empty")
	}
}

func TestParseCPUList(t *testing.T) {
	values, err := parseCPUList("0-2,4,7-8")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{0, 1, 2, 4, 7, 8}
	if len(values) != len(want) {
		t.Fatalf("values = %v", values)
	}
	for index := range want {
		if values[index] != want[index] {
			t.Fatalf("values = %v", values)
		}
	}
	if _, err := parseCPUList("4-2"); err == nil {
		t.Fatal("invalid range accepted")
	}
}

func mustMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	parsed, err := net.ParseMAC(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
