package pfcp

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

func TestPFCPInformationElementsRoundTrip(t *testing.T) {
	fseid, err := NewFSEIDIE(FSEID{SEID: 0x0102030405060708, IPv4: netip.MustParseAddr("10.200.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	fteid, err := NewFTEIDIE(FTEID{TEID: 0x11223344, IPv4: netip.MustParseAddr("10.201.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	pdi, err := NewGroupedIE(IEPDI,
		mustInterfaceIE(t, IESourceInterface, InterfaceAccess),
		fteid,
	)
	if err != nil {
		t.Fatal(err)
	}
	pdr, err := NewGroupedIE(IECreatePDR, mustPDRIDIE(t, 1), pdi)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := MarshalIEs([]IE{fseid, pdr, {Type: 32_768, Value: []byte{0x28, 0xaf, 1, 2}}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseIEs(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !bytes.Equal(got[2].Value, []byte{0x28, 0xaf, 1, 2}) {
		t.Fatalf("unexpected IEs: %#v", got)
	}
	decoded, err := got[0].FSEID()
	if err != nil || decoded.SEID != 0x0102030405060708 || decoded.IPv4.String() != "10.200.0.1" {
		t.Fatalf("unexpected F-SEID: %#v, %v", decoded, err)
	}
}

func TestOuterHeaderAndRuleValues(t *testing.T) {
	ie, err := NewOuterHeaderCreationIE(OuterHeader{
		Description: OuterHeaderGTPUUDPIPv4,
		TEID:        0xaabbccdd,
		IPv4:        netip.MustParseAddr("10.202.0.7"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ie.OuterHeaderCreation()
	if err != nil || got.TEID != 0xaabbccdd || got.IPv4.String() != "10.202.0.7" {
		t.Fatalf("unexpected outer header: %#v, %v", got, err)
	}
	for _, action := range []uint8{ApplyDrop, ApplyForward, ApplyBuffer | ApplyNotifyControlPlane} {
		encoded, err := NewApplyActionIE(action)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := encoded.ApplyAction()
		if err != nil || decoded != action {
			t.Fatalf("action round trip: %x, %v", decoded, err)
		}
	}
}

func TestDownlinkDataReportRoundTrip(t *testing.T) {
	reportType, err := NewReportTypeIE(ReportDownlinkData)
	if err != nil {
		t.Fatal(err)
	}
	pdrID, err := NewPDRIDIE(2)
	if err != nil {
		t.Fatal(err)
	}
	report, err := NewGroupedIE(IEDownlinkDataReport, pdrID)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := MarshalIEs([]IE{reportType, report})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseIEs(wire)
	if err != nil {
		t.Fatal(err)
	}
	flags, err := decoded[0].ReportType()
	if err != nil || flags != ReportDownlinkData {
		t.Fatalf("Report Type = %#x, %v", flags, err)
	}
	children, err := decoded[1].Children()
	if err != nil {
		t.Fatal(err)
	}
	gotPDR, err := children[0].PDRID()
	if err != nil || gotPDR != 2 {
		t.Fatalf("PDR ID = %d, %v", gotPDR, err)
	}
}

func TestUsageReportInformationElementsRoundTrip(t *testing.T) {
	reportType, err := NewReportTypeIE(ReportDownlinkData | ReportUsage)
	if err != nil {
		t.Fatal(err)
	}
	if flags, err := reportType.ReportType(); err != nil || flags != ReportDownlinkData|ReportUsage {
		t.Fatalf("report type = %#x, %v", flags, err)
	}

	sequence := NewURSEQNIE(0xfeedbeef)
	if got, err := sequence.URSEQN(); err != nil || got != 0xfeedbeef {
		t.Fatalf("UR-SEQN = %#x, %v", got, err)
	}
	trigger, err := NewUsageReportTriggerIE(UsageReportTriggerVolumeThreshold | UsageReportTriggerImmediate)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := trigger.UsageReportTrigger(); err != nil || got != UsageReportTriggerVolumeThreshold|UsageReportTriggerImmediate {
		t.Fatalf("trigger = %#x, %v", got, err)
	}

	measurement := VolumeMeasurement{
		HasTotalBytes: true, HasUplinkBytes: true, HasDownlinkBytes: true,
		HasTotalPackets: true, HasUplinkPackets: true, HasDownlinkPackets: true,
		TotalBytes: 3000, UplinkBytes: 1000, DownlinkBytes: 2000,
		TotalPackets: 30, UplinkPackets: 10, DownlinkPackets: 20,
	}
	volume, err := NewVolumeMeasurementIE(measurement)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := volume.VolumeMeasurement()
	if err != nil || decoded != measurement {
		t.Fatalf("measurement = %#v, %v", decoded, err)
	}

	duration, err := NewDurationMeasurementIE(17*time.Second + 900*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := duration.DurationMeasurement(); err != nil || got != 17*time.Second {
		t.Fatalf("duration = %s, %v", got, err)
	}

	stamp := time.Date(2026, 8, 31, 12, 34, 56, 0, time.UTC)
	for _, typ := range []uint16{IEStartTime, IEEndTime, IETimeOfFirstPacket, IETimeOfLastPacket} {
		encoded, err := NewUsageTimeIE(typ, stamp)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := encoded.UsageTime(); err != nil || !got.Equal(stamp) {
			t.Fatalf("timestamp %d = %s, %v", typ, got, err)
		}
	}

	urrID, _ := NewUint32IE(IEURRID, 7)
	grouped, err := NewGroupedIE(IEUsageReportSessionReport, urrID, sequence, trigger, volume, duration)
	if err != nil {
		t.Fatal(err)
	}
	children, err := grouped.Children()
	if err != nil || len(children) != 5 {
		t.Fatalf("usage report children = %d, %v", len(children), err)
	}
}

func TestUsageReportInformationElementsRejectMalformedValues(t *testing.T) {
	if _, err := NewUsageReportTriggerIE(0); err == nil {
		t.Fatal("accepted an empty Usage Report Trigger")
	}
	if _, err := NewVolumeMeasurementIE(VolumeMeasurement{}); err == nil {
		t.Fatal("accepted an empty Volume Measurement")
	}
	if _, err := (IE{Type: IEVolumeMeasurement, Value: []byte{0x01, 0}}).VolumeMeasurement(); err == nil {
		t.Fatal("accepted a truncated Volume Measurement")
	}
	if _, err := NewUsageTimeIE(IECause, time.Now()); err == nil {
		t.Fatal("accepted an unsupported usage timestamp type")
	}
}

func TestSxaBARInformationElementsRoundTrip(t *testing.T) {
	barID, err := NewBARIDIE(5)
	if err != nil {
		t.Fatal(err)
	}
	delay, err := NewDownlinkDataNotificationDelayIE(150 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	bar, err := NewGroupedIE(IECreateBAR, barID, delay)
	if err != nil {
		t.Fatal(err)
	}
	children, err := bar.Children()
	if err != nil {
		t.Fatal(err)
	}
	gotID, err := children[0].BARID()
	if err != nil || gotID != 5 {
		t.Fatalf("BAR ID = %d, %v", gotID, err)
	}
	gotDelay, err := children[1].DownlinkDataNotificationDelay()
	if err != nil || gotDelay != 150*time.Millisecond {
		t.Fatalf("DDN delay = %s, %v", gotDelay, err)
	}
	if _, err := NewDownlinkDataNotificationDelayIE(51 * time.Millisecond); err == nil {
		t.Fatal("accepted a DDN delay outside the 50 ms wire unit")
	}
}

func TestVendorBearerQoSRoundTrip(t *testing.T) {
	want := BearerQoSMetadata{
		EnterpriseID: 65000, QCI: 5, ARP: 1,
		PreemptionCapable: true, PreemptionVulnerable: true,
	}
	ie, err := NewVendorBearerQoSIE(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ie.VendorBearerQoS()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("vendor bearer QoS = %#v, want %#v", got, want)
	}
	for _, enterpriseID := range []uint16{0, 10415} {
		if _, err := NewVendorBearerQoSIE(BearerQoSMetadata{EnterpriseID: enterpriseID, QCI: 5, ARP: 1}); err == nil {
			t.Fatalf("accepted reserved enterprise ID %d", enterpriseID)
		}
	}
}

func TestUEIPAddressIPv4RoundTrip(t *testing.T) {
	want := netip.MustParseAddr("10.90.0.7")
	for _, destination := range []bool{false, true} {
		ie, err := NewUEIPAddressIE(want, destination)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ie.UEIPAddress()
		if err != nil {
			t.Fatal(err)
		}
		if got.IPv4 != want || got.Destination != destination {
			t.Fatalf("UE IP = %#v, want %s destination=%t", got, want, destination)
		}
	}
}

func TestUEIPAddressRejectsUnsupportedForms(t *testing.T) {
	for _, value := range [][]byte{
		nil,
		{0x02, 10, 90, 0},
		{0x01, 0, 0, 0, 1},
		{0x0a, 10, 90, 0, 1},
		{0x02, 0, 0, 0, 0},
	} {
		if _, err := (IE{Type: IEUEIPAddress, Value: value}).UEIPAddress(); err == nil {
			t.Fatalf("accepted malformed UE IP Address: %x", value)
		}
	}
}

func TestRecoveryTimeStampRoundTrip(t *testing.T) {
	started := time.Date(2026, 8, 30, 2, 0, 0, 0, time.UTC)
	ie, err := NewRecoveryTimeStampIE(started)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ie.RecoveryTimeStamp()
	if err != nil || !got.Equal(started) {
		t.Fatalf("unexpected timestamp %s: %v", got, err)
	}
}

func TestUsageRuleIEsRoundTrip(t *testing.T) {
	method, err := NewMeasurementMethodIE(true, true)
	if err != nil {
		t.Fatal(err)
	}
	volume, duration, err := method.MeasurementMethod()
	if err != nil || !volume || !duration {
		t.Fatalf("measurement method volume=%t duration=%t err=%v", volume, duration, err)
	}
	triggers, err := NewReportingTriggersIE(ReportingTriggerVolumeThreshold)
	if err != nil {
		t.Fatal(err)
	}
	flags, err := triggers.ReportingTriggers()
	if err != nil || flags != ReportingTriggerVolumeThreshold {
		t.Fatalf("reporting triggers=0x%x err=%v", flags, err)
	}
	threshold, err := NewTotalVolumeThresholdIE(1 << 30)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := threshold.VolumeThreshold()
	if err != nil || !decoded.HasTotal || decoded.Total != 1<<30 || decoded.HasUplink || decoded.HasDownlink {
		t.Fatalf("volume threshold=%+v err=%v", decoded, err)
	}
}

func TestUsageRuleIEsRejectQuotaAndMalformedThresholds(t *testing.T) {
	if _, err := NewMeasurementMethodIE(false, false); err == nil {
		t.Fatal("accepted empty measurement method")
	}
	if _, err := NewReportingTriggersIE(1 << 8); err == nil {
		t.Fatal("accepted unsupported quota trigger")
	}
	if _, err := NewTotalVolumeThresholdIE(0); err == nil {
		t.Fatal("accepted zero volume threshold")
	}
	for _, value := range [][]byte{{}, {0}, {1}, {1, 0, 0, 0, 0, 0, 0, 0, 0}} {
		if _, err := (IE{Type: IEVolumeThreshold, Value: value}).VolumeThreshold(); err == nil {
			t.Fatalf("accepted malformed volume threshold %x", value)
		}
	}
}

func TestPFCPMessageRoundTrip(t *testing.T) {
	m := Message{
		Header: Header{Version: Version, HasSEID: true, MessageType: MessageSessionEstablishmentRequest, SEID: 0, SequenceNumber: 0x010203},
		IEs:    []IE{NewCauseIE(CauseRequestAccepted)},
	}
	wire, err := m.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Header.SequenceNumber != 0x010203 || len(got.IEs) != 1 {
		t.Fatalf("unexpected message: %#v", got)
	}
}

func TestParseIEsRejectsTruncation(t *testing.T) {
	for _, packet := range [][]byte{{0, 1, 0}, {0, 1, 0, 4, 1}} {
		if _, err := ParseIEs(packet); err == nil {
			t.Fatalf("expected parse failure for %x", packet)
		}
	}
}

func FuzzParseIEs(f *testing.F) {
	f.Add([]byte{0, 19, 0, 1, 1})
	f.Add([]byte{0, 56, 0, 2, 0, 1})
	f.Fuzz(func(t *testing.T, packet []byte) {
		ies, err := ParseIEs(packet)
		if err != nil {
			return
		}
		wire, err := MarshalIEs(ies)
		if err != nil {
			t.Fatalf("marshal parsed IEs: %v", err)
		}
		if !bytes.Equal(wire, packet) {
			t.Fatalf("round-trip mismatch: %x != %x", wire, packet)
		}
	})
}

func mustInterfaceIE(t *testing.T, typ uint16, value uint8) IE {
	t.Helper()
	ie, err := NewInterfaceIE(typ, value)
	if err != nil {
		t.Fatal(err)
	}
	return ie
}

func mustPDRIDIE(t *testing.T, id uint16) IE {
	t.Helper()
	ie, err := NewPDRIDIE(id)
	if err != nil {
		t.Fatal(err)
	}
	return ie
}
