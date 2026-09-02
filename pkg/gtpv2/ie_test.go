package gtpv2

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestIEsRoundTripAndUnknownPreservation(t *testing.T) {
	fteid, err := NewFTEIDIE(0, FTEID{
		InterfaceType: InterfaceS11MMEGTPC,
		TEID:          0x10203040,
		IPv4:          netip.MustParseAddr("10.200.0.10"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ies := []IE{
		{Type: 200, Instance: 9, Value: []byte{1, 2, 3}},
		fteid,
	}
	wire, err := MarshalIEs(ies)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseIEs(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(ies) || !bytes.Equal(got[0].Value, ies[0].Value) {
		t.Fatalf("unexpected decoded IEs: %#v", got)
	}
	decoded, err := got[1].FTEID()
	if err != nil {
		t.Fatal(err)
	}
	if decoded.TEID != 0x10203040 || decoded.IPv4.String() != "10.200.0.10" || decoded.InterfaceType != InterfaceS11MMEGTPC {
		t.Fatalf("unexpected F-TEID: %#v", decoded)
	}
}

func TestGroupedBearerContextAndUpsert(t *testing.T) {
	ebi, err := NewEBIIE(5, 0)
	if err != nil {
		t.Fatal(err)
	}
	grouped, err := NewGroupedIE(IEBearerContext, 0, ebi, NewCauseIE(CauseRequestAccepted, 0))
	if err != nil {
		t.Fatal(err)
	}
	children, err := grouped.Children()
	if err != nil {
		t.Fatal(err)
	}
	children = UpsertIE(children, NewCauseIE(CauseSystemFailure, 0))
	if len(children) != 2 {
		t.Fatalf("upsert introduced duplicate: %#v", children)
	}
	causeIE, ok := FindIE(children, IECause, 0)
	if !ok {
		t.Fatal("cause not found")
	}
	cause, err := causeIE.Cause()
	if err != nil || cause.Value != CauseSystemFailure {
		t.Fatalf("unexpected cause: %#v, %v", cause, err)
	}
}

func TestIMSIAndAPNRoundTrip(t *testing.T) {
	imsi, err := NewIMSIIE("234150999999999")
	if err != nil {
		t.Fatal(err)
	}
	gotIMSI, err := imsi.IMSI()
	if err != nil || gotIMSI != "234150999999999" {
		t.Fatalf("unexpected IMSI %q: %v", gotIMSI, err)
	}
	apn, err := NewAPNIE("internet.mnc015.mcc234.gprs")
	if err != nil {
		t.Fatal(err)
	}
	gotAPN, err := apn.APN()
	if err != nil || gotAPN != "internet.mnc015.mcc234.gprs" {
		t.Fatalf("unexpected APN %q: %v", gotAPN, err)
	}
}

func TestBearerQoSBitratesAndUnassignedEBI(t *testing.T) {
	ie, err := NewBearerQoSIEWithBitrates(0, 1, 2, 8_000_000, 12_000_000, 3_000_000, 4_000_000)
	if err != nil {
		t.Fatal(err)
	}
	qos, err := ie.BearerQoSDetails()
	if err != nil {
		t.Fatal(err)
	}
	if qos.QCI != 1 || qos.Priority != 2 || qos.UplinkMBR != 8_000_000 || qos.DownlinkMBR != 12_000_000 || qos.UplinkGBR != 3_000_000 || qos.DownlinkGBR != 4_000_000 {
		t.Fatalf("unexpected Bearer QoS: %#v", qos)
	}
	unassigned := IE{Type: IEEBI, Value: []byte{0}}
	if got, err := unassigned.EBIOrZero(); err != nil || got != 0 {
		t.Fatalf("unassigned EBI = %d, %v", got, err)
	}
	if _, err := unassigned.EBI(); err == nil {
		t.Fatal("established EBI decoder accepted zero")
	}
}

func TestAllocationRetentionPriorityRoundTrip(t *testing.T) {
	ie, err := NewARPIE(0, 2, true, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ie.AllocationRetentionPriority()
	if err != nil {
		t.Fatal(err)
	}
	if got.Priority != 2 || !got.PreemptionCapable || got.PreemptionVulnerable {
		t.Fatalf("ARP = %#v", got)
	}
}

func TestPDNTypeAndPAAIPv4RoundTrip(t *testing.T) {
	pdnType, err := NewPDNTypeIE(0, PDNTypeIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := pdnType.PDNType(); err != nil || got != PDNTypeIPv4 {
		t.Fatalf("PDN type = %d, %v", got, err)
	}

	want := netip.MustParseAddr("10.90.0.23")
	paa, err := NewPAAIPv4IE(0, want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(paa.Value, []byte{PDNTypeIPv4, 10, 90, 0, 23}) {
		t.Fatalf("unexpected PAA wire value: %x", paa.Value)
	}
	got, err := paa.PAAIPv4()
	if err != nil || got != want {
		t.Fatalf("PAA IPv4 = %s, %v", got, err)
	}
}

func TestPDNTypeAndPAARejectMalformedValues(t *testing.T) {
	for _, ie := range []IE{
		{Type: IEPDNType, Value: nil},
		{Type: IEPDNType, Value: []byte{0}},
		{Type: IEPDNType, Value: []byte{0x81}},
		{Type: IEPAA, Value: []byte{PDNTypeIPv4, 10, 0, 0}},
		{Type: IEPAA, Value: []byte{PDNTypeIPv6, 10, 0, 0, 1}},
		{Type: IEPAA, Value: []byte{PDNTypeIPv4, 0, 0, 0, 0}},
	} {
		if ie.Type == IEPDNType {
			if _, err := ie.PDNType(); err == nil {
				t.Fatalf("accepted malformed PDN Type: %x", ie.Value)
			}
			continue
		}
		if _, err := ie.PAAIPv4(); err == nil {
			t.Fatalf("accepted malformed PAA: %x", ie.Value)
		}
	}
}

func TestParseIEsRejectsTruncation(t *testing.T) {
	for _, packet := range [][]byte{
		{1},
		{1, 0, 4, 0, 1},
		{87, 0, 5, 0, 0x80, 0, 0, 0},
	} {
		if _, err := ParseIEs(packet); err == nil {
			t.Fatalf("expected error for %x", packet)
		}
	}
}

func TestMessageRoundTrip(t *testing.T) {
	imsi, err := NewIMSIIE("001010123456789")
	if err != nil {
		t.Fatal(err)
	}
	m := Message{
		Header: Header{Version: Version, HasTEID: true, MessageType: MessageCreateSessionRequest, TEID: 0, SequenceNumber: 0x010203},
		IEs:    []IE{imsi},
	}
	wire, err := m.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseMessage(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Header.SequenceNumber != m.Header.SequenceNumber || len(got.IEs) != 1 {
		t.Fatalf("unexpected message: %#v", got)
	}
}

func FuzzParseIEs(f *testing.F) {
	f.Add([]byte{1, 0, 1, 0, 0x21})
	f.Add([]byte{93, 0, 5, 0, 73, 0, 1, 0, 5})
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
