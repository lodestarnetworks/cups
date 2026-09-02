package pfcp

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestSDFFilterRoundTrip(t *testing.T) {
	want := SDFFilter{
		HasFlowDescription: true,
		FlowDescription:    "permit out 17 from 198.51.100.0/24 5060-5061 to assigned 40000",
		HasToSTrafficClass: true,
		ToSTrafficClass:    0xb8,
		ToSTrafficMask:     0xfc,
		HasSPI:             true,
		SPI:                0x01020304,
		HasFlowLabel:       true,
		FlowLabel:          0x0abcde,
		Bidirectional:      true,
		FilterID:           7,
	}
	ie, err := NewSDFFilterIE(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ie.SDFFilter()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
}

func TestParseIPv4FlowDescriptionCanonical(t *testing.T) {
	text := "permit out 17 from 198.51.100.0/24 5060-5061 to assigned 40000"
	got, err := ParseIPv4FlowDescription(text)
	if err != nil {
		t.Fatal(err)
	}
	if got.AnyProtocol || got.Protocol != 17 || !got.SourcePrefix.IsValid() || got.SourcePrefix != netip.MustParsePrefix("198.51.100.0/24") ||
		!got.SourcePort.Present || got.SourcePort.Low != 5060 || got.SourcePort.High != 5061 ||
		!got.DestinationAssigned || !got.DestinationPort.Present || got.DestinationPort.Low != 40000 || got.String() != text {
		t.Fatalf("unexpected parsed description: %#v (%q)", got, got.String())
	}

	any, err := ParseIPv4FlowDescription("permit out ip from any to assigned")
	if err != nil || !any.AnyProtocol || !any.SourceAny || !any.DestinationAssigned {
		t.Fatalf("wildcard description = %#v, err=%v", any, err)
	}
}

func TestSDFFilterRejectsMalformedEncodings(t *testing.T) {
	valid, err := NewSDFFilterIE(SDFFilter{HasFlowDescription: true, FlowDescription: "permit out ip from any to assigned"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []IE{
		{Type: 999, Value: valid.Value},
		{Type: IESDFFilter, Value: nil},
		{Type: IESDFFilter, Value: []byte{0x80, 0}},
		{Type: IESDFFilter, Value: []byte{1, 1, 0, 1, 'x'}},
		{Type: IESDFFilter, Value: []byte{1, 0, 0, 2, 'x'}},
		{Type: IESDFFilter, Value: append(append([]byte(nil), valid.Value...), 0)},
		{Type: IESDFFilter, Value: []byte{8, 0, 0xf0, 0, 0}},
		{Type: IESDFFilter, Value: []byte{16, 0, 0, 0, 0, 0}},
	}
	for index, test := range tests {
		if _, err := test.SDFFilter(); err == nil {
			t.Fatalf("case %d accepted %#v", index, test.Value)
		}
	}
}

func TestParseIPv4FlowDescriptionRejectsUnsupportedGrammar(t *testing.T) {
	tests := []string{
		"deny out ip from any to assigned",
		"permit in ip from any to assigned",
		"permit out ip from any 80 to assigned",
		"permit out 17 from !198.51.100.1 to assigned",
		"permit out 17 from 198.51.100.1,198.51.100.2 to assigned",
		"permit out 17 from 198.51.100.1 90-80 to assigned",
		"permit out 17 from 198.51.100.1 to assigned 080",
		"permit out 17 from 198.51.100.1/24 to assigned",
		"permit out 17 from assigned to any",
		"permit  out 17 from any to assigned",
		"permit out 17 from any to assigned frag",
	}
	for _, test := range tests {
		if _, err := ParseIPv4FlowDescription(test); err == nil {
			t.Errorf("accepted %q", test)
		}
	}
}

func FuzzSDFFilter(f *testing.F) {
	seed, _ := NewSDFFilterIE(SDFFilter{HasFlowDescription: true, FlowDescription: "permit out 17 from any 5060 to assigned 5060"})
	f.Add(seed.Value)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, value []byte) {
		decoded, err := (IE{Type: IESDFFilter, Value: value}).SDFFilter()
		if err != nil {
			return
		}
		encoded, err := NewSDFFilterIE(decoded)
		if err != nil {
			t.Fatalf("accepted value did not re-encode: %v", err)
		}
		if !reflect.DeepEqual(encoded.Value, value) {
			t.Fatalf("non-canonical accepted value: %x -> %x", value, encoded.Value)
		}
	})
}

func FuzzIPv4FlowDescription(f *testing.F) {
	f.Add("permit out ip from any to assigned")
	f.Add("permit out 17 from 198.51.100.0/24 5060 to 10.0.0.1 40000-40010")
	f.Add(strings.Repeat("x", maxFlowDescriptionLength+1))
	f.Fuzz(func(t *testing.T, value string) {
		decoded, err := ParseIPv4FlowDescription(value)
		if err != nil {
			return
		}
		canonical := decoded.String()
		second, err := ParseIPv4FlowDescription(canonical)
		if err != nil {
			t.Fatalf("canonical form rejected: %v", err)
		}
		if !reflect.DeepEqual(decoded, second) {
			t.Fatalf("round-trip mismatch: %#v != %#v", decoded, second)
		}
	})
}
