package gtpv2

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestBearerTFTParsesDirectionsComponentsAndPrecedence(t *testing.T) {
	ie := IE{Type: IEBearerTFT, Value: validBearerTFT()}
	tft, err := ie.BearerTFT()
	if err != nil {
		t.Fatal(err)
	}
	if tft.Operation != TFTOperationCreate || tft.ParametersIncluded || len(tft.Filters) != 2 {
		t.Fatalf("TFT = %#v", tft)
	}
	if tft.Filters[0].ID != 1 || tft.Filters[0].Direction != TFTDirectionDownlink || tft.Filters[0].Precedence != 10 {
		t.Fatalf("downlink filter = %#v", tft.Filters[0])
	}
	if tft.Filters[1].ID != 2 || tft.Filters[1].Direction != TFTDirectionBidirectional || tft.Filters[1].Precedence != 20 {
		t.Fatalf("bidirectional filter = %#v", tft.Filters[1])
	}

	downlink := ipv4UDPPacket(t, "203.0.113.10", "10.90.0.2", 5060, 5060)
	matched, ok, err := tft.MatchIPv4(downlink, TFTDirectionDownlink)
	if err != nil || !ok || matched.ID != 1 {
		t.Fatalf("downlink match = %#v, %v, %v", matched, ok, err)
	}
	uplink := ipv4UDPPacket(t, "10.90.0.2", "198.51.100.20", 5060, 45_000)
	matched, ok, err = tft.MatchIPv4(uplink, TFTDirectionUplink)
	if err != nil || !ok || matched.ID != 2 {
		t.Fatalf("uplink match = %#v, %v, %v", matched, ok, err)
	}

	native := tft.NormalizeDirections(false)
	flipped := tft.NormalizeDirections(true)
	if native.Filters[0].Direction != TFTDirectionDownlink || flipped.Filters[0].Direction != TFTDirectionUplink || tft.Filters[0].Direction != TFTDirectionDownlink {
		t.Fatalf("direction normalization mutated or failed: native=%#v flipped=%#v original=%#v", native.Filters[0], flipped.Filters[0], tft.Filters[0])
	}
}

func TestBearerTFTMarshalRoundTrip(t *testing.T) {
	tft := TrafficFlowTemplate{
		Operation: TFTOperationCreate,
		Filters: []PacketFilter{{
			ID: 1, Direction: TFTDirectionBidirectional, Precedence: 10,
			Components: []PacketFilterComponent{
				{Type: TFTComponentProtocol, Value: []byte{17}},
				{Type: TFTComponentSingleLocalPort, Value: []byte{0x13, 0xc4}},
				{Type: TFTComponentSingleRemotePort, Value: []byte{0x13, 0xc5}},
			},
		}},
	}
	encoded, err := MarshalBearerTFT(tft)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseBearerTFT(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Filters) != 1 || decoded.Filters[0].Direction != TFTDirectionBidirectional || len(decoded.Filters[0].Components) != 3 {
		t.Fatalf("round-trip TFT = %#v", decoded)
	}
	ie, err := NewBearerTFTIE(0, tft)
	if err != nil || ie.Type != IEBearerTFT {
		t.Fatalf("Bearer TFT IE = %#v, %v", ie, err)
	}
}

func TestBearerTFTMarshalRejectsNonCanonicalInput(t *testing.T) {
	tests := []TrafficFlowTemplate{
		{Operation: TFTOperationIgnore, Filters: []PacketFilter{{ID: 1}}},
		{Operation: TFTOperationCreate},
		{Operation: TFTOperationCreate, ParametersIncluded: true, Filters: []PacketFilter{{ID: 1}}},
		{Operation: TFTOperationCreate, Filters: []PacketFilter{{ID: 1, Direction: TFTDirectionDownlink, Components: []PacketFilterComponent{{Type: TFTComponentProtocol, Value: nil}}}}},
	}
	for index, input := range tests {
		if _, err := MarshalBearerTFT(input); err == nil {
			t.Fatalf("invalid TFT %d was encoded", index)
		}
	}
}

func TestBearerTFTDeleteAndParameterOperations(t *testing.T) {
	deleted, err := ParseBearerTFT([]byte{0xa2, 0x01, 0x02})
	if err != nil || len(deleted.DeleteFilterIDs) != 2 || deleted.DeleteFilterIDs[0] != 1 || deleted.DeleteFilterIDs[1] != 2 {
		t.Fatalf("delete TFT = %#v, %v", deleted, err)
	}
	parameterOnly, err := ParseBearerTFT([]byte{0xd0, 0x01, 0x01, 0x42})
	if err != nil || parameterOnly.Operation != TFTOperationNoOperation || len(parameterOnly.Parameters) != 1 || parameterOnly.Parameters[0].Value[0] != 0x42 {
		t.Fatalf("parameter TFT = %#v, %v", parameterOnly, err)
	}
}

func TestBearerTFTRejectsMalformedEncodings(t *testing.T) {
	tests := map[string][]byte{
		"empty":                    {},
		"reserved operation":       {0xe0},
		"create without filters":   {0x20},
		"delete with filter count": {0x41},
		"no-op without parameters": {0xc0},
		"filter spare bits":        {0x21, 0x41, 1, 2, 0x30, 17},
		"duplicate filter id":      {0x22, 0x11, 1, 2, 0x30, 17, 0x11, 2, 2, 0x30, 6},
		"duplicate precedence":     {0x22, 0x11, 1, 2, 0x30, 17, 0x12, 1, 2, 0x30, 6},
		"zero content":             {0x21, 0x11, 1, 0},
		"truncated component":      {0x21, 0x11, 1, 1, 0x30},
		"reserved component":       {0x21, 0x11, 1, 2, 0x31, 0},
		"duplicate component":      {0x21, 0x11, 1, 4, 0x30, 17, 0x30, 6},
		"two local port forms":     {0x21, 0x11, 1, 8, 0x40, 0, 1, 0x41, 0, 1, 0, 2},
		"descending port range":    {0x21, 0x11, 1, 5, 0x51, 0, 2, 0, 1},
		"trailing without E bit":   {0x21, 0x11, 1, 2, 0x30, 17, 0xff},
		"E bit without parameter":  {0x31, 0x11, 1, 2, 0x30, 17},
		"truncated parameter":      {0x31, 0x11, 1, 2, 0x30, 17, 1, 3, 1, 2},
		"non-IP with IP component": {0x21, 0x11, 1, 5, 0x87, 0x08, 0x06, 0x30, 17},
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBearerTFT(value); !errors.Is(err, ErrMalformedIE) {
				t.Fatalf("error = %v, want ErrMalformedIE", err)
			}
		})
	}
	if _, err := (IE{Type: IEAPN, Value: []byte{0}}).BearerTFT(); !errors.Is(err, ErrMalformedIE) {
		t.Fatalf("wrong IE error = %v", err)
	}
}

func TestIPv4TFTMatchUsesUERelativePortsAndAddressMasks(t *testing.T) {
	tft, err := ParseBearerTFT(validBearerTFT())
	if err != nil {
		t.Fatal(err)
	}
	filter, err := tft.Filters[0].IPv4()
	if err != nil {
		t.Fatal(err)
	}
	if !filter.Matches(ipv4UDPPacket(t, "203.0.113.99", "10.90.0.2", 5061, 5060), TFTDirectionDownlink) {
		t.Fatal("valid masked remote address/port did not match")
	}
	if filter.Matches(ipv4UDPPacket(t, "192.0.2.1", "10.90.0.2", 5061, 5060), TFTDirectionDownlink) {
		t.Fatal("address outside remote mask matched")
	}
	if filter.Matches(ipv4UDPPacket(t, "203.0.113.99", "10.90.0.2", 5061, 5061), TFTDirectionDownlink) {
		t.Fatal("wrong UE-local destination port matched")
	}
}

func FuzzBearerTFT(f *testing.F) {
	f.Add(validBearerTFT())
	f.Add([]byte{0xa1, 0x01})
	f.Add([]byte{0xd0, 1, 1, 0x42})
	f.Fuzz(func(t *testing.T, value []byte) {
		tft, err := ParseBearerTFT(value)
		if err != nil {
			return
		}
		for _, filter := range tft.Filters {
			ipv4, err := filter.IPv4()
			if err == nil {
				_ = ipv4.Matches(make([]byte, 64), TFTDirectionDownlink)
			}
		}
	})
}

func validBearerTFT() []byte {
	return []byte{
		0x22,
		0x11, 10, 19,
		TFTComponentIPv4RemoteAddress, 203, 0, 113, 0, 255, 255, 255, 0,
		TFTComponentProtocol, 17,
		TFTComponentSingleLocalPort, 0x13, 0xc4,
		TFTComponentRemotePortRange, 0x13, 0xc4, 0x13, 0xc5,
		0x32, 20, 10,
		TFTComponentProtocol, 17,
		TFTComponentSingleLocalPort, 0x13, 0xc4,
		TFTComponentRemotePortRange, 0x9c, 0x40, 0xc3, 0x50,
	}
}

func ipv4UDPPacket(t *testing.T, source, destination string, sourcePort, destinationPort uint16) []byte {
	t.Helper()
	src := netip.MustParseAddr(source).As4()
	dst := netip.MustParseAddr(destination).As4()
	packet := make([]byte, 28)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint16(packet[24:26], 8)
	return packet
}
