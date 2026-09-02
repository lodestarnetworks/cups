package gtpv2

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"
)

func TestPCORoundTripAndDNSResponse(t *testing.T) {
	ipcp := []byte{
		IPCPConfigureRequest, 0x37, 0, 16,
		IPCPOptionPrimaryDNS, 6, 0, 0, 0, 0,
		IPCPOptionSecondDNS, 6, 0, 0, 0, 0,
	}
	request := PCO{
		Extension: true, ConfigurationProtocol: PCOProtocolPPP,
		Containers: []PCOContainer{
			{ID: PCOContainerIPCP, Contents: ipcp},
			{ID: PCOContainerDNSServerIPv4},
			{ID: PCOContainerPCSCFIPv4},
			{ID: PCOContainerIPv4LinkMTU},
		},
	}
	ie, err := NewPCOIE(0, request)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ie.PCO()
	if err != nil {
		t.Fatal(err)
	}
	response, err := BuildPCOResponse(parsed, PCOResponseProfile{
		DNSIPv4:     []netip.Addr{netip.MustParseAddr("10.250.70.1"), netip.MustParseAddr("10.250.70.2")},
		PCSCFIPv4:   []netip.Addr{netip.MustParseAddr("10.250.70.3")},
		IPv4LinkMTU: 1400,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Containers) != 5 {
		t.Fatalf("response containers = %#v", response.Containers)
	}
	gotIPCP := response.Containers[0].Contents
	wantIPCP := []byte{
		IPCPConfigureAck, 0x37, 0, 16,
		IPCPOptionPrimaryDNS, 6, 10, 250, 70, 1,
		IPCPOptionSecondDNS, 6, 10, 250, 70, 2,
	}
	if string(gotIPCP) != string(wantIPCP) {
		t.Fatalf("IPCP response = %x, want %x", gotIPCP, wantIPCP)
	}
	if got := netip.AddrFrom4([4]byte(response.Containers[1].Contents)); got.String() != "10.250.70.1" {
		t.Fatalf("primary direct DNS = %s", got)
	}
	if got := netip.AddrFrom4([4]byte(response.Containers[2].Contents)); got.String() != "10.250.70.2" {
		t.Fatalf("secondary direct DNS = %s", got)
	}
	if got := netip.AddrFrom4([4]byte(response.Containers[3].Contents)); got.String() != "10.250.70.3" {
		t.Fatalf("P-CSCF = %s", got)
	}
	if got := binary.BigEndian.Uint16(response.Containers[4].Contents); got != 1400 {
		t.Fatalf("link MTU = %d", got)
	}
}

func FuzzPCO(f *testing.F) {
	f.Add([]byte{0x80})
	f.Add([]byte{0x80, 0x00, 0x0d, 0x00})
	f.Add([]byte{0x80, 0x80, 0x21, 0x04, 1, 1, 0, 4})
	f.Fuzz(func(t *testing.T, value []byte) {
		parsed, err := (IE{Type: IEPCO, Value: value}).PCO()
		if err != nil {
			return
		}
		encoded, err := NewPCOIE(0, parsed)
		if err != nil {
			t.Fatalf("valid parsed PCO could not be re-encoded: %v", err)
		}
		roundTrip, err := encoded.PCO()
		if err != nil {
			t.Fatalf("re-encoded PCO could not be parsed: %v", err)
		}
		if !reflect.DeepEqual(roundTrip, parsed) {
			t.Fatalf("PCO round trip changed value: got=%#v want=%#v", roundTrip, parsed)
		}
		_, _ = BuildPCOResponse(parsed, PCOResponseProfile{
			DNSIPv4:     []netip.Addr{netip.MustParseAddr("10.250.70.1"), netip.MustParseAddr("10.250.70.2")},
			PCSCFIPv4:   []netip.Addr{netip.MustParseAddr("10.250.70.3")},
			IPv4LinkMTU: 1400,
		})
	})
}

func TestPCORejectsMalformedLengthsAndSpareBits(t *testing.T) {
	for _, value := range [][]byte{
		{},
		{0x88},
		{0x80, 0x00, 0x0d},
		{0x80, 0x00, 0x0d, 0x04, 10, 0},
	} {
		if _, err := (IE{Type: IEPCO, Value: value}).PCO(); err == nil {
			t.Fatalf("malformed PCO accepted: %x", value)
		}
	}
	request := PCO{Extension: true, Containers: []PCOContainer{{
		ID: PCOContainerIPCP, Contents: []byte{IPCPConfigureRequest, 1, 0, 9, IPCPOptionPrimaryDNS, 6, 0, 0, 0, 0},
	}}}
	if _, err := BuildPCOResponse(request, PCOResponseProfile{DNSIPv4: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}); err == nil {
		t.Fatal("malformed IPCP length accepted")
	}
}

func TestAMBRUsesBitsPerSecondAPI(t *testing.T) {
	ie, err := NewAMBRIE(0, 1_000_000_000, 2_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	uplink, downlink, err := ie.AMBR()
	if err != nil || uplink != 1_000_000_000 || downlink != 2_000_000_000 {
		t.Fatalf("AMBR = %d/%d bps, %v", uplink, downlink, err)
	}
	if _, err := NewAMBRIE(0, 1_000_001, 2_000_000); err == nil {
		t.Fatal("sub-kbps AMBR precision was silently lost")
	}
}
