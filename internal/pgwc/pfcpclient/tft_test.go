package pfcpclient

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/lodestarnetworks/cups/pkg/gtpv2"
)

func TestSDFPlansFromTFTPreservesUERelativeDirection(t *testing.T) {
	filter := gtpv2.PacketFilter{
		ID: 3, Direction: gtpv2.TFTDirectionDownlink, Precedence: 7,
		Components: []gtpv2.PacketFilterComponent{
			{Type: gtpv2.TFTComponentIPv4RemoteAddress, Value: addressAndMask("198.51.100.10", "255.255.255.0")},
			{Type: gtpv2.TFTComponentProtocol, Value: []byte{17}},
			{Type: gtpv2.TFTComponentSingleRemotePort, Value: port(5060)},
			{Type: gtpv2.TFTComponentSingleLocalPort, Value: port(40000)},
			{Type: gtpv2.TFTComponentTypeOfService, Value: []byte{0xb8, 0xfc}},
		},
	}
	plans, err := SDFPlansFromTFT(gtpv2.TrafficFlowTemplate{Operation: gtpv2.TFTOperationCreate, Filters: []gtpv2.PacketFilter{filter}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 || plans[0].PacketFilterID != 3 || plans[0].Direction != gtpv2.TFTDirectionDownlink || plans[0].Precedence != 7 {
		t.Fatalf("unexpected plans: %#v", plans)
	}
	if got, want := plans[0].Filter.FlowDescription, "permit out 17 from 198.51.100.0/24 5060 to assigned 40000"; got != want {
		t.Fatalf("flow description = %q, want %q", got, want)
	}
	if !plans[0].Filter.HasToSTrafficClass || plans[0].Filter.ToSTrafficClass != 0xb8 || plans[0].Filter.ToSTrafficMask != 0xfc {
		t.Fatalf("ToS metadata lost: %#v", plans[0].Filter)
	}
}

func TestSDFPlansFromTFTExpandsProtocolWildcardWithPorts(t *testing.T) {
	filter := gtpv2.PacketFilter{
		ID: 1, Direction: gtpv2.TFTDirectionBidirectional, Precedence: 10,
		Components: []gtpv2.PacketFilterComponent{{Type: gtpv2.TFTComponentSingleRemotePort, Value: port(53)}},
	}
	plans, err := SDFPlansFromTFT(gtpv2.TrafficFlowTemplate{Operation: gtpv2.TFTOperationCreate, Filters: []gtpv2.PacketFilter{filter}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 2 || !strings.Contains(plans[0].Filter.FlowDescription, "out 6 ") || !strings.Contains(plans[1].Filter.FlowDescription, "out 17 ") {
		t.Fatalf("wildcard port filter was not expanded to TCP and UDP: %#v", plans)
	}
}

func TestSDFPlansFromTFTRejectsUnsafeMappings(t *testing.T) {
	tests := []gtpv2.PacketFilter{
		{ID: 1, Direction: gtpv2.TFTDirectionPreRelease7, Components: []gtpv2.PacketFilterComponent{{Type: gtpv2.TFTComponentProtocol, Value: []byte{17}}}},
		{ID: 1, Direction: gtpv2.TFTDirectionDownlink, Components: []gtpv2.PacketFilterComponent{{Type: gtpv2.TFTComponentIPv4RemoteAddress, Value: addressAndMask("198.51.100.1", "255.0.255.0")}}},
		{ID: 1, Direction: gtpv2.TFTDirectionDownlink, Components: []gtpv2.PacketFilterComponent{{Type: gtpv2.TFTComponentProtocol, Value: []byte{1}}, {Type: gtpv2.TFTComponentSingleRemotePort, Value: port(80)}}},
		{ID: 1, Direction: gtpv2.TFTDirectionDownlink, Components: []gtpv2.PacketFilterComponent{{Type: gtpv2.TFTComponentSecurityParameterIndex, Value: []byte{0, 0, 0, 1}}}},
	}
	for index, filter := range tests {
		if _, err := SDFPlansFromTFT(gtpv2.TrafficFlowTemplate{Operation: gtpv2.TFTOperationCreate, Filters: []gtpv2.PacketFilter{filter}}); err == nil {
			t.Errorf("case %d was accepted", index)
		}
	}
}

func addressAndMask(address, mask string) []byte {
	addressBytes, maskBytes := netip.MustParseAddr(address).As4(), netip.MustParseAddr(mask).As4()
	return append(append([]byte(nil), addressBytes[:]...), maskBytes[:]...)
}

func port(value uint16) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, value)
	return out
}
