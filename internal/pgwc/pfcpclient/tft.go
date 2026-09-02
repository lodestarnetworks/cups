package pfcpclient

import (
	"fmt"
	"net/netip"

	"github.com/lodestarnetworks/cups/pkg/gtpv2"
	"github.com/lodestarnetworks/cups/pkg/pfcp"
)

// SDFPlan is one standards-based PFCP packet-filter instruction derived from
// a TS 24.008 TFT packet filter. A packet filter without an explicit protocol
// and with ports expands into separate TCP and UDP plans because RFC 6733 does
// not permit port matching with the wildcard "ip" protocol.
type SDFPlan struct {
	PacketFilterID uint8
	Direction      gtpv2.TFTDirection
	Precedence     uint32
	Filter         pfcp.SDFFilter
}

func SDFPlansFromTFT(tft gtpv2.TrafficFlowTemplate) ([]SDFPlan, error) {
	switch tft.Operation {
	case gtpv2.TFTOperationCreate, gtpv2.TFTOperationAddFilters, gtpv2.TFTOperationReplaceFilters:
	default:
		return nil, fmt.Errorf("pgwc PFCP: TFT operation %d does not install packet filters", tft.Operation)
	}
	if len(tft.Filters) == 0 {
		return nil, fmt.Errorf("pgwc PFCP: TFT has no packet filters")
	}
	plans := make([]SDFPlan, 0, len(tft.Filters))
	for index, packetFilter := range tft.Filters {
		if packetFilter.Direction != gtpv2.TFTDirectionDownlink && packetFilter.Direction != gtpv2.TFTDirectionUplink && packetFilter.Direction != gtpv2.TFTDirectionBidirectional {
			return nil, fmt.Errorf("pgwc PFCP: packet filter %d has unsupported direction %d", index, packetFilter.Direction)
		}
		filter, err := packetFilter.IPv4()
		if err != nil {
			return nil, fmt.Errorf("pgwc PFCP: packet filter %d: %w", index, err)
		}
		descriptions, err := flowDescriptions(filter)
		if err != nil {
			return nil, fmt.Errorf("pgwc PFCP: packet filter %d: %w", index, err)
		}
		for _, description := range descriptions {
			plans = append(plans, SDFPlan{
				PacketFilterID: packetFilter.ID,
				Direction:      packetFilter.Direction,
				Precedence:     uint32(packetFilter.Precedence),
				Filter: pfcp.SDFFilter{
					HasFlowDescription: true,
					FlowDescription:    description.String(),
					HasToSTrafficClass: filter.HasTypeOfService,
					ToSTrafficClass:    filter.TypeOfService,
					ToSTrafficMask:     filter.TypeOfServiceMask,
				},
			})
		}
	}
	return plans, nil
}

func flowDescriptions(filter gtpv2.IPv4PacketFilter) ([]pfcp.IPv4FlowDescription, error) {
	base := pfcp.IPv4FlowDescription{}
	var err error
	if filter.HasRemoteAddress {
		base.SourceAny, base.SourcePrefix, err = flowPrefix(filter.RemoteAddress, filter.RemoteAddressMask)
		if err != nil {
			return nil, fmt.Errorf("remote address: %w", err)
		}
	} else {
		base.SourceAny = true
	}
	if filter.HasLocalAddress {
		base.DestinationAny, base.DestinationPrefix, err = flowPrefix(filter.LocalAddress, filter.LocalAddressMask)
		if err != nil {
			return nil, fmt.Errorf("local address: %w", err)
		}
	} else {
		base.DestinationAssigned = true
	}
	if filter.HasRemotePort {
		base.SourcePort = pfcp.PortRange{Present: true, Low: filter.RemotePortLow, High: filter.RemotePortHigh}
	}
	if filter.HasLocalPort {
		base.DestinationPort = pfcp.PortRange{Present: true, Low: filter.LocalPortLow, High: filter.LocalPortHigh}
	}
	hasPorts := filter.HasRemotePort || filter.HasLocalPort
	if filter.HasProtocol {
		if hasPorts && filter.Protocol != 6 && filter.Protocol != 17 && filter.Protocol != 132 {
			return nil, fmt.Errorf("port components require TCP, UDP, or SCTP, got protocol %d", filter.Protocol)
		}
		base.Protocol = filter.Protocol
		return []pfcp.IPv4FlowDescription{base}, nil
	}
	if !hasPorts {
		base.AnyProtocol = true
		return []pfcp.IPv4FlowDescription{base}, nil
	}
	tcp, udp := base, base
	tcp.Protocol, udp.Protocol = 6, 17
	return []pfcp.IPv4FlowDescription{tcp, udp}, nil
}

func flowPrefix(address, mask netip.Addr) (bool, netip.Prefix, error) {
	if !address.Is4() || !mask.Is4() {
		return false, netip.Prefix{}, fmt.Errorf("IPv4 address and mask required")
	}
	addressBytes, maskBytes := address.As4(), mask.As4()
	bits := 0
	zeroSeen := false
	var network [4]byte
	for index := range maskBytes {
		network[index] = addressBytes[index] & maskBytes[index]
		for shift := 7; shift >= 0; shift-- {
			set := maskBytes[index]&(1<<shift) != 0
			if zeroSeen && set {
				return false, netip.Prefix{}, fmt.Errorf("non-contiguous IPv4 mask %s", mask)
			}
			if set {
				bits++
			} else {
				zeroSeen = true
			}
		}
	}
	if bits == 0 {
		return true, netip.Prefix{}, nil
	}
	return false, netip.PrefixFrom(netip.AddrFrom4(network), bits), nil
}
