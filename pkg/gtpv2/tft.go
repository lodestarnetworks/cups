package gtpv2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

// Traffic Flow Template operation codes and packet-filter directions are
// encoded as specified by TS 24.008 clause 10.5.6.12. A Bearer TFT GTPv2 IE
// starts at octet 3 of that encoding, so Value[0] contains these fields.
const (
	TFTOperationIgnore         uint8 = 0
	TFTOperationCreate         uint8 = 1
	TFTOperationDelete         uint8 = 2
	TFTOperationAddFilters     uint8 = 3
	TFTOperationReplaceFilters uint8 = 4
	TFTOperationDeleteFilters  uint8 = 5
	TFTOperationNoOperation    uint8 = 6
)

type TFTDirection uint8

const (
	TFTDirectionPreRelease7   TFTDirection = 0
	TFTDirectionDownlink      TFTDirection = 1
	TFTDirectionUplink        TFTDirection = 2
	TFTDirectionBidirectional TFTDirection = 3
)

// TS 24.008 packet-filter component type identifiers.
const (
	TFTComponentIPv4RemoteAddress      uint8 = 0x10
	TFTComponentIPv4LocalAddress       uint8 = 0x11
	TFTComponentIPv6RemoteAddress      uint8 = 0x20
	TFTComponentIPv6RemotePrefix       uint8 = 0x21
	TFTComponentIPv6LocalPrefix        uint8 = 0x23
	TFTComponentProtocol               uint8 = 0x30
	TFTComponentSingleLocalPort        uint8 = 0x40
	TFTComponentLocalPortRange         uint8 = 0x41
	TFTComponentSingleRemotePort       uint8 = 0x50
	TFTComponentRemotePortRange        uint8 = 0x51
	TFTComponentSecurityParameterIndex uint8 = 0x60
	TFTComponentTypeOfService          uint8 = 0x70
	TFTComponentFlowLabel              uint8 = 0x80
	TFTComponentDestinationMAC         uint8 = 0x81
	TFTComponentSourceMAC              uint8 = 0x82
	TFTComponentCustomerVLANID         uint8 = 0x83
	TFTComponentServiceVLANID          uint8 = 0x84
	TFTComponentCustomerVLANPriority   uint8 = 0x85
	TFTComponentServiceVLANPriority    uint8 = 0x86
	TFTComponentEtherType              uint8 = 0x87
)

var ErrUnsupportedTFTComponent = errors.New("gtpv2: TFT component is unsupported by IPv4 classifier")

type TrafficFlowTemplate struct {
	Operation          uint8
	ParametersIncluded bool
	Filters            []PacketFilter
	DeleteFilterIDs    []uint8
	Parameters         []TFTParameter
}

type PacketFilter struct {
	ID         uint8
	Direction  TFTDirection
	Precedence uint8
	Components []PacketFilterComponent
}

type PacketFilterComponent struct {
	Type  uint8
	Value []byte
}

type TFTParameter struct {
	ID    uint8
	Value []byte
}

// IPv4PacketFilter is the production-safe subset needed to classify LTE IPv4
// traffic. "Local" always means the UE and "remote" means the external
// network, independent of packet direction.
type IPv4PacketFilter struct {
	ID         uint8
	Direction  TFTDirection
	Precedence uint8

	HasLocalAddress   bool
	LocalAddress      netip.Addr
	LocalAddressMask  netip.Addr
	HasRemoteAddress  bool
	RemoteAddress     netip.Addr
	RemoteAddressMask netip.Addr

	HasProtocol bool
	Protocol    uint8

	HasLocalPort   bool
	LocalPortLow   uint16
	LocalPortHigh  uint16
	HasRemotePort  bool
	RemotePortLow  uint16
	RemotePortHigh uint16

	HasTypeOfService  bool
	TypeOfService     uint8
	TypeOfServiceMask uint8
}

func (ie IE) BearerTFT() (TrafficFlowTemplate, error) {
	if ie.Type != IEBearerTFT {
		return TrafficFlowTemplate{}, fmt.Errorf("%w: IE type %d is not Bearer TFT", ErrMalformedIE, ie.Type)
	}
	return ParseBearerTFT(ie.Value)
}

// ParseBearerTFT parses the value field copied from TS 24.008 octet 3. It
// rejects reserved encodings, truncation, duplicate identifiers/components,
// invalid component combinations, and trailing bytes not protected by the E
// bit. The input is capped by the one-octet TFT length from TS 24.008.
func ParseBearerTFT(value []byte) (TrafficFlowTemplate, error) {
	if len(value) == 0 || len(value) > 255 {
		return TrafficFlowTemplate{}, malformedTFT("value length %d is outside 1..255", len(value))
	}
	first := value[0]
	out := TrafficFlowTemplate{
		Operation:          first >> 5,
		ParametersIncluded: first&0x10 != 0,
	}
	count := int(first & 0x0f)
	if out.Operation > TFTOperationNoOperation {
		return TrafficFlowTemplate{}, malformedTFT("reserved operation %d", out.Operation)
	}
	if out.Operation == TFTOperationIgnore {
		if out.ParametersIncluded || count != 0 || len(value) != 1 {
			return TrafficFlowTemplate{}, malformedTFT("ignore operation must contain only a zero control octet")
		}
		return out, nil
	}
	if out.Operation == TFTOperationDelete || out.Operation == TFTOperationNoOperation {
		if count != 0 {
			return TrafficFlowTemplate{}, malformedTFT("operation %d requires zero packet filters", out.Operation)
		}
	} else if count == 0 {
		return TrafficFlowTemplate{}, malformedTFT("operation %d requires at least one packet filter", out.Operation)
	}
	if out.Operation == TFTOperationNoOperation && !out.ParametersIncluded {
		return TrafficFlowTemplate{}, malformedTFT("no-operation TFT requires a parameters list")
	}

	offset := 1
	if out.Operation == TFTOperationDeleteFilters {
		out.DeleteFilterIDs = make([]uint8, 0, count)
		seen := make(map[uint8]struct{}, count)
		for index := 0; index < count; index++ {
			if offset >= len(value) {
				return TrafficFlowTemplate{}, malformedTFT("truncated delete-filter identifier %d", index)
			}
			encoded := value[offset]
			offset++
			if encoded&0xf0 != 0 {
				return TrafficFlowTemplate{}, malformedTFT("delete-filter identifier has non-zero spare bits")
			}
			id := encoded & 0x0f
			if _, duplicate := seen[id]; duplicate {
				return TrafficFlowTemplate{}, malformedTFT("duplicate packet-filter identifier %d", id)
			}
			seen[id] = struct{}{}
			out.DeleteFilterIDs = append(out.DeleteFilterIDs, id)
		}
	} else if out.Operation == TFTOperationCreate || out.Operation == TFTOperationAddFilters || out.Operation == TFTOperationReplaceFilters {
		out.Filters = make([]PacketFilter, 0, count)
		ids := make(map[uint8]struct{}, count)
		precedences := make(map[uint8]struct{}, count)
		for index := 0; index < count; index++ {
			if len(value)-offset < 3 {
				return TrafficFlowTemplate{}, malformedTFT("truncated packet-filter header %d", index)
			}
			identity := value[offset]
			precedence := value[offset+1]
			contentLength := int(value[offset+2])
			offset += 3
			if identity&0xc0 != 0 {
				return TrafficFlowTemplate{}, malformedTFT("packet filter %d has non-zero spare bits", index)
			}
			if contentLength == 0 || contentLength > len(value)-offset {
				return TrafficFlowTemplate{}, malformedTFT("packet filter %d content length %d exceeds %d", index, contentLength, len(value)-offset)
			}
			filter := PacketFilter{
				ID: identity & 0x0f, Direction: TFTDirection((identity >> 4) & 0x03), Precedence: precedence,
			}
			if _, duplicate := ids[filter.ID]; duplicate {
				return TrafficFlowTemplate{}, malformedTFT("duplicate packet-filter identifier %d", filter.ID)
			}
			if _, duplicate := precedences[filter.Precedence]; duplicate {
				return TrafficFlowTemplate{}, malformedTFT("duplicate packet-filter precedence %d", filter.Precedence)
			}
			ids[filter.ID] = struct{}{}
			precedences[filter.Precedence] = struct{}{}
			components, err := parseTFTComponents(value[offset : offset+contentLength])
			if err != nil {
				return TrafficFlowTemplate{}, fmt.Errorf("packet filter %d: %w", index, err)
			}
			filter.Components = components
			out.Filters = append(out.Filters, filter)
			offset += contentLength
		}
	}

	if out.ParametersIncluded {
		if offset == len(value) {
			return TrafficFlowTemplate{}, malformedTFT("E bit set without a parameter")
		}
		for offset < len(value) {
			if len(value)-offset < 2 {
				return TrafficFlowTemplate{}, malformedTFT("truncated parameter header")
			}
			id := value[offset]
			length := int(value[offset+1])
			offset += 2
			if length > len(value)-offset {
				return TrafficFlowTemplate{}, malformedTFT("parameter %d length %d exceeds %d", id, length, len(value)-offset)
			}
			out.Parameters = append(out.Parameters, TFTParameter{ID: id, Value: append([]byte(nil), value[offset:offset+length]...)})
			offset += length
		}
	} else if offset != len(value) {
		return TrafficFlowTemplate{}, malformedTFT("%d trailing bytes without E bit", len(value)-offset)
	}
	return out, nil
}

// MarshalBearerTFT serializes the TS 24.008 Bearer TFT value carried after
// the GTPv2 IE header. It is deliberately strict: fields which do not belong
// to the selected operation, overlong components, and non-canonical control
// flags are rejected before a message can reach a peer.
func MarshalBearerTFT(tft TrafficFlowTemplate) ([]byte, error) {
	if tft.Operation > TFTOperationNoOperation {
		return nil, malformedTFT("reserved operation %d", tft.Operation)
	}
	if tft.ParametersIncluded != (len(tft.Parameters) != 0) {
		return nil, malformedTFT("parameters flag does not match the parameters list")
	}
	if len(tft.Filters) > 15 || len(tft.DeleteFilterIDs) > 15 {
		return nil, malformedTFT("packet-filter count exceeds 15")
	}

	count := 0
	switch tft.Operation {
	case TFTOperationIgnore:
		if len(tft.Filters) != 0 || len(tft.DeleteFilterIDs) != 0 || len(tft.Parameters) != 0 {
			return nil, malformedTFT("ignore operation contains data")
		}
	case TFTOperationCreate, TFTOperationAddFilters, TFTOperationReplaceFilters:
		if len(tft.Filters) == 0 || len(tft.DeleteFilterIDs) != 0 {
			return nil, malformedTFT("operation %d requires only packet filters", tft.Operation)
		}
		count = len(tft.Filters)
	case TFTOperationDelete:
		if len(tft.Filters) != 0 || len(tft.DeleteFilterIDs) != 0 {
			return nil, malformedTFT("delete operation cannot contain packet filters")
		}
	case TFTOperationDeleteFilters:
		if len(tft.DeleteFilterIDs) == 0 || len(tft.Filters) != 0 {
			return nil, malformedTFT("delete-filters operation requires only filter identifiers")
		}
		count = len(tft.DeleteFilterIDs)
	case TFTOperationNoOperation:
		if len(tft.Filters) != 0 || len(tft.DeleteFilterIDs) != 0 || len(tft.Parameters) == 0 {
			return nil, malformedTFT("no-operation requires only parameters")
		}
	}

	control := tft.Operation<<5 | uint8(count)
	if tft.ParametersIncluded {
		control |= 0x10
	}
	out := []byte{control}
	switch tft.Operation {
	case TFTOperationCreate, TFTOperationAddFilters, TFTOperationReplaceFilters:
		for index, filter := range tft.Filters {
			if filter.ID > 15 || filter.Direction > TFTDirectionBidirectional {
				return nil, malformedTFT("packet filter %d has invalid identity or direction", index)
			}
			contents := make([]byte, 0, 32)
			for _, component := range filter.Components {
				expected, ok := tftComponentLength(component.Type)
				if !ok || len(component.Value) != expected {
					return nil, malformedTFT("packet filter %d component %#x has length %d, expected %d", index, component.Type, len(component.Value), expected)
				}
				contents = append(contents, component.Type)
				contents = append(contents, component.Value...)
			}
			if len(contents) == 0 || len(contents) > 255 {
				return nil, malformedTFT("packet filter %d content length %d is outside 1..255", index, len(contents))
			}
			out = append(out, byte(filter.Direction)<<4|filter.ID, filter.Precedence, byte(len(contents)))
			out = append(out, contents...)
		}
	case TFTOperationDeleteFilters:
		for _, id := range tft.DeleteFilterIDs {
			if id > 15 {
				return nil, malformedTFT("delete-filter identifier %d exceeds 15", id)
			}
			out = append(out, id)
		}
	}
	for _, parameter := range tft.Parameters {
		if len(parameter.Value) > 255 {
			return nil, malformedTFT("parameter %d length %d exceeds 255", parameter.ID, len(parameter.Value))
		}
		out = append(out, parameter.ID, byte(len(parameter.Value)))
		out = append(out, parameter.Value...)
	}
	if len(out) > 255 {
		return nil, malformedTFT("encoded value length %d exceeds 255", len(out))
	}
	if _, err := ParseBearerTFT(out); err != nil {
		return nil, err
	}
	return out, nil
}

func NewBearerTFTIE(instance uint8, tft TrafficFlowTemplate) (IE, error) {
	if instance > 15 {
		return IE{}, fmt.Errorf("%w: Bearer TFT instance %d exceeds 15", ErrMalformedIE, instance)
	}
	value, err := MarshalBearerTFT(tft)
	if err != nil {
		return IE{}, err
	}
	return IE{Type: IEBearerTFT, Instance: instance, Value: value}, nil
}

func parseTFTComponents(contents []byte) ([]PacketFilterComponent, error) {
	components := make([]PacketFilterComponent, 0, 8)
	seen := make(map[uint8]struct{}, 8)
	for offset := 0; offset < len(contents); {
		typ := contents[offset]
		offset++
		length, ok := tftComponentLength(typ)
		if !ok {
			return nil, malformedTFT("reserved packet-filter component %#x", typ)
		}
		if length > len(contents)-offset {
			return nil, malformedTFT("component %#x length %d exceeds %d", typ, length, len(contents)-offset)
		}
		if _, duplicate := seen[typ]; duplicate {
			return nil, malformedTFT("duplicate component %#x", typ)
		}
		value := append([]byte(nil), contents[offset:offset+length]...)
		if err := validateTFTComponentValue(typ, value); err != nil {
			return nil, err
		}
		seen[typ] = struct{}{}
		components = append(components, PacketFilterComponent{Type: typ, Value: value})
		offset += length
	}
	if err := validateTFTComponentCombinations(seen, components); err != nil {
		return nil, err
	}
	return components, nil
}

func tftComponentLength(typ uint8) (int, bool) {
	switch typ {
	case TFTComponentIPv4RemoteAddress, TFTComponentIPv4LocalAddress:
		return 8, true
	case TFTComponentIPv6RemoteAddress:
		return 32, true
	case TFTComponentIPv6RemotePrefix, TFTComponentIPv6LocalPrefix:
		return 17, true
	case TFTComponentProtocol, TFTComponentCustomerVLANPriority, TFTComponentServiceVLANPriority:
		return 1, true
	case TFTComponentSingleLocalPort, TFTComponentSingleRemotePort, TFTComponentTypeOfService,
		TFTComponentCustomerVLANID, TFTComponentServiceVLANID, TFTComponentEtherType:
		return 2, true
	case TFTComponentFlowLabel:
		return 3, true
	case TFTComponentLocalPortRange, TFTComponentRemotePortRange, TFTComponentSecurityParameterIndex:
		return 4, true
	case TFTComponentDestinationMAC, TFTComponentSourceMAC:
		return 6, true
	default:
		return 0, false
	}
}

func validateTFTComponentValue(typ uint8, value []byte) error {
	switch typ {
	case TFTComponentIPv6RemotePrefix, TFTComponentIPv6LocalPrefix:
		if value[16] > 128 {
			return malformedTFT("component %#x has invalid IPv6 prefix %d", typ, value[16])
		}
	case TFTComponentLocalPortRange, TFTComponentRemotePortRange:
		if binary.BigEndian.Uint16(value[:2]) > binary.BigEndian.Uint16(value[2:]) {
			return malformedTFT("component %#x has descending port range", typ)
		}
	case TFTComponentFlowLabel:
		if value[0]&0xf0 != 0 {
			return malformedTFT("flow label has non-zero spare bits")
		}
	case TFTComponentCustomerVLANID, TFTComponentServiceVLANID:
		if value[0]&0xf0 != 0 {
			return malformedTFT("VLAN identifier has non-zero spare bits")
		}
	case TFTComponentCustomerVLANPriority, TFTComponentServiceVLANPriority:
		if value[0]&0xf0 != 0 {
			return malformedTFT("VLAN priority has non-zero spare bits")
		}
	}
	return nil
}

func validateTFTComponentCombinations(seen map[uint8]struct{}, components []PacketFilterComponent) error {
	if hasAnyTFTComponent(seen, TFTComponentIPv4RemoteAddress) && hasAnyTFTComponent(seen, TFTComponentIPv6RemoteAddress, TFTComponentIPv6RemotePrefix) {
		return malformedTFT("packet filter mixes IPv4 and IPv6 remote addresses")
	}
	if hasAnyTFTComponent(seen, TFTComponentIPv4LocalAddress) && hasAnyTFTComponent(seen, TFTComponentIPv6LocalPrefix) {
		return malformedTFT("packet filter mixes IPv4 and IPv6 local addresses")
	}
	if hasAnyTFTComponent(seen, TFTComponentIPv6RemoteAddress, TFTComponentIPv6RemotePrefix) &&
		hasAnyTFTComponent(seen, TFTComponentIPv6RemoteAddress) && hasAnyTFTComponent(seen, TFTComponentIPv6RemotePrefix) {
		return malformedTFT("packet filter contains two IPv6 remote address forms")
	}
	if hasAnyTFTComponent(seen, TFTComponentSingleLocalPort) && hasAnyTFTComponent(seen, TFTComponentLocalPortRange) {
		return malformedTFT("packet filter contains two local port forms")
	}
	if hasAnyTFTComponent(seen, TFTComponentSingleRemotePort) && hasAnyTFTComponent(seen, TFTComponentRemotePortRange) {
		return malformedTFT("packet filter contains two remote port forms")
	}

	var etherType uint16
	for _, component := range components {
		if component.Type == TFTComponentEtherType {
			etherType = binary.BigEndian.Uint16(component.Value)
		}
	}
	if etherType != 0 {
		ipv4 := hasAnyTFTComponent(seen, TFTComponentIPv4RemoteAddress, TFTComponentIPv4LocalAddress)
		ipv6 := hasAnyTFTComponent(seen, TFTComponentIPv6RemoteAddress, TFTComponentIPv6RemotePrefix, TFTComponentIPv6LocalPrefix, TFTComponentFlowLabel)
		ipCommon := hasAnyTFTComponent(seen, TFTComponentProtocol, TFTComponentSingleLocalPort, TFTComponentLocalPortRange,
			TFTComponentSingleRemotePort, TFTComponentRemotePortRange, TFTComponentSecurityParameterIndex, TFTComponentTypeOfService)
		switch etherType {
		case 0x0800:
			if ipv6 {
				return malformedTFT("IPv4 EtherType is combined with IPv6 components")
			}
		case 0x86dd:
			if ipv4 {
				return malformedTFT("IPv6 EtherType is combined with IPv4 components")
			}
		default:
			if ipv4 || ipv6 || ipCommon {
				return malformedTFT("non-IP EtherType is combined with IP components")
			}
		}
	}
	return nil
}

func hasAnyTFTComponent(seen map[uint8]struct{}, types ...uint8) bool {
	for _, typ := range types {
		if _, ok := seen[typ]; ok {
			return true
		}
	}
	return false
}

func (filter PacketFilter) IPv4() (IPv4PacketFilter, error) {
	out := IPv4PacketFilter{ID: filter.ID, Direction: filter.Direction, Precedence: filter.Precedence}
	for _, component := range filter.Components {
		switch component.Type {
		case TFTComponentIPv4LocalAddress:
			out.HasLocalAddress = true
			out.LocalAddress = netip.AddrFrom4([4]byte(component.Value[:4]))
			out.LocalAddressMask = netip.AddrFrom4([4]byte(component.Value[4:8]))
		case TFTComponentIPv4RemoteAddress:
			out.HasRemoteAddress = true
			out.RemoteAddress = netip.AddrFrom4([4]byte(component.Value[:4]))
			out.RemoteAddressMask = netip.AddrFrom4([4]byte(component.Value[4:8]))
		case TFTComponentProtocol:
			out.HasProtocol, out.Protocol = true, component.Value[0]
		case TFTComponentSingleLocalPort:
			out.HasLocalPort = true
			out.LocalPortLow = binary.BigEndian.Uint16(component.Value)
			out.LocalPortHigh = out.LocalPortLow
		case TFTComponentLocalPortRange:
			out.HasLocalPort = true
			out.LocalPortLow = binary.BigEndian.Uint16(component.Value[:2])
			out.LocalPortHigh = binary.BigEndian.Uint16(component.Value[2:])
		case TFTComponentSingleRemotePort:
			out.HasRemotePort = true
			out.RemotePortLow = binary.BigEndian.Uint16(component.Value)
			out.RemotePortHigh = out.RemotePortLow
		case TFTComponentRemotePortRange:
			out.HasRemotePort = true
			out.RemotePortLow = binary.BigEndian.Uint16(component.Value[:2])
			out.RemotePortHigh = binary.BigEndian.Uint16(component.Value[2:])
		case TFTComponentTypeOfService:
			out.HasTypeOfService = true
			out.TypeOfService, out.TypeOfServiceMask = component.Value[0], component.Value[1]
		case TFTComponentEtherType:
			if binary.BigEndian.Uint16(component.Value) != 0x0800 {
				return IPv4PacketFilter{}, fmt.Errorf("%w: EtherType %#x", ErrUnsupportedTFTComponent, binary.BigEndian.Uint16(component.Value))
			}
		default:
			return IPv4PacketFilter{}, fmt.Errorf("%w: type %#x", ErrUnsupportedTFTComponent, component.Type)
		}
	}
	return out, nil
}

func (filter IPv4PacketFilter) AppliesTo(direction TFTDirection) bool {
	if direction != TFTDirectionDownlink && direction != TFTDirectionUplink {
		return false
	}
	switch filter.Direction {
	case TFTDirectionDownlink, TFTDirectionUplink:
		return filter.Direction == direction
	case TFTDirectionBidirectional:
		return true
	default:
		return false
	}
}

// Matches evaluates an IPv4 packet using TS 24.008's UE-relative local and
// remote semantics. Non-initial fragments cannot satisfy a port filter.
func (filter IPv4PacketFilter) Matches(packet []byte, direction TFTDirection) bool {
	if !filter.AppliesTo(direction) || len(packet) < 20 || packet[0]>>4 != 4 {
		return false
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(packet) {
		return false
	}
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength < headerLength || totalLength > len(packet) {
		return false
	}
	packet = packet[:totalLength]
	protocol := packet[9]
	if filter.HasProtocol && protocol != filter.Protocol {
		return false
	}
	source := netip.AddrFrom4([4]byte(packet[12:16]))
	destination := netip.AddrFrom4([4]byte(packet[16:20]))
	localAddress, remoteAddress := source, destination
	if direction == TFTDirectionDownlink {
		localAddress, remoteAddress = destination, source
	}
	if filter.HasLocalAddress && !maskedIPv4Equal(localAddress, filter.LocalAddress, filter.LocalAddressMask) {
		return false
	}
	if filter.HasRemoteAddress && !maskedIPv4Equal(remoteAddress, filter.RemoteAddress, filter.RemoteAddressMask) {
		return false
	}
	if filter.HasTypeOfService && packet[1]&filter.TypeOfServiceMask != filter.TypeOfService&filter.TypeOfServiceMask {
		return false
	}
	if !filter.HasLocalPort && !filter.HasRemotePort {
		return true
	}
	if binary.BigEndian.Uint16(packet[6:8])&0x1fff != 0 || (protocol != 6 && protocol != 17 && protocol != 132) || len(packet) < headerLength+4 {
		return false
	}
	sourcePort := binary.BigEndian.Uint16(packet[headerLength : headerLength+2])
	destinationPort := binary.BigEndian.Uint16(packet[headerLength+2 : headerLength+4])
	localPort, remotePort := sourcePort, destinationPort
	if direction == TFTDirectionDownlink {
		localPort, remotePort = destinationPort, sourcePort
	}
	if filter.HasLocalPort && (localPort < filter.LocalPortLow || localPort > filter.LocalPortHigh) {
		return false
	}
	if filter.HasRemotePort && (remotePort < filter.RemotePortLow || remotePort > filter.RemotePortHigh) {
		return false
	}
	return true
}

// MatchIPv4 returns the highest-precedence matching filter (the numerically
// lowest precedence value). It is used as the correctness oracle for TFT rule
// translation and packet-capture conformance tests.
func (tft TrafficFlowTemplate) MatchIPv4(packet []byte, direction TFTDirection) (PacketFilter, bool, error) {
	filters := append([]PacketFilter(nil), tft.Filters...)
	sort.SliceStable(filters, func(i, j int) bool { return filters[i].Precedence < filters[j].Precedence })
	for _, candidate := range filters {
		if candidate.Direction != TFTDirectionBidirectional && candidate.Direction != direction {
			continue
		}
		filter, err := candidate.IPv4()
		if err != nil {
			return PacketFilter{}, false, err
		}
		if filter.Matches(packet, direction) {
			return candidate, true, nil
		}
	}
	return PacketFilter{}, false, nil
}

// NormalizeDirections swaps uplink and downlink only for an explicitly named
// legacy compatibility mode. The safe/default path returns an independent
// copy with native TS 24.008 direction semantics.
func (tft TrafficFlowTemplate) NormalizeDirections(expectFlipped bool) TrafficFlowTemplate {
	out := cloneTFT(tft)
	if !expectFlipped {
		return out
	}
	for index := range out.Filters {
		switch out.Filters[index].Direction {
		case TFTDirectionDownlink:
			out.Filters[index].Direction = TFTDirectionUplink
		case TFTDirectionUplink:
			out.Filters[index].Direction = TFTDirectionDownlink
		}
	}
	return out
}

func cloneTFT(in TrafficFlowTemplate) TrafficFlowTemplate {
	out := in
	out.DeleteFilterIDs = append([]uint8(nil), in.DeleteFilterIDs...)
	out.Filters = make([]PacketFilter, len(in.Filters))
	for index, filter := range in.Filters {
		out.Filters[index] = filter
		out.Filters[index].Components = make([]PacketFilterComponent, len(filter.Components))
		for componentIndex, component := range filter.Components {
			out.Filters[index].Components[componentIndex] = PacketFilterComponent{Type: component.Type, Value: append([]byte(nil), component.Value...)}
		}
	}
	out.Parameters = make([]TFTParameter, len(in.Parameters))
	for index, parameter := range in.Parameters {
		out.Parameters[index] = TFTParameter{ID: parameter.ID, Value: append([]byte(nil), parameter.Value...)}
	}
	return out
}

func maskedIPv4Equal(got, want, mask netip.Addr) bool {
	if !got.Is4() || !want.Is4() || !mask.Is4() {
		return false
	}
	gotBytes, wantBytes, maskBytes := got.As4(), want.As4(), mask.As4()
	for index := range gotBytes {
		if gotBytes[index]&maskBytes[index] != wantBytes[index]&maskBytes[index] {
			return false
		}
	}
	return true
}

func malformedTFT(format string, args ...any) error {
	return fmt.Errorf("%w: TFT %s", ErrMalformedIE, fmt.Sprintf(format, args...))
}
