package pfcp

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const maxFlowDescriptionLength = 4096

// SDFFilter is the IPv4-capable subset of the TS 29.244 SDF Filter IE. The
// flow description uses the restricted RFC 6733 IPFilterRule profile required
// by TS 29.212. Optional fields have explicit presence bits so zero remains a
// valid value.
type SDFFilter struct {
	HasFlowDescription bool
	FlowDescription    string
	HasToSTrafficClass bool
	ToSTrafficClass    uint8
	ToSTrafficMask     uint8
	HasSPI             bool
	SPI                uint32
	HasFlowLabel       bool
	FlowLabel          uint32
	Bidirectional      bool
	FilterID           uint32
}

// IPv4FlowDescription is the deliberately restricted IPFilterRule subset
// accepted by this LTE Sxb implementation. Source is the remote endpoint and
// destination is the UE-local endpoint, independent of packet direction.
type IPv4FlowDescription struct {
	AnyProtocol bool
	Protocol    uint8

	SourceAny    bool
	SourcePrefix netip.Prefix
	SourcePort   PortRange

	DestinationAny      bool
	DestinationAssigned bool
	DestinationPrefix   netip.Prefix
	DestinationPort     PortRange
}

type PortRange struct {
	Present bool
	Low     uint16
	High    uint16
}

func NewSDFFilterIE(filter SDFFilter) (IE, error) {
	if err := validateSDFFilter(filter); err != nil {
		return IE{}, err
	}
	flags := uint8(0)
	length := 2
	if filter.HasFlowDescription {
		flags |= 1 << 0
		length += 2 + len(filter.FlowDescription)
	}
	if filter.HasToSTrafficClass {
		flags |= 1 << 1
		length += 2
	}
	if filter.HasSPI {
		flags |= 1 << 2
		length += 4
	}
	if filter.HasFlowLabel {
		flags |= 1 << 3
		length += 3
	}
	if filter.Bidirectional {
		flags |= 1 << 4
		length += 4
	}
	value := make([]byte, length)
	value[0] = flags
	offset := 2
	if filter.HasFlowDescription {
		binary.BigEndian.PutUint16(value[offset:offset+2], uint16(len(filter.FlowDescription)))
		offset += 2
		copy(value[offset:], filter.FlowDescription)
		offset += len(filter.FlowDescription)
	}
	if filter.HasToSTrafficClass {
		value[offset], value[offset+1] = filter.ToSTrafficClass, filter.ToSTrafficMask
		offset += 2
	}
	if filter.HasSPI {
		binary.BigEndian.PutUint32(value[offset:offset+4], filter.SPI)
		offset += 4
	}
	if filter.HasFlowLabel {
		value[offset] = byte(filter.FlowLabel >> 16)
		binary.BigEndian.PutUint16(value[offset+1:offset+3], uint16(filter.FlowLabel))
		offset += 3
	}
	if filter.Bidirectional {
		binary.BigEndian.PutUint32(value[offset:offset+4], filter.FilterID)
	}
	return IE{Type: IESDFFilter, Value: value}, nil
}

func (ie IE) SDFFilter() (SDFFilter, error) {
	if ie.Type != IESDFFilter || len(ie.Value) < 2 || ie.Value[0]&0xe0 != 0 || ie.Value[1] != 0 {
		return SDFFilter{}, fmt.Errorf("%w: invalid SDF Filter header", ErrMalformedIE)
	}
	flags := ie.Value[0]
	offset := 2
	filter := SDFFilter{
		HasFlowDescription: flags&(1<<0) != 0,
		HasToSTrafficClass: flags&(1<<1) != 0,
		HasSPI:             flags&(1<<2) != 0,
		HasFlowLabel:       flags&(1<<3) != 0,
		Bidirectional:      flags&(1<<4) != 0,
	}
	if filter.HasFlowDescription {
		if len(ie.Value)-offset < 2 {
			return SDFFilter{}, fmt.Errorf("%w: truncated SDF flow-description length", ErrMalformedIE)
		}
		length := int(binary.BigEndian.Uint16(ie.Value[offset : offset+2]))
		offset += 2
		if length == 0 || length > len(ie.Value)-offset {
			return SDFFilter{}, fmt.Errorf("%w: invalid SDF flow-description length %d", ErrMalformedIE, length)
		}
		filter.FlowDescription = string(ie.Value[offset : offset+length])
		offset += length
	}
	if filter.HasToSTrafficClass {
		if len(ie.Value)-offset < 2 {
			return SDFFilter{}, fmt.Errorf("%w: truncated SDF ToS traffic class", ErrMalformedIE)
		}
		filter.ToSTrafficClass, filter.ToSTrafficMask = ie.Value[offset], ie.Value[offset+1]
		offset += 2
	}
	if filter.HasSPI {
		if len(ie.Value)-offset < 4 {
			return SDFFilter{}, fmt.Errorf("%w: truncated SDF security parameter index", ErrMalformedIE)
		}
		filter.SPI = binary.BigEndian.Uint32(ie.Value[offset : offset+4])
		offset += 4
	}
	if filter.HasFlowLabel {
		if len(ie.Value)-offset < 3 || ie.Value[offset]&0xf0 != 0 {
			return SDFFilter{}, fmt.Errorf("%w: invalid SDF flow label", ErrMalformedIE)
		}
		filter.FlowLabel = uint32(ie.Value[offset])<<16 | uint32(binary.BigEndian.Uint16(ie.Value[offset+1:offset+3]))
		offset += 3
	}
	if filter.Bidirectional {
		if len(ie.Value)-offset < 4 {
			return SDFFilter{}, fmt.Errorf("%w: truncated SDF filter ID", ErrMalformedIE)
		}
		filter.FilterID = binary.BigEndian.Uint32(ie.Value[offset : offset+4])
		offset += 4
	}
	if offset != len(ie.Value) {
		return SDFFilter{}, fmt.Errorf("%w: %d trailing SDF Filter octets", ErrMalformedIE, len(ie.Value)-offset)
	}
	if err := validateSDFFilter(filter); err != nil {
		return SDFFilter{}, err
	}
	return filter, nil
}

func validateSDFFilter(filter SDFFilter) error {
	if !filter.HasFlowDescription && !filter.HasToSTrafficClass && !filter.HasSPI && !filter.HasFlowLabel {
		return fmt.Errorf("%w: SDF Filter has no matching criterion", ErrMalformedIE)
	}
	if filter.HasFlowDescription {
		if len(filter.FlowDescription) == 0 || len(filter.FlowDescription) > maxFlowDescriptionLength || len(filter.FlowDescription) > 0xffff {
			return fmt.Errorf("%w: invalid SDF flow-description length %d", ErrMalformedIE, len(filter.FlowDescription))
		}
		for _, character := range []byte(filter.FlowDescription) {
			if character < 0x20 || character > 0x7e {
				return fmt.Errorf("%w: SDF flow description is not printable ASCII", ErrMalformedIE)
			}
		}
		if _, err := ParseIPv4FlowDescription(filter.FlowDescription); err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedIE, err)
		}
	} else if filter.FlowDescription != "" {
		return fmt.Errorf("%w: SDF flow description present without FD flag", ErrMalformedIE)
	}
	if filter.HasFlowLabel && filter.FlowLabel > 0x000fffff {
		return fmt.Errorf("%w: SDF flow label exceeds 20 bits", ErrMalformedIE)
	}
	if !filter.HasToSTrafficClass && (filter.ToSTrafficClass != 0 || filter.ToSTrafficMask != 0) {
		return fmt.Errorf("%w: SDF ToS value present without TTC flag", ErrMalformedIE)
	}
	if !filter.HasSPI && filter.SPI != 0 {
		return fmt.Errorf("%w: SDF SPI present without SPI flag", ErrMalformedIE)
	}
	if !filter.HasFlowLabel && filter.FlowLabel != 0 {
		return fmt.Errorf("%w: SDF flow label present without FL flag", ErrMalformedIE)
	}
	if !filter.Bidirectional && filter.FilterID != 0 {
		return fmt.Errorf("%w: SDF filter ID present without BID flag", ErrMalformedIE)
	}
	return nil
}

func ParseIPv4FlowDescription(description string) (IPv4FlowDescription, error) {
	if len(description) == 0 || len(description) > maxFlowDescriptionLength {
		return IPv4FlowDescription{}, fmt.Errorf("invalid flow-description length %d", len(description))
	}
	if strings.TrimSpace(description) != description || strings.ContainsAny(description, "\t\r\n") || strings.Contains(description, "  ") {
		return IPv4FlowDescription{}, fmt.Errorf("flow description is not canonical single-space text")
	}
	fields := strings.Split(description, " ")
	if len(fields) < 7 || len(fields) > 9 || fields[0] != "permit" || fields[1] != "out" || fields[3] != "from" {
		return IPv4FlowDescription{}, fmt.Errorf("unsupported IPFilterRule grammar")
	}
	out := IPv4FlowDescription{}
	if fields[2] == "ip" {
		out.AnyProtocol = true
	} else {
		protocol, err := strconv.ParseUint(fields[2], 10, 8)
		if err != nil || strconv.FormatUint(protocol, 10) != fields[2] {
			return IPv4FlowDescription{}, fmt.Errorf("invalid IP protocol %q", fields[2])
		}
		out.Protocol = uint8(protocol)
	}
	out.SourceAny, out.SourcePrefix = false, netip.Prefix{}
	var err error
	out.SourceAny, _, out.SourcePrefix, err = parseFlowAddress(fields[4], false)
	if err != nil {
		return IPv4FlowDescription{}, fmt.Errorf("source: %w", err)
	}
	index := 5
	if index < len(fields) && fields[index] != "to" {
		out.SourcePort, err = parsePortRange(fields[index])
		if err != nil {
			return IPv4FlowDescription{}, fmt.Errorf("source port: %w", err)
		}
		index++
	}
	if index >= len(fields) || fields[index] != "to" || index+1 >= len(fields) {
		return IPv4FlowDescription{}, fmt.Errorf("missing destination")
	}
	index++
	out.DestinationAny, out.DestinationAssigned, out.DestinationPrefix, err = parseFlowAddress(fields[index], true)
	if err != nil {
		return IPv4FlowDescription{}, fmt.Errorf("destination: %w", err)
	}
	index++
	if index < len(fields) {
		out.DestinationPort, err = parsePortRange(fields[index])
		if err != nil {
			return IPv4FlowDescription{}, fmt.Errorf("destination port: %w", err)
		}
		index++
	}
	if index != len(fields) {
		return IPv4FlowDescription{}, fmt.Errorf("unsupported IPFilterRule options")
	}
	if (out.SourcePort.Present || out.DestinationPort.Present) && (out.AnyProtocol || out.Protocol != 6 && out.Protocol != 17 && out.Protocol != 132) {
		return IPv4FlowDescription{}, fmt.Errorf("ports require TCP, UDP, or SCTP protocol")
	}
	return out, nil
}

func (description IPv4FlowDescription) String() string {
	protocol := "ip"
	if !description.AnyProtocol {
		protocol = strconv.FormatUint(uint64(description.Protocol), 10)
	}
	fields := []string{"permit", "out", protocol, "from", formatFlowAddress(description.SourceAny, false, description.SourcePrefix)}
	if description.SourcePort.Present {
		fields = append(fields, formatPortRange(description.SourcePort))
	}
	fields = append(fields, "to", formatFlowAddress(description.DestinationAny, description.DestinationAssigned, description.DestinationPrefix))
	if description.DestinationPort.Present {
		fields = append(fields, formatPortRange(description.DestinationPort))
	}
	return strings.Join(fields, " ")
}

func parseFlowAddress(value string, allowAssigned bool) (any, assigned bool, prefix netip.Prefix, err error) {
	switch value {
	case "any":
		return true, false, netip.Prefix{}, nil
	case "assigned":
		if !allowAssigned {
			return false, false, netip.Prefix{}, fmt.Errorf("assigned is only valid for the UE-local destination")
		}
		return false, true, netip.Prefix{}, nil
	}
	if strings.Contains(value, "!") || strings.Contains(value, ",") {
		return false, false, netip.Prefix{}, fmt.Errorf("inverted and list addresses are unsupported")
	}
	if address, parseErr := netip.ParseAddr(value); parseErr == nil {
		if !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
			return false, false, netip.Prefix{}, fmt.Errorf("valid unicast IPv4 address required")
		}
		return false, false, netip.PrefixFrom(address.Unmap(), 32), nil
	}
	prefix, err = netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 0 || prefix.Bits() > 32 || prefix != prefix.Masked() {
		return false, false, netip.Prefix{}, fmt.Errorf("canonical IPv4 prefix required")
	}
	if prefix.Bits() == 0 {
		return false, false, netip.Prefix{}, fmt.Errorf("use any for an all-address prefix")
	}
	if prefix.Bits() == 32 {
		return false, false, netip.Prefix{}, fmt.Errorf("use a bare address for a single host")
	}
	return false, false, prefix, nil
}

func parsePortRange(value string) (PortRange, error) {
	if strings.Contains(value, ",") {
		return PortRange{}, fmt.Errorf("port lists are unsupported")
	}
	parts := strings.Split(value, "-")
	if len(parts) > 2 || len(parts) == 0 {
		return PortRange{}, fmt.Errorf("invalid range %q", value)
	}
	low, err := parsePort(parts[0])
	if err != nil {
		return PortRange{}, err
	}
	high := low
	if len(parts) == 2 {
		high, err = parsePort(parts[1])
		if err != nil {
			return PortRange{}, err
		}
	}
	if low > high {
		return PortRange{}, fmt.Errorf("descending range %d-%d", low, high)
	}
	return PortRange{Present: true, Low: low, High: high}, nil
}

func parsePort(value string) (uint16, error) {
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil || strconv.FormatUint(port, 10) != value {
		return 0, fmt.Errorf("invalid decimal port %q", value)
	}
	return uint16(port), nil
}

func formatFlowAddress(any, assigned bool, prefix netip.Prefix) string {
	if any {
		return "any"
	}
	if assigned {
		return "assigned"
	}
	if prefix.Bits() == 32 {
		return prefix.Addr().String()
	}
	return prefix.String()
}

func formatPortRange(value PortRange) string {
	if value.Low == value.High {
		return strconv.FormatUint(uint64(value.Low), 10)
	}
	return strconv.FormatUint(uint64(value.Low), 10) + "-" + strconv.FormatUint(uint64(value.High), 10)
}
