package gtpv2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Information element types used by the LTE Serving Gateway profile. Unknown
// information elements are preserved and can be relayed without interpretation.
const (
	IEIMSI           uint8 = 1
	IECause          uint8 = 2
	IERecovery       uint8 = 3
	IEAPN            uint8 = 71
	IEAMBR           uint8 = 72
	IEEBI            uint8 = 73
	IEPCO            uint8 = 78
	IEPAA            uint8 = 79
	IEBearerQoS      uint8 = 80
	IERATType        uint8 = 82
	IEServingNetwork uint8 = 83
	IEBearerTFT      uint8 = 84
	IEFTEID          uint8 = 87
	IEBearerContext  uint8 = 93
	IEPDNType        uint8 = 99
	IEARP            uint8 = 155
)

const maxAMBRKbps = uint64(^uint32(0))

const (
	InterfaceS1UENodeBGTPU uint8 = 0
	InterfaceS1USGWGTPU    uint8 = 1
	InterfaceS5S8SGWGTPU   uint8 = 4
	InterfaceS5S8PGWGTPU   uint8 = 5
	InterfaceS5S8SGWGTPC   uint8 = 6
	InterfaceS5S8PGWGTPC   uint8 = 7
	InterfaceS11MMEGTPC    uint8 = 10
	InterfaceS11SGWGTPC    uint8 = 11
)

// PDN types used by the LTE IPv4 profile. The values are shared by the PDN
// Type and PAA information elements (3GPP TS 29.274 sections 8.34 and 8.14).
const (
	PDNTypeIPv4   uint8 = 1
	PDNTypeIPv6   uint8 = 2
	PDNTypeIPv4v6 uint8 = 3
)

const (
	CauseRequestAccepted         uint8 = 16
	CauseContextNotFound         uint8 = 64
	CauseInvalidMessageFormat    uint8 = 65
	CauseVersionNotSupported     uint8 = 66
	CauseInvalidLength           uint8 = 67
	CauseServiceNotSupported     uint8 = 68
	CauseMandatoryIEIncorrect    uint8 = 69
	CauseMandatoryIEMissing      uint8 = 70
	CauseSystemFailure           uint8 = 72
	CauseNoResourcesAvailable    uint8 = 73
	CauseMissingOrUnknownAPN     uint8 = 78
	CauseRemotePeerNotResponding uint8 = 100
	CauseInvalidReplyFromPeer    uint8 = 107
)

const (
	maxIEsPerScope  = 256
	maxGroupedDepth = 8
)

var (
	ErrMalformedIE  = errors.New("gtpv2: malformed information element")
	ErrTooManyIEs   = errors.New("gtpv2: too many information elements")
	ErrGroupedDepth = errors.New("gtpv2: grouped information element depth exceeded")
	ErrMissingIE    = errors.New("gtpv2: mandatory information element missing")
)

// IE is a GTPv2-C TLIV information element. Value never aliases the packet
// passed to ParseIEs, which lets callers safely retain and mutate messages.
type IE struct {
	Type     uint8
	Instance uint8
	Value    []byte
}

// FTEID is the decoded value of a Fully Qualified Tunnel Endpoint Identifier.
type FTEID struct {
	InterfaceType uint8
	TEID          uint32
	IPv4          netip.Addr
	IPv6          netip.Addr
}

// Cause is the subset of the Cause IE needed to accept or reject requests.
type Cause struct {
	Value uint8
	PCE   bool
	BCE   bool
	CS    bool
}

type BearerQoS struct {
	QCI                  uint8
	Priority             uint8
	PreemptionCapable    bool
	PreemptionVulnerable bool
	UplinkMBR            uint64
	DownlinkMBR          uint64
	UplinkGBR            uint64
	DownlinkGBR          uint64
}

type AllocationRetentionPriority struct {
	Priority             uint8
	PreemptionCapable    bool
	PreemptionVulnerable bool
}

func ParseIEs(payload []byte) ([]IE, error) {
	return parseIEs(payload, 0)
}

func parseIEs(payload []byte, depth int) ([]IE, error) {
	if depth > maxGroupedDepth {
		return nil, ErrGroupedDepth
	}
	ies := make([]IE, 0, min(len(payload)/4, 16))
	for offset := 0; offset < len(payload); {
		if len(ies) >= maxIEsPerScope {
			return nil, ErrTooManyIEs
		}
		if len(payload)-offset < 4 {
			return nil, fmt.Errorf("%w: truncated header at offset %d", ErrMalformedIE, offset)
		}
		length := int(binary.BigEndian.Uint16(payload[offset+1 : offset+3]))
		total := 4 + length
		if payload[offset] == 0 || payload[offset+3]&0xf0 != 0 || total < 4 || total > len(payload)-offset {
			return nil, fmt.Errorf("%w: type=%d length=%d remaining=%d", ErrMalformedIE, payload[offset], length, len(payload)-offset)
		}
		value := append([]byte(nil), payload[offset+4:offset+total]...)
		ies = append(ies, IE{Type: payload[offset], Instance: payload[offset+3] & 0x0f, Value: value})
		offset += total
	}
	return ies, nil
}

func MarshalIEs(ies []IE) ([]byte, error) {
	if len(ies) > maxIEsPerScope {
		return nil, ErrTooManyIEs
	}
	total := 0
	for _, ie := range ies {
		if ie.Type == 0 || ie.Instance > 15 || len(ie.Value) > 0xffff {
			return nil, fmt.Errorf("%w: type=%d instance=%d length=%d", ErrMalformedIE, ie.Type, ie.Instance, len(ie.Value))
		}
		if total > 0xffff-(4+len(ie.Value)) {
			return nil, fmt.Errorf("%w: aggregate IE payload too large", ErrMalformedIE)
		}
		total += 4 + len(ie.Value)
	}
	out := make([]byte, total)
	offset := 0
	for _, ie := range ies {
		out[offset] = ie.Type
		binary.BigEndian.PutUint16(out[offset+1:offset+3], uint16(len(ie.Value)))
		out[offset+3] = ie.Instance
		copy(out[offset+4:], ie.Value)
		offset += 4 + len(ie.Value)
	}
	return out, nil
}

func (ie IE) Clone() IE {
	return IE{Type: ie.Type, Instance: ie.Instance, Value: append([]byte(nil), ie.Value...)}
}

func (ie IE) Children() ([]IE, error) {
	if ie.Type != IEBearerContext {
		return nil, fmt.Errorf("%w: IE type %d is not a supported grouped IE", ErrMalformedIE, ie.Type)
	}
	return parseIEs(ie.Value, 1)
}

func NewGroupedIE(typ, instance uint8, children ...IE) (IE, error) {
	if typ != IEBearerContext {
		return IE{}, fmt.Errorf("%w: unsupported grouped IE type %d", ErrMalformedIE, typ)
	}
	value, err := MarshalIEs(children)
	if err != nil {
		return IE{}, err
	}
	return IE{Type: typ, Instance: instance, Value: value}, nil
}

func FindIE(ies []IE, typ, instance uint8) (IE, bool) {
	for _, ie := range ies {
		if ie.Type == typ && ie.Instance == instance {
			return ie.Clone(), true
		}
	}
	return IE{}, false
}

func FindAllIEs(ies []IE, typ, instance uint8) []IE {
	out := make([]IE, 0, 1)
	for _, ie := range ies {
		if ie.Type == typ && ie.Instance == instance {
			out = append(out, ie.Clone())
		}
	}
	return out
}

// UpsertIE replaces the first matching IE, removes duplicate matches, and
// appends the replacement when no match exists. All unrelated IEs retain order.
func UpsertIE(ies []IE, replacement IE) []IE {
	out := make([]IE, 0, len(ies)+1)
	replaced := false
	for _, ie := range ies {
		if ie.Type == replacement.Type && ie.Instance == replacement.Instance {
			if !replaced {
				out = append(out, replacement.Clone())
				replaced = true
			}
			continue
		}
		out = append(out, ie.Clone())
	}
	if !replaced {
		out = append(out, replacement.Clone())
	}
	return out
}

func RemoveIE(ies []IE, typ, instance uint8) []IE {
	out := make([]IE, 0, len(ies))
	for _, ie := range ies {
		if ie.Type == typ && ie.Instance == instance {
			continue
		}
		out = append(out, ie.Clone())
	}
	return out
}

func NewCauseIE(value uint8, instance uint8) IE {
	return IE{Type: IECause, Instance: instance, Value: []byte{value, 0}}
}

func (ie IE) Cause() (Cause, error) {
	if ie.Type != IECause || len(ie.Value) < 2 {
		return Cause{}, fmt.Errorf("%w: invalid Cause IE", ErrMalformedIE)
	}
	return Cause{
		Value: ie.Value[0],
		PCE:   ie.Value[1]&0x04 != 0,
		BCE:   ie.Value[1]&0x02 != 0,
		CS:    ie.Value[1]&0x01 != 0,
	}, nil
}

func NewRecoveryIE(counter uint8) IE {
	return IE{Type: IERecovery, Value: []byte{counter}}
}

func (ie IE) Recovery() (uint8, error) {
	if ie.Type != IERecovery || len(ie.Value) < 1 {
		return 0, fmt.Errorf("%w: invalid Recovery IE", ErrMalformedIE)
	}
	return ie.Value[0], nil
}

func NewPDNTypeIE(instance, pdnType uint8) (IE, error) {
	if instance > 15 || pdnType < PDNTypeIPv4 || pdnType > PDNTypeIPv4v6 {
		return IE{}, fmt.Errorf("%w: invalid PDN type %d", ErrMalformedIE, pdnType)
	}
	return IE{Type: IEPDNType, Instance: instance, Value: []byte{pdnType}}, nil
}

func (ie IE) PDNType() (uint8, error) {
	if ie.Type != IEPDNType || len(ie.Value) != 1 || ie.Value[0]&0xf8 != 0 {
		return 0, fmt.Errorf("%w: invalid PDN Type IE", ErrMalformedIE)
	}
	pdnType := ie.Value[0] & 0x07
	if pdnType < PDNTypeIPv4 || pdnType > PDNTypeIPv4v6 {
		return 0, fmt.Errorf("%w: unsupported PDN type %d", ErrMalformedIE, pdnType)
	}
	return pdnType, nil
}

// NewPAAIPv4IE creates the five-octet IPv4 PDN Address Allocation IE. IPv6
// and dual-stack constructors remain separate so their prefix semantics cannot
// accidentally be confused with a host address.
func NewPAAIPv4IE(instance uint8, addr netip.Addr) (IE, error) {
	if instance > 15 || !addr.Is4() {
		return IE{}, fmt.Errorf("%w: PAA requires an IPv4 address", ErrMalformedIE)
	}
	raw := addr.Unmap().As4()
	value := make([]byte, 5)
	value[0] = PDNTypeIPv4
	copy(value[1:], raw[:])
	return IE{Type: IEPAA, Instance: instance, Value: value}, nil
}

func (ie IE) PAAIPv4() (netip.Addr, error) {
	if ie.Type != IEPAA || len(ie.Value) != 5 || ie.Value[0]&0xf8 != 0 || ie.Value[0]&0x07 != PDNTypeIPv4 {
		return netip.Addr{}, fmt.Errorf("%w: invalid IPv4 PAA IE", ErrMalformedIE)
	}
	var raw [4]byte
	copy(raw[:], ie.Value[1:])
	addr := netip.AddrFrom4(raw)
	if addr.IsUnspecified() || addr.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("%w: unusable IPv4 PAA address", ErrMalformedIE)
	}
	return addr, nil
}

// NewAMBRIE creates the APN Aggregate Maximum Bit Rate IE. The public API is
// deliberately expressed in bits per second; GTPv2-C encodes both values in
// kilobits per second on the wire.
func NewAMBRIE(instance uint8, uplinkBPS, downlinkBPS uint64) (IE, error) {
	if instance > 15 || uplinkBPS == 0 || downlinkBPS == 0 {
		return IE{}, fmt.Errorf("%w: APN-AMBR values must be positive", ErrMalformedIE)
	}
	if uplinkBPS%1000 != 0 || downlinkBPS%1000 != 0 {
		return IE{}, fmt.Errorf("%w: APN-AMBR values must be whole kilobits per second", ErrMalformedIE)
	}
	uplinkKbps, downlinkKbps := uplinkBPS/1000, downlinkBPS/1000
	if uplinkKbps > maxAMBRKbps || downlinkKbps > maxAMBRKbps {
		return IE{}, fmt.Errorf("%w: APN-AMBR exceeds the 32-bit kbps fields", ErrMalformedIE)
	}
	value := make([]byte, 8)
	binary.BigEndian.PutUint32(value[0:4], uint32(uplinkKbps))
	binary.BigEndian.PutUint32(value[4:8], uint32(downlinkKbps))
	return IE{Type: IEAMBR, Instance: instance, Value: value}, nil
}

// AMBR returns APN-AMBR values in bits per second.
func (ie IE) AMBR() (uplinkBPS, downlinkBPS uint64, err error) {
	if ie.Type != IEAMBR || len(ie.Value) != 8 {
		return 0, 0, fmt.Errorf("%w: invalid APN-AMBR IE", ErrMalformedIE)
	}
	uplinkBPS = uint64(binary.BigEndian.Uint32(ie.Value[0:4])) * 1000
	downlinkBPS = uint64(binary.BigEndian.Uint32(ie.Value[4:8])) * 1000
	if uplinkBPS == 0 || downlinkBPS == 0 {
		return 0, 0, fmt.Errorf("%w: zero APN-AMBR value", ErrMalformedIE)
	}
	return uplinkBPS, downlinkBPS, nil
}

func NewFTEIDIE(instance uint8, f FTEID) (IE, error) {
	if f.InterfaceType > 63 || f.TEID == 0 {
		return IE{}, fmt.Errorf("%w: invalid F-TEID interface or TEID", ErrMalformedIE)
	}
	flags := f.InterfaceType
	length := 5
	if f.IPv4.IsValid() {
		if !f.IPv4.Is4() {
			return IE{}, fmt.Errorf("%w: IPv4 field is not IPv4", ErrMalformedIE)
		}
		flags |= 0x80
		length += 4
	}
	if f.IPv6.IsValid() {
		if !f.IPv6.Is6() {
			return IE{}, fmt.Errorf("%w: IPv6 field is not IPv6", ErrMalformedIE)
		}
		flags |= 0x40
		length += 16
	}
	if flags&0xc0 == 0 {
		return IE{}, fmt.Errorf("%w: F-TEID requires an IP address", ErrMalformedIE)
	}
	value := make([]byte, length)
	value[0] = flags
	binary.BigEndian.PutUint32(value[1:5], f.TEID)
	offset := 5
	if f.IPv4.IsValid() {
		addr := f.IPv4.As4()
		copy(value[offset:offset+4], addr[:])
		offset += 4
	}
	if f.IPv6.IsValid() {
		addr := f.IPv6.As16()
		copy(value[offset:offset+16], addr[:])
	}
	return IE{Type: IEFTEID, Instance: instance, Value: value}, nil
}

func (ie IE) FTEID() (FTEID, error) {
	if ie.Type != IEFTEID || len(ie.Value) < 5 {
		return FTEID{}, fmt.Errorf("%w: invalid F-TEID IE", ErrMalformedIE)
	}
	flags := ie.Value[0]
	if flags&0xc0 == 0 {
		return FTEID{}, fmt.Errorf("%w: F-TEID has no IP address", ErrMalformedIE)
	}
	need := 5
	if flags&0x80 != 0 {
		need += 4
	}
	if flags&0x40 != 0 {
		need += 16
	}
	if len(ie.Value) < need {
		return FTEID{}, fmt.Errorf("%w: truncated F-TEID value", ErrMalformedIE)
	}
	out := FTEID{InterfaceType: flags & 0x3f, TEID: binary.BigEndian.Uint32(ie.Value[1:5])}
	if out.TEID == 0 {
		return FTEID{}, fmt.Errorf("%w: zero F-TEID", ErrMalformedIE)
	}
	offset := 5
	if flags&0x80 != 0 {
		var raw [4]byte
		copy(raw[:], ie.Value[offset:offset+4])
		out.IPv4 = netip.AddrFrom4(raw)
		offset += 4
	}
	if flags&0x40 != 0 {
		var raw [16]byte
		copy(raw[:], ie.Value[offset:offset+16])
		out.IPv6 = netip.AddrFrom16(raw)
	}
	return out, nil
}

func NewEBIIE(ebi, instance uint8) (IE, error) {
	if ebi < 5 || ebi > 15 {
		return IE{}, fmt.Errorf("%w: EBI %d outside supported LTE range", ErrMalformedIE, ebi)
	}
	return IE{Type: IEEBI, Instance: instance, Value: []byte{ebi & 0x0f}}, nil
}

func (ie IE) EBI() (uint8, error) {
	ebi, err := ie.EBIOrZero()
	if err != nil {
		return 0, err
	}
	if ebi < 5 {
		return 0, fmt.Errorf("%w: unsupported EBI %d", ErrMalformedIE, ebi)
	}
	return ebi, nil
}

// EBIOrZero accepts the unassigned value used in a PGW-initiated Create
// Bearer Request. All established bearer state should continue to use EBI.
func (ie IE) EBIOrZero() (uint8, error) {
	if ie.Type != IEEBI || len(ie.Value) < 1 {
		return 0, fmt.Errorf("%w: invalid EBI IE", ErrMalformedIE)
	}
	ebi := ie.Value[0] & 0x0f
	if ebi != 0 && ebi < 5 || ebi > 15 {
		return 0, fmt.Errorf("%w: unsupported EBI %d", ErrMalformedIE, ebi)
	}
	return ebi, nil
}

func (ie IE) BearerQoS() (qci, priority uint8, err error) {
	details, err := ie.BearerQoSDetails()
	if err != nil {
		return 0, 0, err
	}
	return details.QCI, details.Priority, nil
}

func NewARPIE(instance, priority uint8, preemptionCapable, preemptionVulnerable bool) (IE, error) {
	if instance > 15 || priority == 0 || priority > 15 {
		return IE{}, fmt.Errorf("%w: invalid Allocation/Retention Priority", ErrMalformedIE)
	}
	value := priority << 2
	if preemptionCapable {
		value |= 1 << 6
	}
	if preemptionVulnerable {
		value |= 1
	}
	return IE{Type: IEARP, Instance: instance, Value: []byte{value}}, nil
}

func (ie IE) AllocationRetentionPriority() (AllocationRetentionPriority, error) {
	if ie.Type != IEARP || len(ie.Value) < 1 {
		return AllocationRetentionPriority{}, fmt.Errorf("%w: invalid Allocation/Retention Priority IE", ErrMalformedIE)
	}
	arp := AllocationRetentionPriority{
		Priority:             (ie.Value[0] >> 2) & 0x0f,
		PreemptionCapable:    ie.Value[0]&(1<<6) != 0,
		PreemptionVulnerable: ie.Value[0]&1 != 0,
	}
	if arp.Priority == 0 {
		return AllocationRetentionPriority{}, fmt.Errorf("%w: invalid Allocation/Retention Priority", ErrMalformedIE)
	}
	return arp, nil
}

func (ie IE) BearerQoSDetails() (BearerQoS, error) {
	if ie.Type != IEBearerQoS || len(ie.Value) < 22 {
		return BearerQoS{}, fmt.Errorf("%w: invalid Bearer QoS IE", ErrMalformedIE)
	}
	out := BearerQoS{
		QCI:                  ie.Value[1],
		Priority:             (ie.Value[0] >> 2) & 0x0f,
		PreemptionCapable:    ie.Value[0]&0x40 != 0,
		PreemptionVulnerable: ie.Value[0]&0x01 != 0,
		UplinkMBR:            uint40(ie.Value[2:7]) * 1000,
		DownlinkMBR:          uint40(ie.Value[7:12]) * 1000,
		UplinkGBR:            uint40(ie.Value[12:17]) * 1000,
		DownlinkGBR:          uint40(ie.Value[17:22]) * 1000,
	}
	if out.QCI == 0 || out.Priority == 0 {
		return BearerQoS{}, fmt.Errorf("%w: invalid QCI/ARP", ErrMalformedIE)
	}
	return out, nil
}

// NewBearerQoSIE creates the LTE Bearer Level QoS IE used by the default-
// bearer profile. Bitrates are encoded in the extended fields by richer PCC
// implementations; the portable SGW currently preserves those fields when
// relaying and only originates QCI and allocation/retention priority.
func NewBearerQoSIE(instance, qci, priority uint8) (IE, error) {
	return NewBearerQoSIEWithBitrates(instance, qci, priority, 0, 0, 0, 0)
}

func NewBearerQoSIEWithBitrates(instance, qci, priority uint8, uplinkMBR, downlinkMBR, uplinkGBR, downlinkGBR uint64) (IE, error) {
	if instance > 15 || qci == 0 || priority == 0 || priority > 15 {
		return IE{}, fmt.Errorf("%w: invalid QCI/ARP", ErrMalformedIE)
	}
	value := make([]byte, 22)
	value[0] = priority << 2
	value[1] = qci
	for _, rate := range []struct {
		value  uint64
		offset int
	}{
		{uplinkMBR, 2}, {downlinkMBR, 7}, {uplinkGBR, 12}, {downlinkGBR, 17},
	} {
		if rate.value/1000 > 0xff_ffff_ffff {
			return IE{}, fmt.Errorf("%w: bearer bitrate exceeds 40-bit kbps field", ErrMalformedIE)
		}
		putUint40(value[rate.offset:rate.offset+5], rate.value/1000)
	}
	return IE{Type: IEBearerQoS, Instance: instance, Value: value}, nil
}

func uint40(value []byte) uint64 {
	var out uint64
	for _, octet := range value[:5] {
		out = out<<8 | uint64(octet)
	}
	return out
}

func putUint40(target []byte, value uint64) {
	for index := 4; index >= 0; index-- {
		target[index] = byte(value)
		value >>= 8
	}
}

func (ie IE) IMSI() (string, error) {
	if ie.Type != IEIMSI || len(ie.Value) == 0 || len(ie.Value) > 8 {
		return "", fmt.Errorf("%w: invalid IMSI IE", ErrMalformedIE)
	}
	return decodeTBCD(ie.Value, 15)
}

func NewIMSIIE(imsi string) (IE, error) {
	value, err := encodeTBCD(imsi, 15)
	if err != nil {
		return IE{}, err
	}
	return IE{Type: IEIMSI, Value: value}, nil
}

func (ie IE) APN() (string, error) {
	if ie.Type != IEAPN {
		return "", fmt.Errorf("%w: not an APN IE", ErrMalformedIE)
	}
	return decodeLabels(ie.Value)
}

func NewAPNIE(apn string) (IE, error) {
	value, err := encodeLabels(apn)
	if err != nil {
		return IE{}, err
	}
	return IE{Type: IEAPN, Value: value}, nil
}

func decodeTBCD(value []byte, maxDigits int) (string, error) {
	var b strings.Builder
	for index, octet := range value {
		for nibbleIndex, nibble := range []byte{octet & 0x0f, octet >> 4} {
			last := index == len(value)-1 && nibbleIndex == 1
			if nibble == 0x0f && last {
				continue
			}
			if nibble > 9 || b.Len() >= maxDigits {
				return "", fmt.Errorf("%w: invalid TBCD digit", ErrMalformedIE)
			}
			b.WriteByte('0' + nibble)
		}
	}
	if b.Len() == 0 {
		return "", fmt.Errorf("%w: empty TBCD value", ErrMalformedIE)
	}
	return b.String(), nil
}

func encodeTBCD(digits string, maxDigits int) ([]byte, error) {
	if len(digits) == 0 || len(digits) > maxDigits {
		return nil, fmt.Errorf("%w: invalid digit count", ErrMalformedIE)
	}
	out := make([]byte, (len(digits)+1)/2)
	for index, digit := range []byte(digits) {
		if digit < '0' || digit > '9' {
			return nil, fmt.Errorf("%w: non-decimal digit", ErrMalformedIE)
		}
		value := digit - '0'
		if index%2 == 0 {
			out[index/2] = value
		} else {
			out[index/2] |= value << 4
		}
	}
	if len(digits)%2 == 1 {
		out[len(out)-1] |= 0xf0
	}
	return out, nil
}

func decodeLabels(value []byte) (string, error) {
	if len(value) == 0 || len(value) > 100 {
		return "", fmt.Errorf("%w: invalid APN length", ErrMalformedIE)
	}
	labels := make([]string, 0, 4)
	for offset := 0; offset < len(value); {
		length := int(value[offset])
		offset++
		if length == 0 || length > 63 || length > len(value)-offset {
			return "", fmt.Errorf("%w: malformed APN label", ErrMalformedIE)
		}
		label := string(value[offset : offset+length])
		for _, c := range []byte(label) {
			if !(c == '-' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
				return "", fmt.Errorf("%w: invalid APN character", ErrMalformedIE)
			}
		}
		labels = append(labels, strings.ToLower(label))
		offset += length
	}
	return strings.Join(labels, "."), nil
}

func encodeLabels(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" || len(name) > 100 {
		return nil, fmt.Errorf("%w: invalid APN", ErrMalformedIE)
	}
	labels := strings.Split(name, ".")
	out := make([]byte, 0, len(name)+1)
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("%w: invalid APN label length", ErrMalformedIE)
		}
		for _, c := range []byte(label) {
			if !(c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z') {
				return nil, fmt.Errorf("%w: invalid APN character", ErrMalformedIE)
			}
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return out, nil
}
