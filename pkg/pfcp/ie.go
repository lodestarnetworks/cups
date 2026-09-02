package pfcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const (
	IECreatePDR                  uint16 = 1
	IEPDI                        uint16 = 2
	IECreateFAR                  uint16 = 3
	IEForwardingParameters       uint16 = 4
	IECreateURR                  uint16 = 6
	IECreateQER                  uint16 = 7
	IECreatedPDR                 uint16 = 8
	IEUpdatePDR                  uint16 = 9
	IEUpdateFAR                  uint16 = 10
	IEUpdateForwardingParameters uint16 = 11
	IEUpdateURR                  uint16 = 13
	IEUpdateQER                  uint16 = 14
	IERemovePDR                  uint16 = 15
	IERemoveFAR                  uint16 = 16
	IERemoveURR                  uint16 = 17
	IERemoveQER                  uint16 = 18
	IECause                      uint16 = 19
	IESourceInterface            uint16 = 20
	IEFTEID                      uint16 = 21
	IENetworkInstance            uint16 = 22
	IESDFFilter                  uint16 = 23
	IEGateStatus                 uint16 = 25
	IEMBR                        uint16 = 26
	IEGBR                        uint16 = 27
	IEPrecedence                 uint16 = 29
	IEVolumeThreshold            uint16 = 31
	IEReportingTriggers          uint16 = 37
	IEReportType                 uint16 = 39
	IEDestinationInterface       uint16 = 42
	IEUPFunctionFeatures         uint16 = 43
	IEApplyAction                uint16 = 44
	IEDownlinkDataServiceInfo    uint16 = 45
	IEDownlinkDataNotifyDelay    uint16 = 46
	IEPDRID                      uint16 = 56
	IEFSEID                      uint16 = 57
	IENodeID                     uint16 = 60
	IEMeasurementMethod          uint16 = 62
	IEUsageReportTrigger         uint16 = 63
	IEVolumeMeasurement          uint16 = 66
	IEDurationMeasurement        uint16 = 67
	IETimeOfFirstPacket          uint16 = 69
	IETimeOfLastPacket           uint16 = 70
	IEStartTime                  uint16 = 75
	IEEndTime                    uint16 = 76
	IEUsageReportSessionReport   uint16 = 80
	IEURRID                      uint16 = 81
	IEDownlinkDataReport         uint16 = 83
	IEOuterHeaderCreation        uint16 = 84
	IECreateBAR                  uint16 = 85
	IEUpdateBAR                  uint16 = 86
	IERemoveBAR                  uint16 = 87
	IEBARID                      uint16 = 88
	IECPFunctionFeatures         uint16 = 89
	IEUEIPAddress                uint16 = 93
	IEOuterHeaderRemoval         uint16 = 95
	IERecoveryTimeStamp          uint16 = 96
	IEURSEQN                     uint16 = 104
	IEFARID                      uint16 = 108
	IEQERID                      uint16 = 109
	IEPDNType                    uint16 = 113
	IEAPNDNN                     uint16 = 159

	// IEVendorBearerQoS is a vendor-controlled type for the optional Lodestar
	// Sxa bearer metadata profile. Its value includes the configured IANA
	// Private Enterprise Number and it is never emitted when that number is 0.
	IEVendorBearerQoS uint16 = 0x8000
)

const (
	CauseRequestAccepted      uint8 = 1
	CauseRequestRejected      uint8 = 64
	CauseSessionNotFound      uint8 = 65
	CauseMandatoryIEMissing   uint8 = 66
	CauseConditionalIEMissing uint8 = 67
	CauseInvalidLength        uint8 = 68
	CauseMandatoryIEIncorrect uint8 = 69
	CauseNoAssociation        uint8 = 72
	CauseRuleCreationFailure  uint8 = 73
	CauseNoResources          uint8 = 75
	CauseServiceNotSupported  uint8 = 76
	CauseSystemFailure        uint8 = 77
)

const (
	InterfaceAccess uint8 = 0
	InterfaceCore   uint8 = 1
)

const (
	ApplyDrop               uint8 = 1 << 0
	ApplyForward            uint8 = 1 << 1
	ApplyBuffer             uint8 = 1 << 2
	ApplyNotifyControlPlane uint8 = 1 << 3
)

const (
	ReportDownlinkData uint8 = 1 << 0
	ReportUsage        uint8 = 1 << 1
)

const (
	UsageReportTriggerPeriodic        uint32 = 1 << 0
	UsageReportTriggerVolumeThreshold uint32 = 1 << 1
	UsageReportTriggerTimeThreshold   uint32 = 1 << 2
	UsageReportTriggerImmediate       uint32 = 1 << 7
	UsageReportTriggerTermination     uint32 = 1 << 11
)

const (
	MeasurementDuration uint8 = 1 << 0
	MeasurementVolume   uint8 = 1 << 1
)

const (
	ReportingTriggerPeriodic        uint32 = 1 << 0
	ReportingTriggerVolumeThreshold uint32 = 1 << 1
	ReportingTriggerTimeThreshold   uint32 = 1 << 2
)

const (
	OuterHeaderGTPUUDPIPv4 uint16 = 0x0100
	OuterHeaderGTPUUDPIPv6 uint16 = 0x0200
)

const (
	OuterHeaderRemovalGTPUUDPIPv4 uint8 = 0
	OuterHeaderRemovalGTPUUDPIPv6 uint8 = 1
	OuterHeaderRemovalGTPUUDPIP   uint8 = 6
)

const (
	maxIEsPerScope  = 512
	maxGroupedDepth = 8
	ntpUnixOffset   = 2_208_988_800
)

var (
	ErrMalformedIE  = errors.New("pfcp: malformed information element")
	ErrTooManyIEs   = errors.New("pfcp: too many information elements")
	ErrGroupedDepth = errors.New("pfcp: grouped information element depth exceeded")
	ErrMissingIE    = errors.New("pfcp: mandatory information element missing")
)

type IE struct {
	Type  uint16
	Value []byte
}

type FSEID struct {
	SEID uint64
	IPv4 netip.Addr
	IPv6 netip.Addr
}

type FTEID struct {
	TEID uint32
	IPv4 netip.Addr
	IPv6 netip.Addr
}

type OuterHeader struct {
	Description uint16
	TEID        uint32
	IPv4        netip.Addr
	IPv6        netip.Addr
	Port        uint16
}

// UEIPAddress is the IPv4 subset of the PFCP UE IP Address IE used by the
// LTE Sxb profile. Destination is true for downlink PDR matching and false for
// uplink source-address matching.
type UEIPAddress struct {
	IPv4        netip.Addr
	Destination bool
}

// BearerQoSMetadata is the LTE bearer information carried by the optional
// Lodestar vendor profile when both CUPS peers are configured with the same
// registered IANA Private Enterprise Number.
type BearerQoSMetadata struct {
	EnterpriseID         uint16
	QCI                  uint8
	ARP                  uint8
	PreemptionCapable    bool
	PreemptionVulnerable bool
}

type VolumeThreshold struct {
	HasTotal    bool
	HasUplink   bool
	HasDownlink bool
	Total       uint64
	Uplink      uint64
	Downlink    uint64
}

// VolumeMeasurement is the volume-and-packet subset of TS 29.244 clause
// 8.2.44. Values are cumulative within one Usage Report interval.
type VolumeMeasurement struct {
	HasTotalPackets    bool
	HasUplinkPackets   bool
	HasDownlinkPackets bool
	HasTotalBytes      bool
	HasUplinkBytes     bool
	HasDownlinkBytes   bool
	TotalPackets       uint64
	UplinkPackets      uint64
	DownlinkPackets    uint64
	TotalBytes         uint64
	UplinkBytes        uint64
	DownlinkBytes      uint64
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
		typ := binary.BigEndian.Uint16(payload[offset : offset+2])
		length := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		total := 4 + length
		if typ == 0 || total < 4 || total > len(payload)-offset {
			return nil, fmt.Errorf("%w: type=%d length=%d remaining=%d", ErrMalformedIE, typ, length, len(payload)-offset)
		}
		ies = append(ies, IE{Type: typ, Value: append([]byte(nil), payload[offset+4:offset+total]...)})
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
		if ie.Type == 0 || len(ie.Value) > 0xffff {
			return nil, fmt.Errorf("%w: type=%d length=%d", ErrMalformedIE, ie.Type, len(ie.Value))
		}
		if total > 0xffff-(4+len(ie.Value)) {
			return nil, fmt.Errorf("%w: aggregate IE payload too large", ErrMalformedIE)
		}
		total += 4 + len(ie.Value)
	}
	out := make([]byte, total)
	offset := 0
	for _, ie := range ies {
		binary.BigEndian.PutUint16(out[offset:offset+2], ie.Type)
		binary.BigEndian.PutUint16(out[offset+2:offset+4], uint16(len(ie.Value)))
		copy(out[offset+4:], ie.Value)
		offset += 4 + len(ie.Value)
	}
	return out, nil
}

func (ie IE) Clone() IE {
	return IE{Type: ie.Type, Value: append([]byte(nil), ie.Value...)}
}

func IsGroupedType(typ uint16) bool {
	switch typ {
	case IECreatePDR, IEPDI, IECreateFAR, IEForwardingParameters, IECreateURR,
		IECreateQER, IECreatedPDR, IEUpdatePDR, IEUpdateFAR,
		IEUpdateForwardingParameters, IEUpdateURR, IEUpdateQER, IERemovePDR,
		IERemoveFAR, IERemoveURR, IERemoveQER, IEDownlinkDataReport,
		IECreateBAR, IEUpdateBAR, IERemoveBAR, IEUsageReportSessionReport:
		return true
	default:
		return false
	}
}

func (ie IE) Children() ([]IE, error) {
	if !IsGroupedType(ie.Type) {
		return nil, fmt.Errorf("%w: IE type %d is not grouped", ErrMalformedIE, ie.Type)
	}
	return parseIEs(ie.Value, 1)
}

func NewGroupedIE(typ uint16, children ...IE) (IE, error) {
	if !IsGroupedType(typ) {
		return IE{}, fmt.Errorf("%w: IE type %d is not grouped", ErrMalformedIE, typ)
	}
	value, err := MarshalIEs(children)
	if err != nil {
		return IE{}, err
	}
	return IE{Type: typ, Value: value}, nil
}

func FindIE(ies []IE, typ uint16) (IE, bool) {
	for _, ie := range ies {
		if ie.Type == typ {
			return ie.Clone(), true
		}
	}
	return IE{}, false
}

func FindAllIEs(ies []IE, typ uint16) []IE {
	out := make([]IE, 0, 1)
	for _, ie := range ies {
		if ie.Type == typ {
			out = append(out, ie.Clone())
		}
	}
	return out
}

func NewCauseIE(cause uint8) IE {
	return IE{Type: IECause, Value: []byte{cause}}
}

func (ie IE) Cause() (uint8, error) {
	if ie.Type != IECause || len(ie.Value) < 1 || ie.Value[0] == 0 {
		return 0, fmt.Errorf("%w: invalid Cause IE", ErrMalformedIE)
	}
	return ie.Value[0], nil
}

func NewReportTypeIE(flags uint8) (IE, error) {
	if flags == 0 || flags&^(ReportDownlinkData|ReportUsage) != 0 {
		return IE{}, fmt.Errorf("%w: unsupported Report Type flags 0x%x", ErrMalformedIE, flags)
	}
	return IE{Type: IEReportType, Value: []byte{flags}}, nil
}

func (ie IE) ReportType() (uint8, error) {
	if ie.Type != IEReportType || len(ie.Value) < 1 {
		return 0, fmt.Errorf("%w: invalid Report Type IE", ErrMalformedIE)
	}
	if _, err := NewReportTypeIE(ie.Value[0]); err != nil {
		return 0, err
	}
	return ie.Value[0], nil
}

func NewURSEQNIE(sequence uint32) IE {
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, sequence)
	return IE{Type: IEURSEQN, Value: value}
}

func (ie IE) URSEQN() (uint32, error) {
	if ie.Type != IEURSEQN || len(ie.Value) != 4 {
		return 0, fmt.Errorf("%w: invalid UR-SEQN IE", ErrMalformedIE)
	}
	return binary.BigEndian.Uint32(ie.Value), nil
}

// NewUsageReportTriggerIE accepts operational reporting triggers only. Quota
// triggers are intentionally unsupported because usage never gates Lodestar
// mobile data forwarding.
func NewUsageReportTriggerIE(flags uint32) (IE, error) {
	const supported = UsageReportTriggerPeriodic | UsageReportTriggerVolumeThreshold |
		UsageReportTriggerTimeThreshold | UsageReportTriggerImmediate | UsageReportTriggerTermination
	if flags == 0 || flags&^supported != 0 {
		return IE{}, fmt.Errorf("%w: unsupported Usage Report Trigger flags 0x%x", ErrMalformedIE, flags)
	}
	length := 1
	if flags > 0xff {
		length = 2
	}
	if flags > 0xffff {
		length = 3
	}
	value := make([]byte, length)
	for index := range value {
		value[index] = byte(flags >> (8 * index))
	}
	return IE{Type: IEUsageReportTrigger, Value: value}, nil
}

func (ie IE) UsageReportTrigger() (uint32, error) {
	if ie.Type != IEUsageReportTrigger || len(ie.Value) < 1 || len(ie.Value) > 3 {
		return 0, fmt.Errorf("%w: invalid Usage Report Trigger IE", ErrMalformedIE)
	}
	var flags uint32
	for index, value := range ie.Value {
		flags |= uint32(value) << (8 * index)
	}
	if _, err := NewUsageReportTriggerIE(flags); err != nil {
		return 0, err
	}
	return flags, nil
}

func NewVolumeMeasurementIE(measurement VolumeMeasurement) (IE, error) {
	fields := []struct {
		present bool
		value   uint64
	}{
		{measurement.HasTotalBytes, measurement.TotalBytes},
		{measurement.HasUplinkBytes, measurement.UplinkBytes},
		{measurement.HasDownlinkBytes, measurement.DownlinkBytes},
		{measurement.HasTotalPackets, measurement.TotalPackets},
		{measurement.HasUplinkPackets, measurement.UplinkPackets},
		{measurement.HasDownlinkPackets, measurement.DownlinkPackets},
	}
	flags := uint8(0)
	count := 0
	for index, field := range fields {
		if field.present {
			flags |= 1 << index
			count++
		}
	}
	if flags == 0 {
		return IE{}, fmt.Errorf("%w: empty Volume Measurement IE", ErrMalformedIE)
	}
	value := make([]byte, 1+count*8)
	value[0] = flags
	offset := 1
	for _, field := range fields {
		if !field.present {
			continue
		}
		binary.BigEndian.PutUint64(value[offset:offset+8], field.value)
		offset += 8
	}
	return IE{Type: IEVolumeMeasurement, Value: value}, nil
}

func (ie IE) VolumeMeasurement() (VolumeMeasurement, error) {
	if ie.Type != IEVolumeMeasurement || len(ie.Value) < 9 || ie.Value[0] == 0 || ie.Value[0]&^uint8(0x3f) != 0 {
		return VolumeMeasurement{}, fmt.Errorf("%w: invalid Volume Measurement IE", ErrMalformedIE)
	}
	flags := ie.Value[0]
	count := 0
	for bit := uint8(0); bit < 6; bit++ {
		if flags&(1<<bit) != 0 {
			count++
		}
	}
	if len(ie.Value) != 1+count*8 {
		return VolumeMeasurement{}, fmt.Errorf("%w: invalid Volume Measurement length", ErrMalformedIE)
	}
	out := VolumeMeasurement{
		HasTotalBytes: flags&(1<<0) != 0, HasUplinkBytes: flags&(1<<1) != 0, HasDownlinkBytes: flags&(1<<2) != 0,
		HasTotalPackets: flags&(1<<3) != 0, HasUplinkPackets: flags&(1<<4) != 0, HasDownlinkPackets: flags&(1<<5) != 0,
	}
	destinations := []struct {
		present bool
		value   *uint64
	}{
		{out.HasTotalBytes, &out.TotalBytes}, {out.HasUplinkBytes, &out.UplinkBytes}, {out.HasDownlinkBytes, &out.DownlinkBytes},
		{out.HasTotalPackets, &out.TotalPackets}, {out.HasUplinkPackets, &out.UplinkPackets}, {out.HasDownlinkPackets, &out.DownlinkPackets},
	}
	offset := 1
	for _, destination := range destinations {
		if !destination.present {
			continue
		}
		*destination.value = binary.BigEndian.Uint64(ie.Value[offset : offset+8])
		offset += 8
	}
	return out, nil
}

func NewDurationMeasurementIE(duration time.Duration) (IE, error) {
	if duration < 0 || uint64(duration/time.Second) > uint64(^uint32(0)) {
		return IE{}, fmt.Errorf("%w: duration measurement outside Uint32 seconds", ErrMalformedIE)
	}
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, uint32(duration/time.Second))
	return IE{Type: IEDurationMeasurement, Value: value}, nil
}

func (ie IE) DurationMeasurement() (time.Duration, error) {
	if ie.Type != IEDurationMeasurement || len(ie.Value) != 4 {
		return 0, fmt.Errorf("%w: invalid Duration Measurement IE", ErrMalformedIE)
	}
	return time.Duration(binary.BigEndian.Uint32(ie.Value)) * time.Second, nil
}

func NewUsageTimeIE(typ uint16, value time.Time) (IE, error) {
	switch typ {
	case IEStartTime, IEEndTime, IETimeOfFirstPacket, IETimeOfLastPacket:
	default:
		return IE{}, fmt.Errorf("%w: unsupported usage timestamp IE %d", ErrMalformedIE, typ)
	}
	seconds := value.UTC().Unix()
	if value.IsZero() || seconds < -ntpUnixOffset || seconds > int64(^uint32(0))-ntpUnixOffset {
		return IE{}, fmt.Errorf("%w: usage timestamp outside NTP32 range", ErrMalformedIE)
	}
	wire := make([]byte, 4)
	binary.BigEndian.PutUint32(wire, uint32(seconds+ntpUnixOffset))
	return IE{Type: typ, Value: wire}, nil
}

func (ie IE) UsageTime() (time.Time, error) {
	switch ie.Type {
	case IEStartTime, IEEndTime, IETimeOfFirstPacket, IETimeOfLastPacket:
	default:
		return time.Time{}, fmt.Errorf("%w: unsupported usage timestamp IE %d", ErrMalformedIE, ie.Type)
	}
	if len(ie.Value) != 4 {
		return time.Time{}, fmt.Errorf("%w: invalid usage timestamp IE", ErrMalformedIE)
	}
	seconds := int64(binary.BigEndian.Uint32(ie.Value)) - ntpUnixOffset
	return time.Unix(seconds, 0).UTC(), nil
}

func NewBARIDIE(id uint8) (IE, error) {
	if id == 0 {
		return IE{}, fmt.Errorf("%w: zero BAR ID", ErrMalformedIE)
	}
	return IE{Type: IEBARID, Value: []byte{id}}, nil
}

func (ie IE) BARID() (uint8, error) {
	if ie.Type != IEBARID || len(ie.Value) < 1 || ie.Value[0] == 0 {
		return 0, fmt.Errorf("%w: invalid BAR ID", ErrMalformedIE)
	}
	return ie.Value[0], nil
}

// NewDownlinkDataNotificationDelayIE encodes the Sxa BAR delay in the 50 ms
// units mandated by TS 29.244. A zero value explicitly clears the delay.
func NewDownlinkDataNotificationDelayIE(delay time.Duration) (IE, error) {
	const unit = 50 * time.Millisecond
	if delay < 0 || delay%unit != 0 || delay/unit > 255 {
		return IE{}, fmt.Errorf("%w: downlink notification delay must be 0..12750 ms in 50 ms units", ErrMalformedIE)
	}
	return IE{Type: IEDownlinkDataNotifyDelay, Value: []byte{byte(delay / unit)}}, nil
}

func (ie IE) DownlinkDataNotificationDelay() (time.Duration, error) {
	if ie.Type != IEDownlinkDataNotifyDelay || len(ie.Value) < 1 {
		return 0, fmt.Errorf("%w: invalid Downlink Data Notification Delay IE", ErrMalformedIE)
	}
	return time.Duration(ie.Value[0]) * 50 * time.Millisecond, nil
}

// NewVendorBearerQoSIE encodes QCI/ARP without pretending those fields are a
// standard Sxa QER parameter. The caller must supply its registered PEN; 0 and
// 10415 (3GPP) are deliberately rejected.
func NewVendorBearerQoSIE(metadata BearerQoSMetadata) (IE, error) {
	if metadata.EnterpriseID == 0 || metadata.EnterpriseID == 10415 || metadata.QCI == 0 || metadata.ARP == 0 || metadata.ARP > 15 {
		return IE{}, fmt.Errorf("%w: invalid vendor bearer QoS metadata", ErrMalformedIE)
	}
	flags := uint8(0)
	if metadata.PreemptionCapable {
		flags |= 1 << 0
	}
	if metadata.PreemptionVulnerable {
		flags |= 1 << 1
	}
	value := make([]byte, 6)
	binary.BigEndian.PutUint16(value[:2], metadata.EnterpriseID)
	value[2] = 1 // Lodestar bearer metadata profile version.
	value[3] = metadata.QCI
	value[4] = metadata.ARP
	value[5] = flags
	return IE{Type: IEVendorBearerQoS, Value: value}, nil
}

func (ie IE) VendorBearerQoS() (BearerQoSMetadata, error) {
	if ie.Type != IEVendorBearerQoS || len(ie.Value) < 6 || ie.Value[2] != 1 || ie.Value[5]&^uint8(0x03) != 0 {
		return BearerQoSMetadata{}, fmt.Errorf("%w: invalid vendor bearer QoS IE", ErrMalformedIE)
	}
	metadata := BearerQoSMetadata{
		EnterpriseID:         binary.BigEndian.Uint16(ie.Value[:2]),
		QCI:                  ie.Value[3],
		ARP:                  ie.Value[4],
		PreemptionCapable:    ie.Value[5]&(1<<0) != 0,
		PreemptionVulnerable: ie.Value[5]&(1<<1) != 0,
	}
	if metadata.EnterpriseID == 0 || metadata.EnterpriseID == 10415 || metadata.QCI == 0 || metadata.ARP == 0 || metadata.ARP > 15 {
		return BearerQoSMetadata{}, fmt.Errorf("%w: invalid vendor bearer QoS metadata", ErrMalformedIE)
	}
	return metadata, nil
}

// NewMeasurementMethodIE encodes the LTE PFCP duration/volume subset. Event
// charging is intentionally outside this EPC profile.
func NewMeasurementMethodIE(volume, duration bool) (IE, error) {
	flags := uint8(0)
	if duration {
		flags |= MeasurementDuration
	}
	if volume {
		flags |= MeasurementVolume
	}
	if flags == 0 {
		return IE{}, fmt.Errorf("%w: at least one measurement method is required", ErrMalformedIE)
	}
	return IE{Type: IEMeasurementMethod, Value: []byte{flags}}, nil
}

func (ie IE) MeasurementMethod() (volume, duration bool, err error) {
	if ie.Type != IEMeasurementMethod || len(ie.Value) < 1 || ie.Value[0]&^(MeasurementDuration|MeasurementVolume) != 0 || ie.Value[0] == 0 {
		return false, false, fmt.Errorf("%w: invalid Measurement Method IE", ErrMalformedIE)
	}
	return ie.Value[0]&MeasurementVolume != 0, ie.Value[0]&MeasurementDuration != 0, nil
}

// NewReportingTriggersIE encodes the 24-bit Reporting Triggers field. This
// release accepts only telemetry thresholds/periods and never quota triggers.
func NewReportingTriggersIE(flags uint32) (IE, error) {
	const supported = ReportingTriggerPeriodic | ReportingTriggerVolumeThreshold | ReportingTriggerTimeThreshold
	if flags == 0 || flags&^supported != 0 {
		return IE{}, fmt.Errorf("%w: unsupported Reporting Triggers flags 0x%x", ErrMalformedIE, flags)
	}
	return IE{Type: IEReportingTriggers, Value: []byte{byte(flags), byte(flags >> 8), byte(flags >> 16)}}, nil
}

func (ie IE) ReportingTriggers() (uint32, error) {
	if ie.Type != IEReportingTriggers || len(ie.Value) < 1 || len(ie.Value) > 3 {
		return 0, fmt.Errorf("%w: invalid Reporting Triggers IE", ErrMalformedIE)
	}
	flags := uint32(ie.Value[0])
	if len(ie.Value) > 1 {
		flags |= uint32(ie.Value[1]) << 8
	}
	if len(ie.Value) > 2 {
		flags |= uint32(ie.Value[2]) << 16
	}
	if _, err := NewReportingTriggersIE(flags); err != nil {
		return 0, err
	}
	return flags, nil
}

func NewVolumeThresholdIE(threshold VolumeThreshold) (IE, error) {
	flags := uint8(0)
	length := 1
	if threshold.HasTotal {
		flags |= 1 << 0
		length += 8
	}
	if threshold.HasUplink {
		flags |= 1 << 1
		length += 8
	}
	if threshold.HasDownlink {
		flags |= 1 << 2
		length += 8
	}
	if flags == 0 || threshold.HasTotal && threshold.Total == 0 || threshold.HasUplink && threshold.Uplink == 0 || threshold.HasDownlink && threshold.Downlink == 0 {
		return IE{}, fmt.Errorf("%w: invalid Volume Threshold IE", ErrMalformedIE)
	}
	value := make([]byte, length)
	value[0] = flags
	offset := 1
	for _, field := range []struct {
		present bool
		value   uint64
	}{{threshold.HasTotal, threshold.Total}, {threshold.HasUplink, threshold.Uplink}, {threshold.HasDownlink, threshold.Downlink}} {
		if field.present {
			binary.BigEndian.PutUint64(value[offset:offset+8], field.value)
			offset += 8
		}
	}
	return IE{Type: IEVolumeThreshold, Value: value}, nil
}

func NewTotalVolumeThresholdIE(bytes uint64) (IE, error) {
	return NewVolumeThresholdIE(VolumeThreshold{HasTotal: true, Total: bytes})
}

func (ie IE) VolumeThreshold() (VolumeThreshold, error) {
	if ie.Type != IEVolumeThreshold || len(ie.Value) < 1 || ie.Value[0]&^uint8(0x07) != 0 || ie.Value[0] == 0 {
		return VolumeThreshold{}, fmt.Errorf("%w: invalid Volume Threshold IE", ErrMalformedIE)
	}
	flags := ie.Value[0]
	want := 1 + 8*int(flags&1) + 4*int(flags&2) + 2*int(flags&4)
	if len(ie.Value) != want {
		return VolumeThreshold{}, fmt.Errorf("%w: invalid Volume Threshold length", ErrMalformedIE)
	}
	out := VolumeThreshold{HasTotal: flags&1 != 0, HasUplink: flags&2 != 0, HasDownlink: flags&4 != 0}
	offset := 1
	for _, field := range []struct {
		present bool
		dst     *uint64
	}{{out.HasTotal, &out.Total}, {out.HasUplink, &out.Uplink}, {out.HasDownlink, &out.Downlink}} {
		if field.present {
			*field.dst = binary.BigEndian.Uint64(ie.Value[offset : offset+8])
			if *field.dst == 0 {
				return VolumeThreshold{}, fmt.Errorf("%w: zero Volume Threshold", ErrMalformedIE)
			}
			offset += 8
		}
	}
	return out, nil
}

func NewNodeIDIE(addr netip.Addr, fqdn string) (IE, error) {
	switch {
	case addr.Is4():
		raw := addr.As4()
		return IE{Type: IENodeID, Value: append([]byte{0}, raw[:]...)}, nil
	case addr.Is6():
		raw := addr.As16()
		return IE{Type: IENodeID, Value: append([]byte{1}, raw[:]...)}, nil
	case fqdn != "":
		labels, err := encodeLabels(fqdn)
		if err != nil {
			return IE{}, err
		}
		return IE{Type: IENodeID, Value: append([]byte{2}, labels...)}, nil
	default:
		return IE{}, fmt.Errorf("%w: Node ID requires an address or FQDN", ErrMalformedIE)
	}
}

func (ie IE) NodeID() (netip.Addr, string, error) {
	if ie.Type != IENodeID || len(ie.Value) < 2 {
		return netip.Addr{}, "", fmt.Errorf("%w: invalid Node ID IE", ErrMalformedIE)
	}
	switch ie.Value[0] & 0x0f {
	case 0:
		if len(ie.Value) < 5 {
			return netip.Addr{}, "", fmt.Errorf("%w: truncated IPv4 Node ID", ErrMalformedIE)
		}
		var raw [4]byte
		copy(raw[:], ie.Value[1:5])
		return netip.AddrFrom4(raw), "", nil
	case 1:
		if len(ie.Value) < 17 {
			return netip.Addr{}, "", fmt.Errorf("%w: truncated IPv6 Node ID", ErrMalformedIE)
		}
		var raw [16]byte
		copy(raw[:], ie.Value[1:17])
		return netip.AddrFrom16(raw), "", nil
	case 2:
		fqdn, err := decodeLabels(ie.Value[1:])
		return netip.Addr{}, fqdn, err
	default:
		return netip.Addr{}, "", fmt.Errorf("%w: unsupported Node ID type", ErrMalformedIE)
	}
}

func NewRecoveryTimeStampIE(started time.Time) (IE, error) {
	seconds := started.UTC().Unix()
	if seconds < -ntpUnixOffset || seconds > int64(^uint32(0))-ntpUnixOffset {
		return IE{}, fmt.Errorf("%w: recovery timestamp outside NTP32 range", ErrMalformedIE)
	}
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, uint32(seconds+ntpUnixOffset))
	return IE{Type: IERecoveryTimeStamp, Value: value}, nil
}

func (ie IE) RecoveryTimeStamp() (time.Time, error) {
	if ie.Type != IERecoveryTimeStamp || len(ie.Value) < 4 {
		return time.Time{}, fmt.Errorf("%w: invalid Recovery Time Stamp IE", ErrMalformedIE)
	}
	seconds := int64(binary.BigEndian.Uint32(ie.Value[:4])) - ntpUnixOffset
	return time.Unix(seconds, 0).UTC(), nil
}

func NewFSEIDIE(f FSEID) (IE, error) {
	if f.SEID == 0 {
		return IE{}, fmt.Errorf("%w: zero F-SEID", ErrMalformedIE)
	}
	flags := byte(0)
	length := 9
	if f.IPv4.IsValid() {
		if !f.IPv4.Is4() {
			return IE{}, fmt.Errorf("%w: F-SEID IPv4 field is not IPv4", ErrMalformedIE)
		}
		flags |= 0x02
		length += 4
	}
	if f.IPv6.IsValid() {
		if !f.IPv6.Is6() {
			return IE{}, fmt.Errorf("%w: F-SEID IPv6 field is not IPv6", ErrMalformedIE)
		}
		flags |= 0x01
		length += 16
	}
	if flags == 0 {
		return IE{}, fmt.Errorf("%w: F-SEID requires an IP address", ErrMalformedIE)
	}
	value := make([]byte, length)
	value[0] = flags
	binary.BigEndian.PutUint64(value[1:9], f.SEID)
	offset := 9
	if f.IPv4.IsValid() {
		raw := f.IPv4.As4()
		copy(value[offset:offset+4], raw[:])
		offset += 4
	}
	if f.IPv6.IsValid() {
		raw := f.IPv6.As16()
		copy(value[offset:offset+16], raw[:])
	}
	return IE{Type: IEFSEID, Value: value}, nil
}

func (ie IE) FSEID() (FSEID, error) {
	if ie.Type != IEFSEID || len(ie.Value) < 9 {
		return FSEID{}, fmt.Errorf("%w: invalid F-SEID IE", ErrMalformedIE)
	}
	flags := ie.Value[0]
	need := 9
	if flags&0x02 != 0 {
		need += 4
	}
	if flags&0x01 != 0 {
		need += 16
	}
	if flags&0x03 == 0 || len(ie.Value) < need {
		return FSEID{}, fmt.Errorf("%w: malformed F-SEID addresses", ErrMalformedIE)
	}
	out := FSEID{SEID: binary.BigEndian.Uint64(ie.Value[1:9])}
	if out.SEID == 0 {
		return FSEID{}, fmt.Errorf("%w: zero F-SEID", ErrMalformedIE)
	}
	offset := 9
	if flags&0x02 != 0 {
		var raw [4]byte
		copy(raw[:], ie.Value[offset:offset+4])
		out.IPv4 = netip.AddrFrom4(raw)
		offset += 4
	}
	if flags&0x01 != 0 {
		var raw [16]byte
		copy(raw[:], ie.Value[offset:offset+16])
		out.IPv6 = netip.AddrFrom16(raw)
	}
	return out, nil
}

func NewUEIPAddressIE(addr netip.Addr, destination bool) (IE, error) {
	if !addr.Is4() {
		return IE{}, fmt.Errorf("%w: UE IP Address requires IPv4", ErrMalformedIE)
	}
	raw := addr.Unmap().As4()
	flags := byte(0x02) // V4
	if destination {
		flags |= 0x04 // S/D
	}
	value := make([]byte, 5)
	value[0] = flags
	copy(value[1:], raw[:])
	return IE{Type: IEUEIPAddress, Value: value}, nil
}

func (ie IE) UEIPAddress() (UEIPAddress, error) {
	if ie.Type != IEUEIPAddress || len(ie.Value) != 5 {
		return UEIPAddress{}, fmt.Errorf("%w: invalid IPv4 UE IP Address IE", ErrMalformedIE)
	}
	flags := ie.Value[0]
	// This profile requires V4, forbids V6 and all allocation/prefix flags, and
	// accepts only the S/D selector in addition to V4.
	if flags&0x02 == 0 || flags&0x01 != 0 || flags&^byte(0x06) != 0 {
		return UEIPAddress{}, fmt.Errorf("%w: unsupported UE IP Address flags 0x%x", ErrMalformedIE, flags)
	}
	var raw [4]byte
	copy(raw[:], ie.Value[1:])
	addr := netip.AddrFrom4(raw)
	if addr.IsUnspecified() || addr.IsMulticast() {
		return UEIPAddress{}, fmt.Errorf("%w: unusable UE IPv4 address", ErrMalformedIE)
	}
	return UEIPAddress{IPv4: addr, Destination: flags&0x04 != 0}, nil
}

func NewFTEIDIE(f FTEID) (IE, error) {
	if f.TEID == 0 {
		return IE{}, fmt.Errorf("%w: zero F-TEID", ErrMalformedIE)
	}
	flags := byte(0)
	length := 5
	if f.IPv4.IsValid() {
		if !f.IPv4.Is4() {
			return IE{}, fmt.Errorf("%w: F-TEID IPv4 field is not IPv4", ErrMalformedIE)
		}
		flags |= 0x01
		length += 4
	}
	if f.IPv6.IsValid() {
		if !f.IPv6.Is6() {
			return IE{}, fmt.Errorf("%w: F-TEID IPv6 field is not IPv6", ErrMalformedIE)
		}
		flags |= 0x02
		length += 16
	}
	if flags == 0 {
		return IE{}, fmt.Errorf("%w: F-TEID requires an IP address", ErrMalformedIE)
	}
	value := make([]byte, length)
	value[0] = flags
	binary.BigEndian.PutUint32(value[1:5], f.TEID)
	offset := 5
	if f.IPv4.IsValid() {
		raw := f.IPv4.As4()
		copy(value[offset:offset+4], raw[:])
		offset += 4
	}
	if f.IPv6.IsValid() {
		raw := f.IPv6.As16()
		copy(value[offset:offset+16], raw[:])
	}
	return IE{Type: IEFTEID, Value: value}, nil
}

func (ie IE) FTEID() (FTEID, error) {
	if ie.Type != IEFTEID || len(ie.Value) < 5 {
		return FTEID{}, fmt.Errorf("%w: invalid F-TEID IE", ErrMalformedIE)
	}
	flags := ie.Value[0]
	if flags&0x04 != 0 {
		return FTEID{}, fmt.Errorf("%w: CHOOSE F-TEID is not an allocated F-TEID", ErrMalformedIE)
	}
	need := 5
	if flags&0x01 != 0 {
		need += 4
	}
	if flags&0x02 != 0 {
		need += 16
	}
	if flags&0x03 == 0 || len(ie.Value) < need {
		return FTEID{}, fmt.Errorf("%w: malformed F-TEID addresses", ErrMalformedIE)
	}
	out := FTEID{TEID: binary.BigEndian.Uint32(ie.Value[1:5])}
	if out.TEID == 0 {
		return FTEID{}, fmt.Errorf("%w: zero F-TEID", ErrMalformedIE)
	}
	offset := 5
	if flags&0x01 != 0 {
		var raw [4]byte
		copy(raw[:], ie.Value[offset:offset+4])
		out.IPv4 = netip.AddrFrom4(raw)
		offset += 4
	}
	if flags&0x02 != 0 {
		var raw [16]byte
		copy(raw[:], ie.Value[offset:offset+16])
		out.IPv6 = netip.AddrFrom16(raw)
	}
	return out, nil
}

func NewInterfaceIE(typ uint16, value uint8) (IE, error) {
	if typ != IESourceInterface && typ != IEDestinationInterface || value > 15 {
		return IE{}, fmt.Errorf("%w: invalid interface IE", ErrMalformedIE)
	}
	return IE{Type: typ, Value: []byte{value & 0x0f}}, nil
}

func (ie IE) Interface() (uint8, error) {
	if (ie.Type != IESourceInterface && ie.Type != IEDestinationInterface) || len(ie.Value) < 1 {
		return 0, fmt.Errorf("%w: invalid interface IE", ErrMalformedIE)
	}
	value := ie.Value[0] & 0x0f
	if value > 5 {
		return 0, fmt.Errorf("%w: unsupported interface value %d", ErrMalformedIE, value)
	}
	return value, nil
}

func NewPDRIDIE(id uint16) (IE, error) {
	if id == 0 {
		return IE{}, fmt.Errorf("%w: zero PDR ID", ErrMalformedIE)
	}
	value := make([]byte, 2)
	binary.BigEndian.PutUint16(value, id)
	return IE{Type: IEPDRID, Value: value}, nil
}

func (ie IE) PDRID() (uint16, error) {
	if ie.Type != IEPDRID || len(ie.Value) < 2 {
		return 0, fmt.Errorf("%w: invalid PDR ID", ErrMalformedIE)
	}
	id := binary.BigEndian.Uint16(ie.Value[:2])
	if id == 0 {
		return 0, fmt.Errorf("%w: zero PDR ID", ErrMalformedIE)
	}
	return id, nil
}

func NewUint32IE(typ uint16, value uint32) (IE, error) {
	switch typ {
	case IEPrecedence, IEFARID, IEQERID, IEURRID:
	default:
		return IE{}, fmt.Errorf("%w: unsupported uint32 IE type %d", ErrMalformedIE, typ)
	}
	if value == 0 && typ != IEPrecedence {
		return IE{}, fmt.Errorf("%w: zero rule ID", ErrMalformedIE)
	}
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, value)
	return IE{Type: typ, Value: payload}, nil
}

func (ie IE) Uint32() (uint32, error) {
	if len(ie.Value) < 4 {
		return 0, fmt.Errorf("%w: truncated uint32 IE", ErrMalformedIE)
	}
	switch ie.Type {
	case IEPrecedence, IEFARID, IEQERID, IEURRID:
		return binary.BigEndian.Uint32(ie.Value[:4]), nil
	default:
		return 0, fmt.Errorf("%w: IE type %d is not uint32", ErrMalformedIE, ie.Type)
	}
}

func NewApplyActionIE(action uint8) (IE, error) {
	primary := action & (ApplyDrop | ApplyForward | ApplyBuffer)
	if primary == 0 || primary&(primary-1) != 0 || action&^(ApplyDrop|ApplyForward|ApplyBuffer|ApplyNotifyControlPlane) != 0 {
		return IE{}, fmt.Errorf("%w: invalid apply action 0x%x", ErrMalformedIE, action)
	}
	if action&ApplyNotifyControlPlane != 0 && action&ApplyBuffer == 0 {
		return IE{}, fmt.Errorf("%w: notify requires buffer", ErrMalformedIE)
	}
	return IE{Type: IEApplyAction, Value: []byte{action}}, nil
}

func (ie IE) ApplyAction() (uint8, error) {
	if ie.Type != IEApplyAction || len(ie.Value) < 1 {
		return 0, fmt.Errorf("%w: invalid Apply Action IE", ErrMalformedIE)
	}
	if _, err := NewApplyActionIE(ie.Value[0]); err != nil {
		return 0, err
	}
	return ie.Value[0], nil
}

func NewOuterHeaderCreationIE(header OuterHeader) (IE, error) {
	if header.Description != OuterHeaderGTPUUDPIPv4 && header.Description != OuterHeaderGTPUUDPIPv6 {
		return IE{}, fmt.Errorf("%w: unsupported outer-header description 0x%x", ErrMalformedIE, header.Description)
	}
	if header.TEID == 0 {
		return IE{}, fmt.Errorf("%w: outer header has zero TEID", ErrMalformedIE)
	}
	length := 6
	if header.Description == OuterHeaderGTPUUDPIPv4 {
		if !header.IPv4.Is4() {
			return IE{}, fmt.Errorf("%w: outer header requires IPv4", ErrMalformedIE)
		}
		length += 4
	} else {
		if !header.IPv6.Is6() {
			return IE{}, fmt.Errorf("%w: outer header requires IPv6", ErrMalformedIE)
		}
		length += 16
	}
	value := make([]byte, length)
	binary.BigEndian.PutUint16(value[0:2], header.Description)
	binary.BigEndian.PutUint32(value[2:6], header.TEID)
	if header.Description == OuterHeaderGTPUUDPIPv4 {
		raw := header.IPv4.As4()
		copy(value[6:10], raw[:])
	} else {
		raw := header.IPv6.As16()
		copy(value[6:22], raw[:])
	}
	return IE{Type: IEOuterHeaderCreation, Value: value}, nil
}

func (ie IE) OuterHeaderCreation() (OuterHeader, error) {
	if ie.Type != IEOuterHeaderCreation || len(ie.Value) < 6 {
		return OuterHeader{}, fmt.Errorf("%w: invalid Outer Header Creation IE", ErrMalformedIE)
	}
	out := OuterHeader{Description: binary.BigEndian.Uint16(ie.Value[:2]), TEID: binary.BigEndian.Uint32(ie.Value[2:6])}
	switch out.Description {
	case OuterHeaderGTPUUDPIPv4:
		if len(ie.Value) < 10 {
			return OuterHeader{}, fmt.Errorf("%w: truncated IPv4 outer header", ErrMalformedIE)
		}
		var raw [4]byte
		copy(raw[:], ie.Value[6:10])
		out.IPv4 = netip.AddrFrom4(raw)
	case OuterHeaderGTPUUDPIPv6:
		if len(ie.Value) < 22 {
			return OuterHeader{}, fmt.Errorf("%w: truncated IPv6 outer header", ErrMalformedIE)
		}
		var raw [16]byte
		copy(raw[:], ie.Value[6:22])
		out.IPv6 = netip.AddrFrom16(raw)
	default:
		return OuterHeader{}, fmt.Errorf("%w: unsupported outer-header description 0x%x", ErrMalformedIE, out.Description)
	}
	if out.TEID == 0 {
		return OuterHeader{}, fmt.Errorf("%w: zero outer-header TEID", ErrMalformedIE)
	}
	return out, nil
}

func NewOuterHeaderRemovalIE(description uint8) (IE, error) {
	if description != OuterHeaderRemovalGTPUUDPIPv4 && description != OuterHeaderRemovalGTPUUDPIPv6 && description != OuterHeaderRemovalGTPUUDPIP {
		return IE{}, fmt.Errorf("%w: unsupported outer-header removal %d", ErrMalformedIE, description)
	}
	return IE{Type: IEOuterHeaderRemoval, Value: []byte{description}}, nil
}

func (ie IE) OuterHeaderRemoval() (uint8, error) {
	if ie.Type != IEOuterHeaderRemoval || len(ie.Value) < 1 {
		return 0, fmt.Errorf("%w: invalid Outer Header Removal IE", ErrMalformedIE)
	}
	if _, err := NewOuterHeaderRemovalIE(ie.Value[0]); err != nil {
		return 0, err
	}
	return ie.Value[0], nil
}

func NewGateStatusIE(uplinkOpen, downlinkOpen bool) IE {
	value := byte(0)
	if !downlinkOpen {
		value |= 0x01
	}
	if !uplinkOpen {
		value |= 0x04
	}
	return IE{Type: IEGateStatus, Value: []byte{value}}
}

func (ie IE) GateStatus() (uplinkOpen, downlinkOpen bool, err error) {
	if ie.Type != IEGateStatus || len(ie.Value) < 1 {
		return false, false, fmt.Errorf("%w: invalid Gate Status IE", ErrMalformedIE)
	}
	dl := ie.Value[0] & 0x03
	ul := (ie.Value[0] >> 2) & 0x03
	return ul == 0, dl == 0, nil
}

func NewBitRateIE(typ uint16, uplinkKbps, downlinkKbps uint64) (IE, error) {
	if typ != IEMBR && typ != IEGBR || uplinkKbps > 0xff_ffff_ffff || downlinkKbps > 0xff_ffff_ffff {
		return IE{}, fmt.Errorf("%w: invalid PFCP bitrate", ErrMalformedIE)
	}
	value := make([]byte, 10)
	putUint40(value[:5], uplinkKbps)
	putUint40(value[5:], downlinkKbps)
	return IE{Type: typ, Value: value}, nil
}

func (ie IE) BitRate() (uplinkKbps, downlinkKbps uint64, err error) {
	if (ie.Type != IEMBR && ie.Type != IEGBR) || len(ie.Value) < 10 {
		return 0, 0, fmt.Errorf("%w: invalid bitrate IE", ErrMalformedIE)
	}
	return readUint40(ie.Value[:5]), readUint40(ie.Value[5:10]), nil
}

func putUint40(dst []byte, value uint64) {
	dst[0] = byte(value >> 32)
	binary.BigEndian.PutUint32(dst[1:5], uint32(value))
}

func readUint40(src []byte) uint64 {
	return uint64(src[0])<<32 | uint64(binary.BigEndian.Uint32(src[1:5]))
}

func encodeLabels(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" || len(name) > 253 {
		return nil, fmt.Errorf("%w: invalid domain name", ErrMalformedIE)
	}
	out := make([]byte, 0, len(name)+1)
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("%w: invalid domain label", ErrMalformedIE)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return out, nil
}

func decodeLabels(value []byte) (string, error) {
	labels := make([]string, 0, 4)
	for offset := 0; offset < len(value); {
		length := int(value[offset])
		offset++
		if length == 0 || length > 63 || length > len(value)-offset {
			return "", fmt.Errorf("%w: malformed domain label", ErrMalformedIE)
		}
		labels = append(labels, strings.ToLower(string(value[offset:offset+length])))
		offset += length
	}
	if len(labels) == 0 {
		return "", fmt.Errorf("%w: empty domain name", ErrMalformedIE)
	}
	return strings.Join(labels, "."), nil
}
