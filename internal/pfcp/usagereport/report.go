// Package usagereport implements the telemetry-only PFCP Usage Report profile
// shared by Lodestar's Sxa and Sxb interfaces.
package usagereport

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/lodestarnetworks/cups/pkg/pfcp"
)

// Report is one interval of counters for a session-scoped URR. It has no
// quota, balance, or forwarding semantics.
type Report struct {
	CPSEID          uint64
	URRID           uint32
	Sequence        uint32
	Trigger         uint32
	UplinkPackets   uint64
	DownlinkPackets uint64
	UplinkBytes     uint64
	DownlinkBytes   uint64
	StartTime       time.Time
	EndTime         time.Time
	FirstPacket     time.Time
	LastPacket      time.Time
}

func (r Report) TotalPackets() uint64 { return saturatingAdd(r.UplinkPackets, r.DownlinkPackets) }
func (r Report) TotalBytes() uint64   { return saturatingAdd(r.UplinkBytes, r.DownlinkBytes) }

func (r Report) Validate() error {
	if r.CPSEID == 0 || r.URRID == 0 {
		return errors.New("PFCP usage report requires CP-SEID and URR ID")
	}
	if _, err := pfcp.NewUsageReportTriggerIE(r.Trigger); err != nil {
		return err
	}
	if r.Trigger&pfcp.UsageReportTriggerVolumeThreshold != 0 && r.TotalBytes() == 0 {
		return errors.New("volume-threshold report contains no measured bytes")
	}
	if r.StartTime.IsZero() || r.EndTime.IsZero() || r.EndTime.Before(r.StartTime) {
		return errors.New("PFCP usage report has an invalid collection interval")
	}
	if !r.FirstPacket.IsZero() && (r.FirstPacket.Before(r.StartTime) || r.FirstPacket.After(r.EndTime)) {
		return errors.New("PFCP usage report first-packet time is outside its interval")
	}
	if !r.LastPacket.IsZero() && (r.LastPacket.Before(r.StartTime) || r.LastPacket.After(r.EndTime)) {
		return errors.New("PFCP usage report last-packet time is outside its interval")
	}
	if !r.FirstPacket.IsZero() && !r.LastPacket.IsZero() && r.LastPacket.Before(r.FirstPacket) {
		return errors.New("PFCP usage report packet timestamps are reversed")
	}
	return nil
}

func Encode(r Report) (pfcp.IE, error) {
	if err := r.Validate(); err != nil {
		return pfcp.IE{}, err
	}
	urrID, _ := pfcp.NewUint32IE(pfcp.IEURRID, r.URRID)
	trigger, _ := pfcp.NewUsageReportTriggerIE(r.Trigger)
	volume, err := pfcp.NewVolumeMeasurementIE(pfcp.VolumeMeasurement{
		HasTotalBytes: true, HasUplinkBytes: true, HasDownlinkBytes: true,
		HasTotalPackets: true, HasUplinkPackets: true, HasDownlinkPackets: true,
		TotalBytes: r.TotalBytes(), UplinkBytes: r.UplinkBytes, DownlinkBytes: r.DownlinkBytes,
		TotalPackets: r.TotalPackets(), UplinkPackets: r.UplinkPackets, DownlinkPackets: r.DownlinkPackets,
	})
	if err != nil {
		return pfcp.IE{}, err
	}
	start, err := pfcp.NewUsageTimeIE(pfcp.IEStartTime, r.StartTime)
	if err != nil {
		return pfcp.IE{}, err
	}
	end, err := pfcp.NewUsageTimeIE(pfcp.IEEndTime, r.EndTime)
	if err != nil {
		return pfcp.IE{}, err
	}
	duration, err := pfcp.NewDurationMeasurementIE(r.EndTime.Sub(r.StartTime))
	if err != nil {
		return pfcp.IE{}, err
	}
	children := []pfcp.IE{urrID, pfcp.NewURSEQNIE(r.Sequence), trigger, start, end, volume, duration}
	if !r.FirstPacket.IsZero() {
		first, err := pfcp.NewUsageTimeIE(pfcp.IETimeOfFirstPacket, r.FirstPacket)
		if err != nil {
			return pfcp.IE{}, err
		}
		children = append(children, first)
	}
	if !r.LastPacket.IsZero() {
		last, err := pfcp.NewUsageTimeIE(pfcp.IETimeOfLastPacket, r.LastPacket)
		if err != nil {
			return pfcp.IE{}, err
		}
		children = append(children, last)
	}
	return pfcp.NewGroupedIE(pfcp.IEUsageReportSessionReport, children...)
}

func Decode(cpSEID uint64, grouped pfcp.IE) (Report, error) {
	if grouped.Type != pfcp.IEUsageReportSessionReport || cpSEID == 0 {
		return Report{}, errors.New("invalid PFCP Usage Report context")
	}
	children, err := grouped.Children()
	if err != nil {
		return Report{}, err
	}
	allowed := map[uint16]bool{
		pfcp.IEURRID: true, pfcp.IEURSEQN: true, pfcp.IEUsageReportTrigger: true,
		pfcp.IEStartTime: true, pfcp.IEEndTime: true, pfcp.IEVolumeMeasurement: true,
		pfcp.IEDurationMeasurement: true, pfcp.IETimeOfFirstPacket: true, pfcp.IETimeOfLastPacket: true,
	}
	seen := make(map[uint16]bool, len(children))
	for _, child := range children {
		if !allowed[child.Type] {
			return Report{}, fmt.Errorf("unsupported IE %d in PFCP Usage Report", child.Type)
		}
		if seen[child.Type] {
			return Report{}, fmt.Errorf("duplicate IE %d in PFCP Usage Report", child.Type)
		}
		seen[child.Type] = true
	}
	required := []uint16{pfcp.IEURRID, pfcp.IEURSEQN, pfcp.IEUsageReportTrigger, pfcp.IEStartTime, pfcp.IEEndTime, pfcp.IEVolumeMeasurement}
	for _, typ := range required {
		if !seen[typ] {
			return Report{}, pfcp.ErrMissingIE
		}
	}
	urrIE, _ := pfcp.FindIE(children, pfcp.IEURRID)
	sequenceIE, _ := pfcp.FindIE(children, pfcp.IEURSEQN)
	triggerIE, _ := pfcp.FindIE(children, pfcp.IEUsageReportTrigger)
	startIE, _ := pfcp.FindIE(children, pfcp.IEStartTime)
	endIE, _ := pfcp.FindIE(children, pfcp.IEEndTime)
	volumeIE, _ := pfcp.FindIE(children, pfcp.IEVolumeMeasurement)
	urrID, err := urrIE.Uint32()
	if err != nil || urrID == 0 {
		return Report{}, errors.New("invalid URR ID in PFCP Usage Report")
	}
	sequence, err := sequenceIE.URSEQN()
	if err != nil {
		return Report{}, err
	}
	trigger, err := triggerIE.UsageReportTrigger()
	if err != nil {
		return Report{}, err
	}
	start, err := startIE.UsageTime()
	if err != nil {
		return Report{}, err
	}
	end, err := endIE.UsageTime()
	if err != nil {
		return Report{}, err
	}
	volume, err := volumeIE.VolumeMeasurement()
	if err != nil {
		return Report{}, err
	}
	if !volume.HasTotalBytes || !volume.HasUplinkBytes || !volume.HasDownlinkBytes ||
		!volume.HasTotalPackets || !volume.HasUplinkPackets || !volume.HasDownlinkPackets ||
		volume.TotalBytes != saturatingAdd(volume.UplinkBytes, volume.DownlinkBytes) ||
		volume.TotalPackets != saturatingAdd(volume.UplinkPackets, volume.DownlinkPackets) {
		return Report{}, errors.New("inconsistent PFCP Volume Measurement totals")
	}
	report := Report{
		CPSEID: cpSEID, URRID: urrID, Sequence: sequence, Trigger: trigger,
		UplinkPackets: volume.UplinkPackets, DownlinkPackets: volume.DownlinkPackets,
		UplinkBytes: volume.UplinkBytes, DownlinkBytes: volume.DownlinkBytes,
		StartTime: start, EndTime: end,
	}
	if first, ok := pfcp.FindIE(children, pfcp.IETimeOfFirstPacket); ok {
		report.FirstPacket, err = first.UsageTime()
		if err != nil {
			return Report{}, err
		}
	}
	if last, ok := pfcp.FindIE(children, pfcp.IETimeOfLastPacket); ok {
		report.LastPacket, err = last.UsageTime()
		if err != nil {
			return Report{}, err
		}
	}
	if duration, ok := pfcp.FindIE(children, pfcp.IEDurationMeasurement); ok {
		measured, err := duration.DurationMeasurement()
		if err != nil {
			return Report{}, err
		}
		// PFCP duration has whole-second resolution.
		if measured != end.Sub(start).Truncate(time.Second) {
			return Report{}, errors.New("PFCP Duration Measurement does not match report interval")
		}
	}
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	return report, nil
}

func saturatingAdd(left, right uint64) uint64 {
	if right > math.MaxUint64-left {
		return math.MaxUint64
	}
	return left + right
}
