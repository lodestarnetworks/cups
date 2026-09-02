package usagereport

import (
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/pkg/pfcp"
)

func TestReportRoundTrip(t *testing.T) {
	start := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	want := Report{
		CPSEID: 55, URRID: 7, Sequence: 9, Trigger: pfcp.UsageReportTriggerVolumeThreshold,
		UplinkPackets: 10, DownlinkPackets: 20, UplinkBytes: 1000, DownlinkBytes: 2000,
		StartTime: start, EndTime: start.Add(10 * time.Second),
		FirstPacket: start.Add(time.Second), LastPacket: start.Add(9 * time.Second),
	}
	encoded, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(want.CPSEID, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("report = %#v, want %#v", got, want)
	}
}

func TestReportRejectsInconsistentVolume(t *testing.T) {
	start := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	urr, _ := pfcp.NewUint32IE(pfcp.IEURRID, 1)
	trigger, _ := pfcp.NewUsageReportTriggerIE(pfcp.UsageReportTriggerVolumeThreshold)
	startIE, _ := pfcp.NewUsageTimeIE(pfcp.IEStartTime, start)
	endIE, _ := pfcp.NewUsageTimeIE(pfcp.IEEndTime, start.Add(time.Second))
	volume, _ := pfcp.NewVolumeMeasurementIE(pfcp.VolumeMeasurement{
		HasTotalBytes: true, HasUplinkBytes: true, HasDownlinkBytes: true,
		HasTotalPackets: true, HasUplinkPackets: true, HasDownlinkPackets: true,
		TotalBytes: 999, UplinkBytes: 100, DownlinkBytes: 200,
		TotalPackets: 3, UplinkPackets: 1, DownlinkPackets: 2,
	})
	grouped, _ := pfcp.NewGroupedIE(pfcp.IEUsageReportSessionReport,
		urr, pfcp.NewURSEQNIE(0), trigger, startIE, endIE, volume,
	)
	if _, err := Decode(1, grouped); err == nil {
		t.Fatal("accepted inconsistent volume totals")
	}
}
