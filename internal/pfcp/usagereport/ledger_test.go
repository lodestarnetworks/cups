package usagereport

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestLedgerSequenceAndDuplicateHandling(t *testing.T) {
	ledger, err := OpenLedger(LedgerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	epoch := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	first := testReport(0)
	result, err := ledger.Accept(epoch, []Report{first})
	if err != nil || result.Accepted != 1 {
		t.Fatalf("first accept = %#v, %v", result, err)
	}
	result, err = ledger.Accept(epoch, []Report{first})
	if err != nil || result.Duplicate != 1 {
		t.Fatalf("duplicate = %#v, %v", result, err)
	}
	conflict := first
	conflict.UplinkBytes++
	if _, err := ledger.Accept(epoch, []Report{conflict}); !errors.Is(err, ErrSequenceConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	if _, err := ledger.Accept(epoch, []Report{testReport(2)}); !errors.Is(err, ErrSequenceGap) {
		t.Fatalf("gap error = %v", err)
	}
	if _, err := ledger.Accept(epoch, []Report{testReport(1)}); err != nil {
		t.Fatal(err)
	}
	stats := ledger.Stats()
	if stats.ReportsAccepted != 2 || stats.ReportsDuplicate != 1 || stats.SequenceGaps != 1 || stats.SequenceConflicts != 1 ||
		stats.UplinkBytes != 2000 || stats.DownlinkBytes != 4000 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestLedgerDurableReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.state")
	config := LedgerConfig{Path: path, Identity: []byte("pgw-c-test"), MaxBytes: 1 << 20}
	epoch := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	ledger, err := OpenLedger(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Accept(epoch, []Report{testReport(0)}); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	recovered, err := OpenLedger(config)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if stats := recovered.Stats(); !stats.Durable || stats.ReportsAccepted != 1 || stats.ActiveCheckpoints != 1 {
		t.Fatalf("recovered stats = %#v", stats)
	}
	if result, err := recovered.Accept(epoch, []Report{testReport(0)}); err != nil || result.Duplicate != 1 {
		t.Fatalf("recovered duplicate = %#v, %v", result, err)
	}
	if _, err := recovered.Accept(epoch, []Report{testReport(1)}); err != nil {
		t.Fatal(err)
	}
	if err := recovered.RemoveSession(testReport(0).CPSEID); err != nil {
		t.Fatal(err)
	}
	if stats := recovered.Stats(); stats.ReportsAccepted != 2 || stats.ActiveCheckpoints != 0 {
		t.Fatalf("post-delete stats = %#v", stats)
	}
}

func testReport(sequence uint32) Report {
	start := time.Date(2026, 8, 31, 9, int(sequence), 0, 0, time.UTC)
	return Report{
		CPSEID: 99, URRID: 1, Sequence: sequence, Trigger: 1 << 1,
		UplinkPackets: 10, DownlinkPackets: 20, UplinkBytes: 1000, DownlinkBytes: 2000,
		StartTime: start, EndTime: start.Add(time.Minute),
		FirstPacket: start.Add(time.Second), LastPacket: start.Add(59 * time.Second),
	}
}
