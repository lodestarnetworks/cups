package main

import (
	"net/netip"
	"testing"

	"github.com/lodestarnetworks/cups/internal/config"
	"github.com/lodestarnetworks/cups/internal/pgwapi"
	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
)

func TestPGWUAPNSessionTrackerSeparatesPoolsWithoutScrapeScan(t *testing.T) {
	tracker, err := newPGWUAPNSessionTracker(config.PGWU{UEPools: []config.PGWUUEPool{
		{APN: "internet", UEPoolPrefix: "10.45.0.0/16"},
		{APN: "ims", UEPoolPrefix: "10.46.0.0/16"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	tracker.ReconcileSession(rules.Session{UPSEID: 1, UEIPv4: netip.MustParseAddr("10.45.0.20")})
	tracker.ReconcileSession(rules.Session{UPSEID: 2, UEIPv4: netip.MustParseAddr("10.46.0.30")})
	tracker.ReconcileSession(rules.Session{UPSEID: 3, UEIPv4: netip.MustParseAddr("10.45.0.21")})
	tracker.ReconcileSession(rules.Session{UPSEID: 3, UEIPv4: netip.MustParseAddr("10.45.0.21")})

	metrics, total, unmatched := tracker.Metrics()
	assertPGWUMetric(t, metrics, "internet", 2)
	assertPGWUMetric(t, metrics, "ims", 1)
	if total != 3 || unmatched != 0 {
		t.Fatalf("tracker totals = %d/%d, want 3/0", total, unmatched)
	}

	tracker.ReconcileSession(rules.Session{UPSEID: 3, UEIPv4: netip.MustParseAddr("10.46.0.31")})
	tracker.DeleteSession(1)
	metrics, total, unmatched = tracker.Metrics()
	assertPGWUMetric(t, metrics, "internet", 0)
	assertPGWUMetric(t, metrics, "ims", 2)
	if total != 2 || unmatched != 0 {
		t.Fatalf("updated tracker totals = %d/%d, want 2/0", total, unmatched)
	}
}

func TestPGWUAPNSessionTrackerFlagsOutOfPoolAndNeverEmitsEmptyAPN(t *testing.T) {
	tracker, err := newPGWUAPNSessionTracker(config.PGWU{UEPools: []config.PGWUUEPool{
		{APN: "internet", UEPoolPrefix: "10.45.0.0/16"},
		{APN: "ims", UEPoolPrefix: "10.46.0.0/16"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	tracker.ReconcileSession(rules.Session{UPSEID: 7, UEIPv4: netip.MustParseAddr("10.99.0.1")})
	metrics, total, unmatched := tracker.Metrics()
	if total != 1 || unmatched != 1 {
		t.Fatalf("unmatched tracker totals = %d/%d, want 1/1", total, unmatched)
	}
	for _, metric := range metrics {
		if metric.Labels["apn"] == "" {
			t.Fatal("PGW-U metric emitted an empty APN label")
		}
	}
}

func TestPGWUAPNSessionTrackerSupportsSingleUserspaceAPN(t *testing.T) {
	tracker, err := newPGWUAPNSessionTracker(config.PGWU{APN: "lodestartest"})
	if err != nil {
		t.Fatal(err)
	}
	tracker.ReconcileSession(rules.Session{UPSEID: 1, UEIPv4: netip.MustParseAddr("192.0.2.1")})
	metrics, total, unmatched := tracker.Metrics()
	assertPGWUMetric(t, metrics, "lodestartest", 1)
	if total != 1 || unmatched != 0 {
		t.Fatalf("single-APN tracker totals = %d/%d, want 1/0", total, unmatched)
	}
}

func assertPGWUMetric(t *testing.T, metrics []pgwapi.Metric, apn string, want float64) {
	t.Helper()
	for _, metric := range metrics {
		if metric.Name == "pfcp_sessions_active" && metric.Labels["apn"] == apn {
			if metric.Value != want {
				t.Fatalf("PGW-U sessions{%s} = %v, want %v", apn, metric.Value, want)
			}
			return
		}
	}
	t.Fatalf("PGW-U sessions{%s} not found: %#v", apn, metrics)
}
