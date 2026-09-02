package gateway

import (
	"net/netip"
	"testing"
	"time"
)

func TestPagingTrackerRetainsEarliestDDNAndBuildsCumulativeHistogram(t *testing.T) {
	tracker := newPagingTracker()
	started := time.Unix(1_700_000_000, 0)
	if !tracker.start(41, 5, 9, started) {
		t.Fatal("first DDN was not tracked")
	}
	if tracker.start(41, 5, 9, started.Add(20*time.Millisecond)) {
		t.Fatal("duplicate DDN replaced the original paging request")
	}
	if !tracker.observe(41, 5, netip.MustParseAddr("192.0.2.10"), started.Add(40*time.Millisecond)) {
		t.Fatal("Modify Bearer did not complete the pending paging request")
	}
	if tracker.observe(41, 5, netip.MustParseAddr("192.0.2.10"), started.Add(time.Second)) {
		t.Fatal("one paging request was observed twice")
	}

	histograms, pending := tracker.snapshot(started.Add(time.Second))
	if pending != 0 || len(histograms) != 1 {
		t.Fatalf("snapshot: pending=%d histograms=%#v", pending, histograms)
	}
	histogram := histograms[0]
	if histogram.QCI != 9 || histogram.ENB != "192.0.2.10" || histogram.Count != 1 || histogram.SumSeconds != 0.04 {
		t.Fatalf("unexpected histogram: %#v", histogram)
	}
	for _, bucket := range histogram.Buckets {
		want := uint64(0)
		if bucket.UpperBoundSeconds >= 0.05 {
			want = 1
		}
		if bucket.Count != want {
			t.Fatalf("bucket le=%g count=%d, want %d", bucket.UpperBoundSeconds, bucket.Count, want)
		}
	}
}

func TestPagingTrackerCancelPurgeAndStaleExpiry(t *testing.T) {
	tracker := newPagingTracker()
	started := time.Unix(1_700_000_000, 0)
	tracker.start(1, 5, 5, started)
	tracker.start(1, 6, 1, started)
	tracker.start(2, 5, 9, started)
	tracker.cancel(1, 5)
	tracker.purgeSession(2)

	_, pending := tracker.snapshot(started.Add(time.Second))
	if pending != 1 {
		t.Fatalf("pending=%d, want 1", pending)
	}
	_, pending = tracker.snapshot(started.Add(pendingPagingLifetime + time.Second))
	if pending != 0 {
		t.Fatalf("stale pending=%d, want 0", pending)
	}
}
