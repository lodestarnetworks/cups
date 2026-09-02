package usagereport

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestEmitterSendsOrderedIntervalDeltasAndRetries(t *testing.T) {
	var mu sync.Mutex
	measurement := Measurement{UPSEID: 10, URRID: 1, UplinkPackets: 1, UplinkBytes: 1000, ThresholdEvents: 1}
	sent := make(chan Report, 4)
	failures := 1
	emitter, err := NewEmitter(EmitterConfig{
		PollInterval: 10 * time.Millisecond, ReportTimeout: time.Second,
		RetryBase: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond,
		QueueSize: 4, Workers: 1,
		Snapshot: func() []Measurement {
			mu.Lock()
			defer mu.Unlock()
			return []Measurement{measurement}
		},
		ResolveCPSEID: func(uint64) (uint64, bool) { return 20, true },
		Send: func(_ context.Context, _ uint64, report Report) error {
			mu.Lock()
			defer mu.Unlock()
			if failures > 0 {
				failures--
				return errors.New("temporary failure")
			}
			sent <- report
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { emitter.Run(ctx); close(done) }()
	first := awaitReport(t, sent)
	if first.Sequence != 0 || first.UplinkBytes != 1000 || first.DownlinkBytes != 0 {
		t.Fatalf("first report = %#v", first)
	}
	mu.Lock()
	measurement.UplinkPackets = 3
	measurement.DownlinkPackets = 4
	measurement.UplinkBytes = 3000
	measurement.DownlinkBytes = 4000
	measurement.ThresholdEvents = 2
	mu.Unlock()
	second := awaitReport(t, sent)
	if second.Sequence != 1 || second.UplinkBytes != 2000 || second.DownlinkBytes != 4000 ||
		second.UplinkPackets != 2 || second.DownlinkPackets != 4 {
		t.Fatalf("second report = %#v", second)
	}
	cancel()
	<-done
	stats := emitter.Stats()
	if stats.ReportsGenerated != 2 || stats.ReportsSent != 2 || stats.ReportsRetried != 1 || stats.ReportsFailed != 1 || stats.PendingReports != 0 {
		t.Fatalf("stats = %#v", stats)
	}
}

func awaitReport(t *testing.T, reports <-chan Report) Report {
	t.Helper()
	select {
	case report := <-reports:
		return report
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for PFCP usage report")
		return Report{}
	}
}
