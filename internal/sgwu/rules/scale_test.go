package rules

import (
	"context"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/internal/runtimeobs"
)

// TestOneMillionSGWUSessions is the opt-in SGW-U half of T0.4. It models two
// packet rules, one QER, and one URR per LTE default bearer. Run it separately
// from the PGW-U scale test so both million-session stores do not compete for
// memory and distort the GC result.
func TestOneMillionSGWUSessions(t *testing.T) {
	if os.Getenv("LODESTAR_T04_SGWU") != "1" {
		t.Skip("set LODESTAR_T04_SGWU=1 for the ten-minute SGW-U T0.4 run")
	}
	phaseDuration := 5 * time.Minute
	if raw := os.Getenv("LODESTAR_T04_PHASE_DURATION"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			t.Fatalf("invalid LODESTAR_T04_PHASE_DURATION %q", raw)
		}
		phaseDuration = parsed
	}
	workers := runtime.GOMAXPROCS(0)
	if raw := os.Getenv("LODESTAR_T04_WORKERS"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			t.Fatalf("invalid LODESTAR_T04_WORKERS %q", raw)
		}
		workers = parsed
	}
	gcInterval := 10 * time.Second
	if raw := os.Getenv("LODESTAR_T04_GC_INTERVAL"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			t.Fatalf("invalid LODESTAR_T04_GC_INTERVAL %q", raw)
		}
		gcInterval = parsed
	}

	const sessionCount = 1_000_000
	store := NewStoreWithLimit(sessionCount)
	s1Local := netip.MustParseAddr("10.200.0.10")
	s5Local := netip.MustParseAddr("10.200.0.20")
	enodeb := netip.MustParseAddr("10.200.1.10")
	pgwu := netip.MustParseAddr("10.200.2.10")
	started := time.Now()
	for index := 0; index < sessionCount; index++ {
		value := uint32(index + 1)
		toCore := FTEID{TEID: value + 2*sessionCount, IP: pgwu}
		toAccess := FTEID{TEID: value + 3*sessionCount, IP: enodeb}
		if _, err := store.Create(Session{
			CPSEID: uint64(value), UPSEID: uint64(value),
			PDRs: map[uint16]PDR{
				1: {ID: 1, SourceInterface: SourceAccess, LocalFTEID: FTEID{TEID: value, IP: s1Local}, FARID: 1, QERIDs: []uint32{1}, URRIDs: []uint32{1}},
				2: {ID: 2, SourceInterface: SourceCore, LocalFTEID: FTEID{TEID: value + sessionCount, IP: s5Local}, FARID: 2, QERIDs: []uint32{1}, URRIDs: []uint32{1}},
			},
			FARs: map[uint32]FAR{
				1: {ID: 1, ApplyAction: ActionForward, DestinationInterface: DestinationCore, OuterHeader: &toCore},
				2: {ID: 2, ApplyAction: ActionForward, DestinationInterface: DestinationAccess, OuterHeader: &toAccess},
			},
			QERs: map[uint32]QER{1: {ID: 1, UplinkGateOpen: true, DownlinkGateOpen: true}},
			URRs: map[uint32]URR{1: {ID: 1, MeasureVolume: true, MeasureDuration: true}},
		}); err != nil {
			t.Fatalf("create session %d: %v", index, err)
		}
	}
	runtime.GC()
	sampler := runtimeobs.NewSampler()
	baseline := sampler.Snapshot()
	t.Logf("installed=%d setup=%s heap_objects_bytes=%d goroutines=%d", store.LifecycleCounters().Installed, time.Since(started), baseline.HeapObjectsBytes, baseline.Goroutines)

	idleCtx, idleCancel := context.WithTimeout(context.Background(), phaseDuration)
	forceSGWUGC(idleCtx, gcInterval)
	idleCancel()
	sampler.Sample()
	idle := sampler.Snapshot()
	logSGWUGCDelta(t, "idle", baseline, idle)

	loadStart := idle
	ctx, cancel := context.WithTimeout(context.Background(), phaseDuration)
	gcDone := make(chan struct{})
	go func() {
		forceSGWUGC(ctx, gcInterval)
		close(gcDone)
	}()
	operations := make([]uint64, workers)
	var lookupFailures atomic.Uint64
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		group.Add(1)
		go func() {
			defer group.Done()
			value := uint32(worker + 1)
			var completed uint64
			for ctx.Err() == nil {
				value = value*1664525 + 1013904223
				teid := value%sessionCount + 1
				if _, ok := store.LookupPacket(SourceAccess, teid); !ok {
					lookupFailures.Add(1)
				}
				completed++
			}
			operations[worker] = completed
		}()
	}
	group.Wait()
	<-gcDone
	cancel()
	if failures := lookupFailures.Load(); failures != 0 {
		t.Fatalf("lookup failures=%d", failures)
	}
	var operationCount uint64
	for _, completed := range operations {
		operationCount += completed
	}
	sampler.Sample()
	loaded := sampler.Snapshot()
	logSGWUGCDelta(t, "synthetic-load", loadStart, loaded)
	t.Logf("load_workers=%d lookup_operations=%d lookup_ops_per_second=%.0f heap_objects_bytes=%d goroutines=%d",
		workers, operationCount, float64(operationCount)/phaseDuration.Seconds(), loaded.HeapObjectsBytes, loaded.Goroutines)
	runtime.KeepAlive(store)
}

func forceSGWUGC(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			runtime.GC()
		case <-ctx.Done():
			return
		}
	}
}

func logSGWUGCDelta(t *testing.T, phase string, before, after runtimeobs.Snapshot) {
	t.Helper()
	counts := make([]uint64, len(after.GCPauseBuckets))
	for index := range counts {
		prior := uint64(0)
		if index < len(before.GCPauseBuckets) {
			prior = before.GCPauseBuckets[index].Count
		}
		if after.GCPauseBuckets[index].Count >= prior {
			counts[index] = after.GCPauseBuckets[index].Count - prior
		}
	}
	count := after.GCPauseCount - before.GCPauseCount
	t.Logf("phase=%s gc_pauses=%d gc_p50_ms=%.6f gc_p99_ms=%.6f gc_max_ms=%.6f heap_objects_bytes=%d",
		phase, count, sgwPauseQuantile(after.GCPauseBuckets, counts, count, 0.50)*1_000,
		sgwPauseQuantile(after.GCPauseBuckets, counts, count, 0.99)*1_000,
		sgwPauseQuantile(after.GCPauseBuckets, counts, count, 1.00)*1_000, after.HeapObjectsBytes)
}

func sgwPauseQuantile(buckets []runtimeobs.Bucket, cumulativeDelta []uint64, count uint64, quantile float64) float64 {
	if count == 0 || len(buckets) == 0 {
		return 0
	}
	target := uint64(float64(count)*quantile + 0.999999)
	for index, cumulative := range cumulativeDelta {
		if cumulative >= target {
			return buckets[index].UpperBoundSeconds
		}
	}
	return buckets[len(buckets)-1].UpperBoundSeconds
}
