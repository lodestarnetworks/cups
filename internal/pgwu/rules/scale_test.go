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

// TestOneMillionSessions is the opt-in T0.4 GC-pressure run. Keeping it behind
// an environment flag prevents an ordinary unit-test invocation from becoming
// a ten-minute, multi-gigabyte host benchmark.
func TestOneMillionSessions(t *testing.T) {
	if os.Getenv("LODESTAR_T04") != "1" {
		t.Skip("set LODESTAR_T04=1 for the ten-minute T0.4 GC-pressure run")
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
	local := netip.MustParseAddr("10.200.0.20")
	remote := netip.MustParseAddr("10.200.0.10")
	started := time.Now()
	for index := 0; index < sessionCount; index++ {
		value := uint32(index + 1)
		ue := netip.AddrFrom4([4]byte{10, byte(value >> 16), byte(value >> 8), byte(value)})
		if _, err := store.Create(Session{
			CPSEID: uint64(value), UPSEID: uint64(value), UEIPv4: ue,
			Local: Tunnel{TEID: value, IP: local}, Remote: Tunnel{TEID: value + sessionCount, IP: remote},
			UplinkGateOpen: true, DownlinkGateOpen: true,
		}); err != nil {
			t.Fatalf("create session %d: %v", index, err)
		}
	}
	runtime.GC()
	sampler := runtimeobs.NewSampler()
	baseline := sampler.Snapshot()
	t.Logf("installed=%d setup=%s heap_objects_bytes=%d goroutines=%d", store.Count(), time.Since(started), baseline.HeapObjectsBytes, baseline.Goroutines)

	idleCtx, idleCancel := context.WithTimeout(context.Background(), phaseDuration)
	forceGC(idleCtx, gcInterval)
	idleCancel()
	sampler.Sample()
	idle := sampler.Snapshot()
	logGCDelta(t, "idle", baseline, idle)

	loadStart := idle
	ctx, cancel := context.WithTimeout(context.Background(), phaseDuration)
	gcDone := make(chan struct{})
	go func() {
		forceGC(ctx, gcInterval)
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
				if _, ok := store.LookupUplink(teid); !ok {
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
	logGCDelta(t, "synthetic-load", loadStart, loaded)
	t.Logf("load_workers=%d lookup_operations=%d lookup_ops_per_second=%.0f heap_objects_bytes=%d goroutines=%d",
		workers, operationCount, float64(operationCount)/phaseDuration.Seconds(), loaded.HeapObjectsBytes, loaded.Goroutines)
	runtime.KeepAlive(store)
}

func forceGC(ctx context.Context, interval time.Duration) {
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

func logGCDelta(t *testing.T, phase string, before, after runtimeobs.Snapshot) {
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
		phase, count, pauseQuantile(after.GCPauseBuckets, counts, count, 0.50)*1_000,
		pauseQuantile(after.GCPauseBuckets, counts, count, 0.99)*1_000,
		pauseQuantile(after.GCPauseBuckets, counts, count, 1.00)*1_000, after.HeapObjectsBytes)
}

func pauseQuantile(buckets []runtimeobs.Bucket, cumulativeDelta []uint64, count uint64, quantile float64) float64 {
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
