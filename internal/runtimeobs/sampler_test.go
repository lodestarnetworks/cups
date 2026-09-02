package runtimeobs

import (
	"runtime/metrics"
	"testing"
)

func TestPopulatePausesProducesCumulativeBucketsAndTailStatistics(t *testing.T) {
	snapshot := Snapshot{}
	populatePauses(&snapshot, &metrics.Float64Histogram{
		Counts: []uint64{0, 98, 1, 1}, Buckets: []float64{0, 0.001, 0.002, 0.005, 0.010},
	})
	if snapshot.GCPauseCount != 100 || snapshot.GCPauseP99Seconds != 0.005 || snapshot.GCPauseMaxSeconds != 0.010 ||
		len(snapshot.GCPauseBuckets) != 4 || snapshot.GCPauseBuckets[3].Count != 100 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestSamplerReadsRuntime(t *testing.T) {
	sampler := NewSampler()
	current := sampler.Snapshot()
	if current.Goroutines == 0 || current.HeapObjectsBytes == 0 {
		t.Fatalf("runtime snapshot = %#v", current)
	}
}
