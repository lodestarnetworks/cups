// Package runtimeobs samples the Go runtime metrics needed to diagnose user-
// plane GC and scheduler behaviour without adding work to the packet path.
package runtimeobs

import (
	"context"
	"math"
	"runtime/metrics"
	"sync/atomic"
	"time"
)

const (
	heapObjectsMetric = "/memory/classes/heap/objects:bytes"
	goroutinesMetric  = "/sched/goroutines:goroutines"
)

var gcPauseMetricCandidates = [...]string{
	"/sched/pauses/total/gc:seconds",
	"/gc/pauses:seconds",
}

type Bucket struct {
	UpperBoundSeconds float64
	Count             uint64
}

type Snapshot struct {
	HeapObjectsBytes  uint64
	Goroutines        uint64
	GCPauseCount      uint64
	GCPauseP99Seconds float64
	GCPauseMaxSeconds float64
	GCPauseBuckets    []Bucket
}

type Sampler struct {
	samples []metrics.Sample
	value   atomic.Pointer[Snapshot]
}

func NewSampler() *Sampler {
	available := make(map[string]struct{})
	for _, description := range metrics.All() {
		available[description.Name] = struct{}{}
	}
	gcPauseMetric := ""
	for _, candidate := range gcPauseMetricCandidates {
		if _, ok := available[candidate]; ok {
			gcPauseMetric = candidate
			break
		}
	}
	names := []string{heapObjectsMetric, goroutinesMetric}
	if gcPauseMetric != "" {
		names = append(names, gcPauseMetric)
	}
	samples := make([]metrics.Sample, 0, len(names))
	for _, name := range names {
		if _, ok := available[name]; ok {
			samples = append(samples, metrics.Sample{Name: name})
		}
	}
	sampler := &Sampler{samples: samples}
	sampler.Sample()
	return sampler
}

func (s *Sampler) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.Sample()
		case <-ctx.Done():
			return
		}
	}
}

func (s *Sampler) Sample() {
	metrics.Read(s.samples)
	next := &Snapshot{}
	for index := range s.samples {
		sample := &s.samples[index]
		switch sample.Name {
		case heapObjectsMetric:
			if sample.Value.Kind() == metrics.KindUint64 {
				next.HeapObjectsBytes = sample.Value.Uint64()
			}
		case goroutinesMetric:
			if sample.Value.Kind() == metrics.KindUint64 {
				next.Goroutines = sample.Value.Uint64()
			}
		default:
			if sample.Value.Kind() == metrics.KindFloat64Histogram {
				populatePauses(next, sample.Value.Float64Histogram())
			}
		}
	}
	s.value.Store(next)
}

func (s *Sampler) Snapshot() Snapshot {
	current := s.value.Load()
	if current == nil {
		return Snapshot{}
	}
	out := *current
	out.GCPauseBuckets = append([]Bucket(nil), current.GCPauseBuckets...)
	return out
}

func populatePauses(out *Snapshot, histogram *metrics.Float64Histogram) {
	if histogram == nil || len(histogram.Counts) == 0 || len(histogram.Buckets) != len(histogram.Counts)+1 {
		return
	}
	out.GCPauseBuckets = make([]Bucket, 0, len(histogram.Counts))
	var total uint64
	for _, count := range histogram.Counts {
		total += count
	}
	out.GCPauseCount = total
	target := (total*99 + 99) / 100
	var cumulative uint64
	for index, count := range histogram.Counts {
		cumulative += count
		upper := finiteUpperBound(histogram.Buckets, index)
		out.GCPauseBuckets = append(out.GCPauseBuckets, Bucket{UpperBoundSeconds: upper, Count: cumulative})
		if total != 0 && out.GCPauseP99Seconds == 0 && cumulative >= target {
			out.GCPauseP99Seconds = upper
		}
		if count != 0 {
			out.GCPauseMaxSeconds = upper
		}
	}
}

func finiteUpperBound(bounds []float64, countIndex int) float64 {
	upper := bounds[countIndex+1]
	if !math.IsInf(upper, 1) {
		return upper
	}
	lower := bounds[countIndex]
	if math.IsInf(lower, -1) {
		return 0
	}
	return lower
}
