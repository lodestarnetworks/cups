package gateway

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

var pagingLatencyBounds = [...]time.Duration{
	5 * time.Millisecond,
	10 * time.Millisecond,
	25 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
	2500 * time.Millisecond,
	5 * time.Second,
	10 * time.Second,
	30 * time.Second,
}

const pendingPagingLifetime = 10 * time.Minute

// PagingLatencyBucket is one cumulative bucket in the DDN-to-successful-
// Modify-Bearer latency distribution.
type PagingLatencyBucket struct {
	UpperBoundSeconds float64
	Count             uint64
}

// PagingLatencyHistogram is a Prometheus-compatible cumulative histogram for
// one QCI and eNodeB address. Count also represents the +Inf bucket.
type PagingLatencyHistogram struct {
	QCI        uint8
	ENB        string
	Count      uint64
	SumSeconds float64
	Buckets    []PagingLatencyBucket
}

type pagingRequestKey struct {
	sessionID uint64
	ebi       uint8
}

type pendingPagingRequest struct {
	started time.Time
	qci     uint8
}

type pagingHistogramKey struct {
	qci uint8
	enb string
}

type pagingHistogramState struct {
	count   uint64
	sum     time.Duration
	buckets [len(pagingLatencyBounds)]uint64
}

type pagingTracker struct {
	mu         sync.Mutex
	pending    map[pagingRequestKey]pendingPagingRequest
	histograms map[pagingHistogramKey]*pagingHistogramState
}

func newPagingTracker() *pagingTracker {
	return &pagingTracker{
		pending:    make(map[pagingRequestKey]pendingPagingRequest),
		histograms: make(map[pagingHistogramKey]*pagingHistogramState),
	}
}

// start records the first DDN for a bearer and returns true only when this
// call owns that record. Keeping the earliest DDN prevents retransmissions or
// duplicate PFCP reports from understating paging latency.
func (t *pagingTracker) start(sessionID uint64, ebi, qci uint8, started time.Time) bool {
	key := pagingRequestKey{sessionID: sessionID, ebi: ebi}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.pending[key]; exists {
		return false
	}
	t.pending[key] = pendingPagingRequest{started: started, qci: qci}
	return true
}

func (t *pagingTracker) cancel(sessionID uint64, ebi uint8) {
	t.mu.Lock()
	delete(t.pending, pagingRequestKey{sessionID: sessionID, ebi: ebi})
	t.mu.Unlock()
}

func (t *pagingTracker) purgeSession(sessionID uint64) {
	t.mu.Lock()
	for key := range t.pending {
		if key.sessionID == sessionID {
			delete(t.pending, key)
		}
	}
	t.mu.Unlock()
}

func (t *pagingTracker) observe(sessionID uint64, ebi uint8, enb netip.Addr, finished time.Time) bool {
	key := pagingRequestKey{sessionID: sessionID, ebi: ebi}
	t.mu.Lock()
	defer t.mu.Unlock()
	pending, exists := t.pending[key]
	if !exists {
		return false
	}
	delete(t.pending, key)
	duration := finished.Sub(pending.started)
	if duration < 0 {
		duration = 0
	}
	histogramKey := pagingHistogramKey{qci: pending.qci, enb: enb.Unmap().String()}
	histogram := t.histograms[histogramKey]
	if histogram == nil {
		histogram = &pagingHistogramState{}
		t.histograms[histogramKey] = histogram
	}
	histogram.count++
	histogram.sum += duration
	for index, bound := range pagingLatencyBounds {
		if duration <= bound {
			histogram.buckets[index]++
		}
	}
	return true
}

func (t *pagingTracker) snapshot(now time.Time) ([]PagingLatencyHistogram, uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, pending := range t.pending {
		if now.Sub(pending.started) > pendingPagingLifetime {
			delete(t.pending, key)
		}
	}
	out := make([]PagingLatencyHistogram, 0, len(t.histograms))
	for key, state := range t.histograms {
		buckets := make([]PagingLatencyBucket, len(pagingLatencyBounds))
		for index, bound := range pagingLatencyBounds {
			buckets[index] = PagingLatencyBucket{
				UpperBoundSeconds: bound.Seconds(),
				Count:             state.buckets[index],
			}
		}
		out = append(out, PagingLatencyHistogram{
			QCI: key.qci, ENB: key.enb, Count: state.count,
			SumSeconds: state.sum.Seconds(), Buckets: buckets,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].QCI != out[j].QCI {
			return out[i].QCI < out[j].QCI
		}
		return out[i].ENB < out[j].ENB
	})
	return out, uint64(len(t.pending))
}
