package main

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/lodestarnetworks/cups/internal/config"
	"github.com/lodestarnetworks/cups/internal/pgwapi"
	"github.com/lodestarnetworks/cups/internal/pgwu/rules"
)

type pgwuAPNRange struct {
	apn    string
	prefix netip.Prefix
}

// pgwuAPNSessionTracker maintains per-APN gauges in O(log pools) per PFCP
// transition. Metrics scrapes therefore remain O(number of APNs), even when a
// PGW-U owns hundreds of thousands of sessions.
type pgwuAPNSessionTracker struct {
	mu         sync.RWMutex
	defaultAPN string
	ranges     []pgwuAPNRange
	bySession  map[uint64]string
	counts     map[string]int
}

func newPGWUAPNSessionTracker(value config.PGWU) (*pgwuAPNSessionTracker, error) {
	tracker := &pgwuAPNSessionTracker{
		bySession: make(map[uint64]string),
		counts:    make(map[string]int),
	}
	if len(value.UEPools) == 0 {
		tracker.defaultAPN = strings.ToLower(strings.TrimSpace(value.APN))
		if tracker.defaultAPN == "" {
			return nil, errors.New("pgwu APN telemetry: one APN or UE pool is required")
		}
		tracker.counts[tracker.defaultAPN] = 0
		return tracker, nil
	}

	tracker.ranges = make([]pgwuAPNRange, 0, len(value.UEPools))
	for _, pool := range value.UEPools {
		apn := strings.ToLower(strings.TrimSpace(pool.APN))
		if apn == "" {
			return nil, errors.New("pgwu APN telemetry: UE pool has an empty APN")
		}
		prefix, err := config.Prefix(pool.UEPoolPrefix, "ue_pools")
		if err != nil {
			return nil, err
		}
		prefix = prefix.Masked()
		if !prefix.Addr().Is4() {
			return nil, errors.New("pgwu APN telemetry: UE pool must be IPv4")
		}
		tracker.ranges = append(tracker.ranges, pgwuAPNRange{apn: apn, prefix: prefix})
		tracker.counts[apn] = 0
	}
	sort.Slice(tracker.ranges, func(left, right int) bool {
		return tracker.ranges[left].prefix.Addr().Less(tracker.ranges[right].prefix.Addr())
	})
	return tracker, nil
}

func (t *pgwuAPNSessionTracker) ReconcileSession(current rules.Session) {
	apn := t.classify(current.UEIPv4)
	t.mu.Lock()
	defer t.mu.Unlock()
	if previous, exists := t.bySession[current.UPSEID]; exists {
		if previous == apn {
			return
		}
		t.counts[previous]--
	}
	t.bySession[current.UPSEID] = apn
	t.counts[apn]++
}

func (t *pgwuAPNSessionTracker) DeleteSession(upSEID uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	apn, exists := t.bySession[upSEID]
	if !exists {
		return
	}
	delete(t.bySession, upSEID)
	t.counts[apn]--
}

func (t *pgwuAPNSessionTracker) Metrics() ([]pgwapi.Metric, int, int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	apns := make([]string, 0, len(t.counts))
	for apn := range t.counts {
		if apn != "unmatched" {
			apns = append(apns, apn)
		}
	}
	sort.Strings(apns)
	metrics := make([]pgwapi.Metric, 0, len(apns))
	for _, apn := range apns {
		metrics = append(metrics, pgwapi.Metric{
			Name: "pfcp_sessions_active", Help: "Active PGW-U sessions by APN.", Type: "gauge",
			Labels: map[string]string{"node": "pgw-u", "apn": apn}, Value: float64(t.counts[apn]),
		})
	}
	return metrics, len(t.bySession), t.counts["unmatched"]
}

func (t *pgwuAPNSessionTracker) classify(address netip.Addr) string {
	if t.defaultAPN != "" {
		return t.defaultAPN
	}
	address = address.Unmap()
	if !address.Is4() {
		return "unmatched"
	}
	index := sort.Search(len(t.ranges), func(index int) bool {
		return address.Less(t.ranges[index].prefix.Addr())
	})
	if index > 0 && t.ranges[index-1].prefix.Contains(address) {
		return t.ranges[index-1].apn
	}
	return "unmatched"
}

type pgwuObserverSet []rules.Observer

func (o pgwuObserverSet) ReconcileSession(current rules.Session) {
	for _, observer := range o {
		observer.ReconcileSession(current)
	}
}

func (o pgwuObserverSet) DeleteSession(upSEID uint64) {
	for _, observer := range o {
		observer.DeleteSession(upSEID)
	}
}
