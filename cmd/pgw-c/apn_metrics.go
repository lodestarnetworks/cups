package main

import (
	"sort"
	"strings"

	"github.com/lodestarnetworks/cups/internal/config"
	"github.com/lodestarnetworks/cups/internal/pgwapi"
	"github.com/lodestarnetworks/cups/internal/pgwc/session"
)

type pgwcAPNCounts struct {
	sessions int
	bearers  int
}

// pgwcMetricScope labels metrics that describe one PGW-C process rather than
// one APN. Session metrics are emitted separately for every configured APN.
func pgwcMetricScope(value config.PGWC) string {
	apns := pgwcConfiguredAPNs(value)
	if len(apns) == 1 {
		return apns[0]
	}
	if len(apns) > 1 {
		return "multiple"
	}
	return "unconfigured"
}

func pgwcAPNSessionMetrics(value config.PGWC, sessions []session.Session) []pgwapi.Metric {
	counts := make(map[string]pgwcAPNCounts)
	for _, apn := range pgwcConfiguredAPNs(value) {
		counts[apn] = pgwcAPNCounts{}
	}
	for _, current := range sessions {
		apn := strings.ToLower(strings.TrimSpace(current.APN))
		if apn == "" {
			apn = "unmatched"
		}
		currentCounts := counts[apn]
		currentCounts.sessions++
		currentCounts.bearers += len(current.DedicatedBearers)
		counts[apn] = currentCounts
	}

	apns := make([]string, 0, len(counts))
	for apn := range counts {
		apns = append(apns, apn)
	}
	sort.Strings(apns)
	metrics := make([]pgwapi.Metric, 0, len(apns)*2)
	for _, apn := range apns {
		labels := map[string]string{"node": "pgw-c", "apn": apn}
		metrics = append(metrics,
			pgwapi.Metric{Name: "pfcp_sessions_active", Help: "Active PGW-C sessions by APN.", Type: "gauge", Labels: labels, Value: float64(counts[apn].sessions)},
			pgwapi.Metric{Name: "lodestar_pgw_dedicated_bearers_active", Help: "Active dedicated EPS bearers owned by PGW-C, by APN.", Type: "gauge", Labels: labels, Value: float64(counts[apn].bearers)},
		)
	}
	return metrics
}

func pgwcConfiguredAPNs(value config.PGWC) []string {
	seen := make(map[string]struct{}, len(value.APNProfiles)+1)
	for _, profile := range value.APNProfiles {
		if apn := strings.ToLower(strings.TrimSpace(profile.APN)); apn != "" {
			seen[apn] = struct{}{}
		}
	}
	if len(seen) == 0 {
		if apn := strings.ToLower(strings.TrimSpace(value.APN)); apn != "" {
			seen[apn] = struct{}{}
		}
	}
	apns := make([]string, 0, len(seen))
	for apn := range seen {
		apns = append(apns, apn)
	}
	sort.Strings(apns)
	return apns
}
