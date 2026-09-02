package main

import (
	"testing"

	"github.com/lodestarnetworks/cups/internal/config"
	"github.com/lodestarnetworks/cups/internal/pgwapi"
	"github.com/lodestarnetworks/cups/internal/pgwc/session"
)

func TestPGWCAPNSessionMetricsSeparateProfiles(t *testing.T) {
	value := config.PGWC{APNProfiles: []config.PGWCAPNProfile{{APN: "internet"}, {APN: "ims"}}}
	sessions := []session.Session{
		{APN: "internet", DedicatedBearers: map[uint8]session.Bearer{7: {EBI: 7}}},
		{APN: "internet"},
		{APN: "ims", DedicatedBearers: map[uint8]session.Bearer{8: {EBI: 8}, 9: {EBI: 9}}},
	}
	metrics := pgwcAPNSessionMetrics(value, sessions)
	assertPGWCMetric(t, metrics, "pfcp_sessions_active", "internet", 2)
	assertPGWCMetric(t, metrics, "pfcp_sessions_active", "ims", 1)
	assertPGWCMetric(t, metrics, "lodestar_pgw_dedicated_bearers_active", "internet", 1)
	assertPGWCMetric(t, metrics, "lodestar_pgw_dedicated_bearers_active", "ims", 2)
	if scope := pgwcMetricScope(value); scope != "multiple" {
		t.Fatalf("multi-APN metric scope = %q", scope)
	}
}

func TestPGWCAPNSessionMetricsExposeConfiguredZero(t *testing.T) {
	value := config.PGWC{APNProfiles: []config.PGWCAPNProfile{{APN: "internet"}, {APN: "ims"}}}
	metrics := pgwcAPNSessionMetrics(value, nil)
	assertPGWCMetric(t, metrics, "pfcp_sessions_active", "internet", 0)
	assertPGWCMetric(t, metrics, "pfcp_sessions_active", "ims", 0)
	for _, metric := range metrics {
		if metric.Labels["apn"] == "" {
			t.Fatal("multi-APN metric emitted an empty APN label")
		}
	}
}

func assertPGWCMetric(t *testing.T, metrics []pgwapi.Metric, name, apn string, want float64) {
	t.Helper()
	for _, metric := range metrics {
		if metric.Name == name && metric.Labels["apn"] == apn {
			if metric.Value != want {
				t.Fatalf("metric %s{%s} = %v, want %v", name, apn, metric.Value, want)
			}
			return
		}
	}
	t.Fatalf("metric %s{%s} not found: %#v", name, apn, metrics)
}
