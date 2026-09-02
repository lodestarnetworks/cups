package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lodestarnetworks/cups/internal/telemetry"
)

type staticProvider struct{ snapshot telemetry.Snapshot }

func (p staticProvider) Snapshot() telemetry.Snapshot { return p.snapshot }

func TestDashboardAndCORS(t *testing.T) {
	provider := staticProvider{snapshot: telemetry.Snapshot{
		GeneratedAt: time.Unix(1_700_000_000, 0).UTC(),
		Mode:        "test",
		SGWC:        telemetry.SGWC{State: telemetry.StateHealthy, ActiveSessions: 42},
		SGWU:        telemetry.SGWU{State: telemetry.StateHealthy},
	}}
	handler := NewHandler(provider, Config{AllowedOrigins: []string{"http://localhost:3000"}})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard", nil)
	request.Header.Set("Origin", "http://localhost:3000")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Fatalf("allow origin = %q", got)
	}
	if !strings.Contains(response.Body.String(), `"activeSessions":42`) {
		t.Fatalf("dashboard response missing session count: %s", response.Body.String())
	}
}

func TestEventsRejectInvalidLimit(t *testing.T) {
	handler := NewHandler(staticProvider{}, Config{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/events?limit=201", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestHealthIsUnavailableWhenComponentDown(t *testing.T) {
	handler := NewHandler(staticProvider{snapshot: telemetry.Snapshot{
		SGWC: telemetry.SGWC{State: telemetry.StateHealthy},
		SGWU: telemetry.SGWU{State: telemetry.StateDown},
	}}, Config{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestStandaloneSGWUHealthDoesNotInventControlPlaneState(t *testing.T) {
	handler := NewHandler(staticProvider{snapshot: telemetry.Snapshot{
		Mode: "live-sgwu",
		SGWC: telemetry.SGWC{State: telemetry.StateStarting},
		SGWU: telemetry.SGWU{State: telemetry.StateHealthy},
	}}, Config{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	body := response.Body.String()
	if !strings.Contains(body, `"status":"healthy"`) || !strings.Contains(body, `"sgw-u":"healthy"`) {
		t.Fatalf("standalone SGW-U health = %s", body)
	}
	if strings.Contains(body, `"sgw-c"`) {
		t.Fatalf("standalone SGW-U health invented an SGW-C state: %s", body)
	}
}

func TestCombinedHealthStillRequiresBothComponents(t *testing.T) {
	handler := NewHandler(staticProvider{snapshot: telemetry.Snapshot{
		Mode: "live-lte",
		SGWC: telemetry.SGWC{State: telemetry.StateHealthy},
		SGWU: telemetry.SGWU{State: telemetry.StateStarting},
	}}, Config{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, `"status":"degraded"`) ||
		!strings.Contains(body, `"sgw-c":"healthy"`) || !strings.Contains(body, `"sgw-u":"starting"`) {
		t.Fatalf("combined health = status %d, body %s", response.Code, body)
	}
}

func TestMetricsExposeBothDirections(t *testing.T) {
	lastTrafficAt := time.Unix(1_700_000_001, 0).UTC()
	handler := NewHandler(staticProvider{snapshot: telemetry.Snapshot{
		SGWC: telemetry.SGWC{PendingPaging: 2, DDNPagingHistograms: []telemetry.DDNPagingHistogram{{
			QCI: 9, ENB: "192.0.2.10", Count: 3, SumSeconds: 0.12,
			Buckets: []telemetry.HistogramBucket{{UpperBoundSeconds: 0.05, Count: 2}},
		}}},
		SGWU: telemetry.SGWU{
			UplinkBitsPerSecond: 12, DownlinkBitsPerSecond: 34,
			ForwardedPackets: 123, ForwardedBytes: 456, LastTrafficAt: &lastTrafficAt,
			FastPathFallbacks: 5, FastPathForwardedPackets: 8, FastPathForwardedBytes: 9,
			FastPathSyncFailures: 6, FastPathRewriteErrors: 7,
			FastPathP95LatencyMillis: 0.002,
		},
	}}, Config{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := response.Body.String()
	for _, expected := range []string{
		`sgw_next_sgwu_gtpu_bits_per_second{direction="uplink"} 12`,
		`sgw_next_sgwu_gtpu_bits_per_second{direction="downlink"} 34`,
		`sgw_next_sgwu_forwarded_packets_total 123`,
		`sgw_next_sgwu_forwarded_bytes_total 456`,
		`sgw_next_sgwu_last_forwarded_packet_timestamp_seconds 1.700000001e+09`,
		`sgw_next_sgwc_pending_paging 2`,
		`ddn_to_paging_response_seconds_bucket{qci="9",enb="192.0.2.10",le="0.05"} 2`,
		`ddn_to_paging_response_seconds_bucket{qci="9",enb="192.0.2.10",le="+Inf"} 3`,
		`ddn_to_paging_response_seconds_sum{qci="9",enb="192.0.2.10"} 0.12`,
		`ddn_to_paging_response_seconds_count{qci="9",enb="192.0.2.10"} 3`,
		`sgw_next_sgwu_fast_path_fallback_packets_total 5`,
		`sgw_next_sgwu_fast_path_forwarded_packets_total 8`,
		`sgw_next_sgwu_fast_path_forwarded_bytes_total 9`,
		`sgw_next_sgwu_fast_path_sync_failures_total 6`,
		`sgw_next_sgwu_fast_path_rewrite_errors_total 7`,
		`sgw_next_sgwu_fast_path_p95_milliseconds 0.002`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("metrics missing %q:\n%s", expected, body)
		}
	}
}
