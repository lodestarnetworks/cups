package pgwapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthAndMetricsAreReadOnlyAndSeparate(t *testing.T) {
	started := time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC)
	handler := NewHandler(func() Snapshot {
		return Snapshot{
			Component: "pgw-c", Healthy: true, Status: "associated", StartedAt: started,
			Datapath: "control-plane", Capabilities: map[string]bool{"pfcp": true},
			Metrics: []Metric{
				{Name: "pfcp_association_state", Type: "gauge", Help: "PFCP association state.", Labels: map[string]string{"node": "pgw-c", "peer": "10.0.0.2"}, Value: 1},
				{Name: "pfcp_sessions_active", Type: "gauge", Labels: map[string]string{"node": "pgw-c", "apn": "lodestartest"}, Value: 2},
			},
			Histograms: []Histogram{{
				Name: "lodestar_processing_seconds", Help: "Packet latency.", Labels: map[string]string{"node": "pgw-u"},
				Buckets: []HistogramBucket{{UpperBound: 0.001, Count: 2}, {UpperBound: 0.005, Count: 3}}, Count: 4,
			}},
		}
	})

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"component":"pgw-c"`) ||
		!strings.Contains(health.Body.String(), `"datapath":"control-plane"`) || !strings.Contains(health.Body.String(), `"pfcp":true`) {
		t.Fatalf("health response = %d %s", health.Code, health.Body.String())
	}
	if health.Header().Get("Access-Control-Allow-Origin") != "" || health.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("unexpected management headers: %#v", health.Header())
	}

	metrics := httptest.NewRecorder()
	handler.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metrics.Code != http.StatusOK || !strings.Contains(metrics.Body.String(), `pfcp_sessions_active{apn="lodestartest",node="pgw-c"} 2`) ||
		!strings.Contains(metrics.Body.String(), `lodestar_processing_seconds_bucket{le="0.005",node="pgw-u"} 3`) ||
		!strings.Contains(metrics.Body.String(), `lodestar_processing_seconds_bucket{le="+Inf",node="pgw-u"} 4`) {
		t.Fatalf("metrics response = %d %s", metrics.Code, metrics.Body.String())
	}

	post := httptest.NewRecorder()
	handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics status = %d", post.Code)
	}
}
