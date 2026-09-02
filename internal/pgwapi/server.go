// Package pgwapi exposes read-only health and Prometheus endpoints for PGW
// processes. It is deliberately separate from the SGW dashboard API.
package pgwapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Metric struct {
	Name   string
	Help   string
	Type   string
	Labels map[string]string
	Value  float64
}

type HistogramBucket struct {
	UpperBound float64
	Count      uint64
}

type Histogram struct {
	Name    string
	Help    string
	Labels  map[string]string
	Buckets []HistogramBucket
	Count   uint64
}

type Snapshot struct {
	Component    string
	Healthy      bool
	Status       string
	StartedAt    time.Time
	Datapath     string
	Capabilities map[string]bool
	Metrics      []Metric
	Histograms   []Histogram
}

type Provider func() Snapshot

func NewHandler(provider Provider) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		snapshot := provider()
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		status := http.StatusOK
		if !snapshot.Healthy {
			status = http.StatusServiceUnavailable
		}
		writer.WriteHeader(status)
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"component": snapshot.Component, "healthy": snapshot.Healthy,
			"status": snapshot.Status, "startedAt": snapshot.StartedAt.UTC(),
			"datapath": snapshot.Datapath, "capabilities": snapshot.Capabilities,
		})
	})
	mux.HandleFunc("GET /metrics", func(writer http.ResponseWriter, _ *http.Request) {
		snapshot := provider()
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		metrics := append([]Metric(nil), snapshot.Metrics...)
		sort.SliceStable(metrics, func(i, j int) bool { return metrics[i].Name < metrics[j].Name })
		seen := make(map[string]struct{})
		for _, metric := range metrics {
			if !validMetricName(metric.Name) {
				continue
			}
			if _, ok := seen[metric.Name]; !ok {
				if metric.Help != "" {
					_, _ = fmt.Fprintf(writer, "# HELP %s %s\n", metric.Name, escapeHelp(metric.Help))
				}
				metricType := metric.Type
				if metricType != "counter" && metricType != "gauge" && metricType != "histogram" {
					metricType = "gauge"
				}
				_, _ = fmt.Fprintf(writer, "# TYPE %s %s\n", metric.Name, metricType)
				seen[metric.Name] = struct{}{}
			}
			_, _ = fmt.Fprintf(writer, "%s%s %s\n", metric.Name, formatLabels(metric.Labels), strconv.FormatFloat(metric.Value, 'g', -1, 64))
		}
		for _, histogram := range snapshot.Histograms {
			writeHistogram(writer, histogram)
		}
	})
	return securityHeaders(mux)
}

func writeHistogram(writer http.ResponseWriter, histogram Histogram) {
	if !validMetricName(histogram.Name) {
		return
	}
	if histogram.Help != "" {
		_, _ = fmt.Fprintf(writer, "# HELP %s %s\n", histogram.Name, escapeHelp(histogram.Help))
	}
	_, _ = fmt.Fprintf(writer, "# TYPE %s histogram\n", histogram.Name)
	for _, bucket := range histogram.Buckets {
		labels := cloneLabels(histogram.Labels)
		labels["le"] = strconv.FormatFloat(bucket.UpperBound, 'g', -1, 64)
		_, _ = fmt.Fprintf(writer, "%s_bucket%s %d\n", histogram.Name, formatLabels(labels), bucket.Count)
	}
	labels := cloneLabels(histogram.Labels)
	labels["le"] = "+Inf"
	_, _ = fmt.Fprintf(writer, "%s_bucket%s %d\n", histogram.Name, formatLabels(labels), histogram.Count)
	_, _ = fmt.Fprintf(writer, "%s_count%s %d\n", histogram.Name, formatLabels(histogram.Labels), histogram.Count)
}

func cloneLabels(values map[string]string) map[string]string {
	out := make(map[string]string, len(values)+1)
	for key, value := range values {
		out[key] = value
	}
	return out
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(writer, request)
	})
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		if !validLabelName(key) {
			continue
		}
		value := strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"").Replace(labels[key])
		parts = append(parts, key+"=\""+value+"\"")
	}
	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func validMetricName(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if character == '_' || character == ':' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}

func validLabelName(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if character == '_' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}

func escapeHelp(value string) string {
	return strings.NewReplacer("\\", "\\\\", "\n", "\\n").Replace(value)
}
