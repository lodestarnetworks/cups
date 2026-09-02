package alerting

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReleaseAlertRulesValidate(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	path := filepath.Clean(filepath.Join(filepath.Dir(current), "..", "..", "deploy", "prometheus", "lodestar-cups-alerts.yaml"))
	rules, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules.Groups) < 4 {
		t.Fatalf("release alert groups = %d", len(rules.Groups))
	}
}

func TestAlertRulesRejectUnknownAndIncompleteFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.yaml")
	invalid := `groups:
  - name: test
    interval: 15s
    rules:
      - alert: Broken
        expr: vector(1)
        for: 0s
        labels: {severity: notice}
        annotations: {summary: missing-description}
`
	if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "severity") {
		t.Fatalf("incomplete alert error = %v", err)
	}
}
