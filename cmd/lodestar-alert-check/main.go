package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/lodestarnetworks/cups/internal/alerting"
)

func main() {
	path := flag.String("rules", "deploy/prometheus/lodestar-cups-alerts.yaml", "Prometheus alert rules file")
	flag.Parse()
	rules, err := alerting.Load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	alertCount := 0
	for _, group := range rules.Groups {
		alertCount += len(group.Rules)
	}
	fmt.Printf("alert_rules_valid=yes groups=%d alerts=%d\n", len(rules.Groups), alertCount)
}
