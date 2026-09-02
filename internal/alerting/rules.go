// Package alerting validates the Prometheus rule shape shipped with a
// Lodestar CUPS release. Prometheus remains the authority for PromQL parsing;
// this catches malformed YAML and incomplete operational metadata at build.
package alerting

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type File struct {
	Groups []Group `yaml:"groups"`
}

type Group struct {
	Name     string `yaml:"name"`
	Interval string `yaml:"interval"`
	Rules    []Rule `yaml:"rules"`
}

type Rule struct {
	Alert       string            `yaml:"alert"`
	Expression  string            `yaml:"expr"`
	For         string            `yaml:"for"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

func Load(path string) (File, error) {
	file, err := os.Open(path)
	if err != nil {
		return File{}, err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.KnownFields(true)
	var rules File
	if err := decoder.Decode(&rules); err != nil {
		return File{}, fmt.Errorf("decode alert rules: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return File{}, errors.New("alert rules contain a trailing YAML document")
	}
	if err := rules.Validate(); err != nil {
		return File{}, err
	}
	return rules, nil
}

func (f File) Validate() error {
	if len(f.Groups) == 0 {
		return errors.New("alert rules require at least one group")
	}
	groups := make(map[string]struct{}, len(f.Groups))
	alerts := make(map[string]struct{})
	for groupIndex, group := range f.Groups {
		group.Name = strings.TrimSpace(group.Name)
		if group.Name == "" || len(group.Rules) == 0 {
			return fmt.Errorf("alert group %d requires a name and rules", groupIndex)
		}
		if _, duplicate := groups[group.Name]; duplicate {
			return fmt.Errorf("duplicate alert group %q", group.Name)
		}
		groups[group.Name] = struct{}{}
		if duration, err := time.ParseDuration(group.Interval); err != nil || duration <= 0 {
			return fmt.Errorf("alert group %q has an invalid positive interval", group.Name)
		}
		for ruleIndex, rule := range group.Rules {
			rule.Alert = strings.TrimSpace(rule.Alert)
			if rule.Alert == "" || strings.TrimSpace(rule.Expression) == "" {
				return fmt.Errorf("alert group %q rule %d requires alert and expr", group.Name, ruleIndex)
			}
			if _, duplicate := alerts[rule.Alert]; duplicate {
				return fmt.Errorf("duplicate alert %q", rule.Alert)
			}
			alerts[rule.Alert] = struct{}{}
			if duration, err := time.ParseDuration(rule.For); err != nil || duration < 0 {
				return fmt.Errorf("alert %q has an invalid non-negative for duration", rule.Alert)
			}
			severity := rule.Labels["severity"]
			if severity != "warning" && severity != "critical" {
				return fmt.Errorf("alert %q requires warning or critical severity", rule.Alert)
			}
			if strings.TrimSpace(rule.Annotations["summary"]) == "" || strings.TrimSpace(rule.Annotations["description"]) == "" {
				return fmt.Errorf("alert %q requires summary and description annotations", rule.Alert)
			}
		}
	}
	return nil
}
