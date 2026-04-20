package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/safedep/gryph-sentinel/internal/event"
)

type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func ParseSeverity(raw string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "low":
		return SeverityLow, nil
	case "medium":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return 0, fmt.Errorf("unknown severity %q", raw)
	}
}

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

func (s Severity) AtLeast(threshold Severity) bool {
	return s >= threshold
}

type Rule struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	ActionType  string `yaml:"action_type"`
	Pattern     string `yaml:"pattern"`
	Severity    string `yaml:"severity"`
}

type CompiledRule struct {
	Rule
	SeverityValue Severity
	re            *regexp.Regexp
}

type Finding struct {
	RuleName     string
	Description  string
	ActionType   string
	Severity     string
	MatchedValue string
}

func MatchEvent(compiled []CompiledRule, evt event.Event) []Finding {
	target, ok := evt.MatchTarget()
	if !ok {
		return nil
	}

	var findings []Finding
	for _, rule := range compiled {
		if rule.ActionType != evt.ActionType {
			continue
		}
		if rule.re.MatchString(target) {
			findings = append(findings, Finding{
				RuleName:     rule.Name,
				Description:  rule.Description,
				ActionType:   rule.ActionType,
				Severity:     rule.Severity,
				MatchedValue: target,
			})
		}
	}

	return findings
}
