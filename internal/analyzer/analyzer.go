package analyzer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/safedep/gryph-sentinel/internal/event"
	"github.com/safedep/gryph-sentinel/internal/rules"
)

type Options struct {
	Rules       []rules.CompiledRule
	SessionID   string
	MinSeverity rules.Severity
}

type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type Finding struct {
	RuleName         string `json:"rule_name"`
	Severity         string `json:"severity"`
	Description      string `json:"description"`
	ActionType       string `json:"action_type"`
	MatchedValue     string `json:"matched_value"`
	Timestamp        string `json:"timestamp"`
	WorkingDirectory string `json:"working_directory"`
	EventID          string `json:"event_id"`
}

type Report struct {
	SessionID   string    `json:"session_id"`
	AgentName   string    `json:"agent_name"`
	TotalEvents int       `json:"total_events"`
	RiskLevel   string    `json:"risk_level"`
	Findings    []Finding `json:"findings"`
	Summary     Summary   `json:"summary"`
}

func Analyze(r io.Reader, opts Options) (Report, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var report Report
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var evt event.Event
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			continue
		}
		if opts.SessionID != "" && evt.SessionID != opts.SessionID {
			continue
		}

		report.TotalEvents++
		if report.SessionID == "" {
			report.SessionID = evt.SessionID
		}
		if report.AgentName == "" {
			report.AgentName = evt.AgentName
		}

		for _, finding := range rules.MatchEvent(opts.Rules, evt) {
			sev, err := rules.ParseSeverity(finding.Severity)
			if err != nil || sev < opts.MinSeverity {
				continue
			}

			report.Findings = append(report.Findings, Finding{
				RuleName:         finding.RuleName,
				Severity:         finding.Severity,
				Description:      finding.Description,
				ActionType:       finding.ActionType,
				MatchedValue:     finding.MatchedValue,
				Timestamp:        evt.Timestamp,
				WorkingDirectory: evt.WorkingDirectory,
				EventID:          evt.ID,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return Report{}, fmt.Errorf("scan input: %w", err)
	}

	sort.SliceStable(report.Findings, func(i, j int) bool {
		left, _ := rules.ParseSeverity(report.Findings[i].Severity)
		right, _ := rules.ParseSeverity(report.Findings[j].Severity)
		if left != right {
			return left > right
		}
		if report.Findings[i].Timestamp != report.Findings[j].Timestamp {
			return report.Findings[i].Timestamp < report.Findings[j].Timestamp
		}
		return report.Findings[i].RuleName < report.Findings[j].RuleName
	})

	report.Summary = Summarize(report.Findings)
	report.RiskLevel = RiskLevel(report.Summary)
	return report, nil
}

func Summarize(findings []Finding) Summary {
	var summary Summary
	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		}
	}
	return summary
}

func RiskLevel(summary Summary) string {
	switch {
	case summary.Critical > 0:
		return "CRITICAL"
	case summary.High > 0:
		return "HIGH"
	case summary.Medium > 0:
		return "MEDIUM"
	case summary.Low > 0:
		return "LOW"
	default:
		return "CLEAN"
	}
}

func (r Report) HasSeverityAtOrAbove(threshold rules.Severity) bool {
	for _, finding := range r.Findings {
		sev, err := rules.ParseSeverity(finding.Severity)
		if err == nil && sev >= threshold {
			return true
		}
	}
	return false
}
