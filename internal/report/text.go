package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/safedep/gryph-sentinel/internal/analyzer"
)

func RenderText(in analyzer.Report, noColor bool) (string, error) {
	oldNoColor := color.NoColor
	color.NoColor = noColor
	defer func() {
		color.NoColor = oldNoColor
	}()

	if len(in.Findings) == 0 {
		return fmt.Sprintf("No suspicious activity detected across %d events\n", in.TotalEvents), nil
	}

	var b strings.Builder
	line := strings.Repeat("=", 59)
	b.WriteString(line + "\n")
	b.WriteString("  gryph-sentinel  |  Session Risk Report\n")
	b.WriteString(line + "\n\n")
	b.WriteString(fmt.Sprintf("  Agent       %s\n", valueOrUnknown(in.AgentName)))
	b.WriteString(fmt.Sprintf("  Session     %s\n", valueOrUnknown(in.SessionID)))
	b.WriteString(fmt.Sprintf("  Events      %d total  |  %d findings\n", in.TotalEvents, len(in.Findings)))
	b.WriteString(fmt.Sprintf("  Risk        %s\n\n", in.RiskLevel))

	for _, finding := range in.Findings {
		b.WriteString(fmt.Sprintf("%s  %s\n", formatSeverityLabel(finding.Severity), finding.RuleName))
		b.WriteString(fmt.Sprintf("   %s\n", finding.Description))
		if finding.ActionType == "command_exec" {
			b.WriteString(fmt.Sprintf("   Command   %s\n", finding.MatchedValue))
		} else {
			b.WriteString(fmt.Sprintf("   Path      %s\n", finding.MatchedValue))
		}
		b.WriteString(fmt.Sprintf("   Time      %s\n", shortTime(finding.Timestamp)))
		b.WriteString(fmt.Sprintf("   Dir       %s\n\n", valueOrUnknown(finding.WorkingDirectory)))
	}

	b.WriteString(line + "\n")
	b.WriteString(fmt.Sprintf("  %d findings  |  %d critical  %d high  %d medium  %d low\n",
		len(in.Findings), in.Summary.Critical, in.Summary.High, in.Summary.Medium, in.Summary.Low))
	b.WriteString(line + "\n")
	return b.String(), nil
}

func formatSeverityLabel(severity string) string {
	label := strings.ToUpper(severity)

	var sprint func(a ...interface{}) string
	switch severity {
	case "critical":
		sprint = color.New(color.Bold, color.FgRed).SprintFunc()
	case "high":
		sprint = color.New(color.Bold, color.FgYellow).SprintFunc()
	case "medium":
		sprint = color.New(color.Bold, color.FgBlue).SprintFunc()
	default:
		sprint = color.New(color.Bold).SprintFunc()
	}
	return sprint(label)
}

func shortTime(ts string) string {
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return parsed.Format("15:04:05")
}

func valueOrUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
