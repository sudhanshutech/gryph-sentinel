package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/safedep/gryph-sentinel/internal/analyzer"
	"github.com/safedep/gryph-sentinel/internal/notify"
	"github.com/safedep/gryph-sentinel/internal/report"
	"github.com/safedep/gryph-sentinel/internal/rules"
)

var sendNotification = notify.Send

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "analyze" {
		printUsage(stderr)
		return 2
	}

	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var rulesPath string
	var output string
	var minSeverity string
	var sessionID string
	var failOn string
	var notifyFlag bool
	var noColor bool

	fs.StringVar(&rulesPath, "rules", "", "Path to custom rules.yaml")
	fs.StringVar(&output, "output", "text", "Output format: text or json")
	fs.StringVar(&minSeverity, "min-severity", "low", "Minimum severity to report")
	fs.StringVar(&sessionID, "session", "", "Filter to a specific session ID")
	fs.StringVar(&failOn, "fail-on", "", "Exit with code 1 at or above severity")
	fs.BoolVar(&notifyFlag, "notify", false, "Send notification for critical findings")
	fs.BoolVar(&noColor, "no-color", false, "Disable colored output")

	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if len(fs.Args()) > 0 {
		printUsage(stderr)
		fs.PrintDefaults()
		return 2
	}

	min, err := rules.ParseSeverity(minSeverity)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	var failThreshold *rules.Severity
	if failOn != "" {
		sev, err := rules.ParseSeverity(failOn)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		failThreshold = &sev
	}

	compiled, err := rules.Load(rulesPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	rep, err := analyzer.Analyze(stdin, analyzer.Options{
		Rules:       compiled,
		SessionID:   sessionID,
		MinSeverity: min,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	var rendered string
	switch output {
	case "text":
		rendered, err = report.RenderText(rep, noColor)
	case "json":
		rendered, err = report.RenderJSON(rep)
	default:
		fmt.Fprintln(stderr, "invalid output format")
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	if len(rendered) > 0 && rendered[len(rendered)-1] == '\n' {
		fmt.Fprint(stdout, rendered)
	} else {
		fmt.Fprintln(stdout, rendered)
	}

	if notifyFlag && rep.Summary.Critical > 0 {
		if err := sendNotification("gryph-sentinel", "Critical findings detected"); err != nil {
			fmt.Fprintf(stderr, "warning: notification failed: %v\n", err)
		}
	}

	if failThreshold != nil && rep.HasSeverityAtOrAbove(*failThreshold) {
		return 1
	}

	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: gryph-sentinel analyze [flags]")
}
