package notify

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func CommandForPlatform(title, body string) (string, []string, bool) {
	plans := commandPlans(runtime.GOOS, title, body, os.Getenv, currentOSRelease())
	if len(plans) == 0 {
		return "", nil, false
	}
	return plans[0].name, plans[0].args, true
}

func commandForGOOS(goos, title, body string) (string, []string, bool) {
	plans := commandPlans(goos, title, body, func(string) string { return "" }, "")
	if len(plans) == 0 {
		return "", nil, false
	}
	return plans[0].name, plans[0].args, true
}

func Send(title, body string) error {
	return sendWithDeps(title, body, runtime.GOOS, os.Getenv, currentOSRelease(), exec.LookPath, runCommand)
}

type commandPlan struct {
	name string
	args []string
}

var wslPowerShellPaths = []string{
	"/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
	"/mnt/c/Program Files/PowerShell/7/pwsh.exe",
}

func commandPlans(goos, title, body string, getenv func(string) string, osRelease string) []commandPlan {
	switch goos {
	case "darwin":
		script := fmt.Sprintf(`display notification %q with title %q`, body, title)
		return []commandPlan{{name: "osascript", args: []string{"-e", script}}}
	case "windows":
		return windowsPlans(title, body)
	case "linux":
		plans := []commandPlan{{name: "notify-send", args: []string{title, body}}}
		if isWSL(getenv, osRelease) {
			plans = append(plans, windowsPlans(title, body)...)
		}
		return plans
	default:
		return nil
	}
}

func commandCandidates(goos string, getenv func(string) string, osRelease string, plan commandPlan) []string {
	candidates := []string{plan.name}
	if goos == "linux" && isWSL(getenv, osRelease) && plan.name == "powershell.exe" {
		candidates = append(candidates, wslPowerShellPaths...)
	}
	return candidates
}

func windowsPlans(title, body string) []commandPlan {
	return []commandPlan{
		{name: "powershell.exe", args: powershellArgs(windowsToastScript(title, body))},
		{name: "powershell.exe", args: powershellArgs(windowsPopupScript(title, body))},
	}
}

func powershellArgs(script string) []string {
	return []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script}
}

func windowsToastScript(title, body string) string {
	xml := fmt.Sprintf(
		"<toast><visual><binding template='ToastGeneric'><text>%s</text><text>%s</text></binding></visual></toast>",
		xmlEscape(title),
		xmlEscape(body),
	)
	return strings.Join([]string{
		"Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null",
		"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null",
		"[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null",
		fmt.Sprintf("$xml = New-Object Windows.Data.Xml.Dom.XmlDocument; $xml.LoadXml(%s)", psSingleQuoted(xml)),
		"$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)",
		fmt.Sprintf("$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(%s)", psSingleQuoted("gryph-sentinel")),
		"$notifier.Show($toast)",
	}, "; ")
}

func windowsPopupScript(title, body string) string {
	return strings.Join([]string{
		"Add-Type -AssemblyName PresentationFramework | Out-Null",
		fmt.Sprintf("[System.Windows.MessageBox]::Show(%s, %s) | Out-Null", psSingleQuoted(body), psSingleQuoted(title)),
	}, "; ")
}

func psSingleQuoted(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(value)
}

func isWSL(getenv func(string) string, osRelease string) bool {
	if getenv("WSL_DISTRO_NAME") != "" || getenv("WSL_INTEROP") != "" {
		return true
	}
	release := strings.ToLower(osRelease)
	return strings.Contains(release, "microsoft") || strings.Contains(release, "wsl")
}

func currentOSRelease() string {
	paths := []string{
		"/proc/sys/kernel/osrelease",
		"/proc/version",
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

func sendWithDeps(
	title, body, goos string,
	getenv func(string) string,
	osRelease string,
	lookPath func(string) (string, error),
	run func(string, []string) error,
) error {
	plans := commandPlans(goos, title, body, getenv, osRelease)
	if len(plans) == 0 {
		return nil
	}

	var errs []string
	for _, plan := range plans {
		var planErrs []string
		for _, candidate := range commandCandidates(goos, getenv, osRelease, plan) {
			if _, err := lookPath(candidate); err != nil {
				planErrs = append(planErrs, fmt.Sprintf("%s unavailable: %v", candidate, err))
				continue
			}
			if err := run(candidate, plan.args); err == nil {
				return nil
			} else {
				planErrs = append(planErrs, fmt.Sprintf("%s failed: %v", filepath.Base(candidate), err))
			}
		}
		errs = append(errs, planErrs...)
	}

	return errors.New(strings.Join(errs, "; "))
}

func runCommand(name string, args []string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, trimmed)
}
