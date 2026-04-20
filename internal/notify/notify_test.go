package notify

import (
	"errors"
	"strings"
	"testing"
)

func TestIsWSL(t *testing.T) {
	tests := []struct {
		name      string
		envValue  string
		osRelease string
		want      bool
	}{
		{name: "env var", envValue: "Ubuntu-22.04", want: true},
		{name: "kernel release", osRelease: "5.15.153.1-microsoft-standard-WSL2", want: true},
		{name: "plain linux", osRelease: "6.8.0-generic", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isWSL(func(key string) string {
				if key == "WSL_DISTRO_NAME" {
					return tt.envValue
				}
				return ""
			}, tt.osRelease)
			if got != tt.want {
				t.Fatalf("isWSL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommandPlansForLinux(t *testing.T) {
	plans := commandPlans("linux", "gryph-sentinel", "critical findings", func(string) string { return "" }, "6.8.0-generic")
	if len(plans) != 1 || plans[0].name != "notify-send" {
		t.Fatalf("unexpected linux plans: %#v", plans)
	}
}

func TestCommandPlansForWSLIncludeWindowsFallbacks(t *testing.T) {
	plans := commandPlans("linux", "gryph-sentinel", "critical findings", func(key string) string {
		if key == "WSL_DISTRO_NAME" {
			return "Ubuntu-22.04"
		}
		return ""
	}, "")

	if len(plans) != 3 {
		t.Fatalf("expected 3 plans, got %#v", plans)
	}
	if plans[0].name != "notify-send" || plans[1].name != "powershell.exe" || plans[2].name != "powershell.exe" {
		t.Fatalf("unexpected WSL plan order: %#v", plans)
	}

	toast := strings.Join(plans[1].args, " ")
	if !strings.Contains(toast, "CreateToastNotifier") {
		t.Fatalf("expected toast command, got %q", toast)
	}

	popup := strings.Join(plans[2].args, " ")
	if !strings.Contains(popup, "MessageBox") {
		t.Fatalf("expected popup fallback command, got %q", popup)
	}
}

func TestCommandPlansForWindowsUseToastThenPopup(t *testing.T) {
	plans := commandPlans("windows", "gryph-sentinel", "critical findings", func(string) string { return "" }, "")
	if len(plans) != 2 {
		t.Fatalf("expected 2 plans, got %#v", plans)
	}
	if plans[0].name != "powershell.exe" || plans[1].name != "powershell.exe" {
		t.Fatalf("unexpected windows plans: %#v", plans)
	}
}

func TestSendFallsBackAfterNotifySendFailure(t *testing.T) {
	var calls []string
	err := sendWithDeps(
		"gryph-sentinel",
		"critical findings",
		"linux",
		func(key string) string {
			if key == "WSL_DISTRO_NAME" {
				return "Ubuntu-22.04"
			}
			return ""
		},
		"",
		func(name string) (string, error) { return name, nil },
		func(name string, args []string) error {
			calls = append(calls, name)
			if name == "notify-send" {
				return errors.New("dbus unavailable")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("expected fallback success, got %v", err)
	}
	if len(calls) != 2 || calls[0] != "notify-send" || calls[1] != "powershell.exe" {
		t.Fatalf("unexpected call order: %#v", calls)
	}
}

func TestSendUsesAbsolutePowerShellPathInWSL(t *testing.T) {
	var calls []string
	const absPowerShell = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"

	err := sendWithDeps(
		"gryph-sentinel",
		"critical findings",
		"linux",
		func(key string) string {
			if key == "WSL_DISTRO_NAME" {
				return "Ubuntu-22.04"
			}
			return ""
		},
		"",
		func(name string) (string, error) {
			switch name {
			case "notify-send", "powershell.exe":
				return "", errors.New("not found")
			case absPowerShell:
				return name, nil
			default:
				return "", errors.New("unexpected lookup")
			}
		},
		func(name string, args []string) error {
			calls = append(calls, name)
			if name == "notify-send" {
				return errors.New("dbus unavailable")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("expected absolute path fallback success, got %v", err)
	}
	if len(calls) != 1 || calls[0] != absPowerShell {
		t.Fatalf("unexpected call order: %#v", calls)
	}
}

func TestSendReturnsErrorWhenAllPlansFail(t *testing.T) {
	err := sendWithDeps(
		"gryph-sentinel",
		"critical findings",
		"windows",
		func(string) string { return "" },
		"",
		func(name string) (string, error) { return name, nil },
		func(name string, args []string) error { return errors.New("failed") },
	)
	if err == nil {
		t.Fatal("expected send failure")
	}
}
