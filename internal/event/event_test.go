package event

import (
	"encoding/json"
	"testing"
)

func TestUnmarshalCommandExecTarget(t *testing.T) {
	const raw = `{
		"id": "evt-1",
		"session_id": "sess-clean",
		"action_type": "command_exec",
		"payload": { "command": "go test ./..." }
	}`
	var e Event
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.ActionType != "command_exec" {
		t.Fatalf("action_type: got %q", e.ActionType)
	}
	if e.Payload.Command != "go test ./..." {
		t.Fatalf("payload.command: got %q", e.Payload.Command)
	}
	got, ok := e.MatchTarget()
	if !ok || got != "go test ./..." {
		t.Fatalf("MatchTarget: ok=%v got=%q", ok, got)
	}
}

func TestUnmarshalFileReadTarget(t *testing.T) {
	const raw = `{
		"id": "evt-2",
		"session_id": "sess-clean",
		"action_type": "file_read",
		"payload": { "path": "/home/user/project/README.md" }
	}`
	var e Event
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.ActionType != "file_read" {
		t.Fatalf("action_type: got %q", e.ActionType)
	}
	if e.Payload.Path != "/home/user/project/README.md" {
		t.Fatalf("payload.path: got %q", e.Payload.Path)
	}
	got, ok := e.MatchTarget()
	if !ok || got != "/home/user/project/README.md" {
		t.Fatalf("MatchTarget: ok=%v got=%q", ok, got)
	}
}

func TestMatchTargetUnsupportedActionIgnored(t *testing.T) {
	cases := []struct {
		name       string
		actionType string
		payload    string
	}{
		{"session_start", "session_start", `{}`},
		{"tool_use with command", "tool_use", `{"command": "ignored"}`},
		{"network_request with path", "network_request", `{"path": "/ignored"}`},
		{"empty action", "", `{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := `{"action_type":"` + tc.actionType + `","payload":` + tc.payload + `}`
			var e Event
			if err := json.Unmarshal([]byte(raw), &e); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			got, ok := e.MatchTarget()
			if ok || got != "" {
				t.Fatalf("MatchTarget: want ok=false and empty string, got ok=%v got=%q", ok, got)
			}
		})
	}
}

func TestMatchTargetEmptyTargetNoMatch(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"command_exec missing command", `{"action_type":"command_exec","payload":{}}`},
		{"command_exec empty command", `{"action_type":"command_exec","payload":{"command":""}}`},
		{"command_exec whitespace command", `{"action_type":"command_exec","payload":{"command":"  \t "}}`},
		{"file_read missing path", `{"action_type":"file_read","payload":{}}`},
		{"file_read empty path", `{"action_type":"file_read","payload":{"path":""}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var e Event
			if err := json.Unmarshal([]byte(tc.raw), &e); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			got, ok := e.MatchTarget()
			if ok || got != "" {
				t.Fatalf("MatchTarget: want ok=false, got ok=%v got=%q", ok, got)
			}
		})
	}
}
