package event

import "strings"

// Event is a typed subset of the gryph audit schema used for rule matching.
type Event struct {
	ID               string  `json:"id,omitempty"`
	SessionID        string  `json:"session_id,omitempty"`
	AgentSessionID   string  `json:"agent_session_id,omitempty"`
	Sequence         int64   `json:"sequence,omitempty"`
	Timestamp        string  `json:"timestamp,omitempty"`
	AgentName        string  `json:"agent_name,omitempty"`
	ActionType       string  `json:"action_type"`
	ResultStatus     string  `json:"result_status,omitempty"`
	IsSensitive      bool    `json:"is_sensitive,omitempty"`
	ToolName         string  `json:"tool_name,omitempty"`
	WorkingDirectory string  `json:"working_directory,omitempty"`
	Payload          Payload `json:"payload"`
}

// Payload holds optional fields present on some action types.
type Payload struct {
	Command  string `json:"command,omitempty"`
	Path     string `json:"path,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	Output   string `json:"output,omitempty"`
}

// MatchTarget returns the string evaluated by rules for this event, if any.
// Unsupported action types, missing targets, and whitespace-only targets yield no match.
func (e Event) MatchTarget() (string, bool) {
	switch e.ActionType {
	case "command_exec":
		s := strings.TrimSpace(e.Payload.Command)
		if s == "" {
			return "", false
		}
		return s, true
	case "file_read", "file_write", "file_delete":
		s := strings.TrimSpace(e.Payload.Path)
		if s == "" {
			return "", false
		}
		return s, true
	default:
		return "", false
	}
}
