# gryph-sentinel Design

## Overview

`gryph-sentinel` is a standalone Go CLI that analyzes JSONL audit logs emitted by `gryph export` and produces a post-session security report. It focuses on fast, local-only analysis with zero required configuration, built-in rules, and an optional YAML rules file for extension.

The primary user workflow is:

```bash
gryph export --since 1h | gryph-sentinel analyze
```

Version 1 is intentionally scoped to offline analysis of completed sessions. It does not collect logs, monitor live activity, or enforce policy.

## Goals

- Detect suspicious agent activity from completed gryph sessions.
- Work as a composable stdin consumer in existing gryph pipelines.
- Ship usable built-in rules with no required setup.
- Support user-defined YAML rules merged with built-in rules.
- Produce clear terminal output with severity and session summary.
- Support machine-readable JSON output for automation and CI.
- Stay fast for typical sessions of a few hundred events.

## Non-Goals

- Replacing gryph logging, storage, or collection features.
- Real-time monitoring or long-running watch behavior.
- Cloud-based processing or data export.
- Blocking or preventing agent actions.
- Rich policy management such as per-rule suppression or override semantics.

## Recommended Architecture

V1 will use a thin CLI with focused internal packages:

- `cmd/sentinel/main.go`: parses arguments, runs the analyzer, renders output, and determines exit code.
- `internal/event`: owns gryph event decoding and extraction of rule match targets from event payloads.
- `internal/rules`: owns built-in rules, YAML loading, severity parsing, regex compilation, and per-event rule evaluation.
- `internal/analyzer`: streams stdin JSONL, filters events, collects findings, computes summaries, and derives overall session risk.
- `internal/report`: renders text and JSON output from a shared report model.
- `internal/notify`: sends desktop notifications on supported operating systems.

This structure keeps the entrypoint small and makes parsing, matching, and rendering independently testable.

## CLI Design

The top-level binary exposes an `analyze` subcommand.

Supported flags for `analyze`:

- `--rules string`: optional path to a custom `rules.yaml` file
- `--output string`: `text` or `json`, default `text`
- `--min-severity string`: `low`, `medium`, `high`, or `critical`, default `low`
- `--session string`: optional session ID filter
- `--fail-on string`: optional severity threshold that causes exit code `1`
- `--notify`: send a desktop notification when critical findings exist
- `--no-color`: disable ANSI color output in text reports

Exit codes:

- `0`: no findings at or above `--fail-on`, or `--fail-on` not set
- `1`: findings exist at or above `--fail-on`
- `2`: fatal error such as bad flags, unreadable custom rules, or regex compilation failure

## Analyzer Flow

The `analyze` command runs this sequence:

1. Parse flags and validate enum-like values such as output format and severities.
2. Load built-in rules.
3. If `--rules` is set, parse the YAML file and append those rules to the built-in set.
4. Compile all regex patterns before scanning input.
5. Read stdin line by line using a buffered scanner.
6. For each line:
   - Attempt to decode a gryph event.
   - Skip malformed JSON lines and continue scanning.
   - Ignore action types outside the supported set.
   - Apply the optional session filter.
   - Extract the relevant match target from the payload.
   - Evaluate the event against all rules for the event action type.
7. Accumulate findings, severity counts, session metadata, and total event count.
8. Apply `--min-severity` filtering to the final rendered findings and summary.
9. Derive session risk level from the highest remaining finding severity.
10. Render the report in text or JSON.
11. Optionally send a notification if `--notify` is set and any critical finding remains after filtering.
12. Return the appropriate exit code based on `--fail-on`.

The scanner remains streaming and single-pass. Findings are accumulated in memory because the expected event count for V1 is modest and final summary rendering requires the collected results.

## Data Model

### Event

The event package will define a typed subset of the gryph schema containing the fields required by V1:

- `id`
- `session_id`
- `agent_session_id`
- `sequence`
- `timestamp`
- `agent_name`
- `action_type`
- `result_status`
- `is_sensitive`
- `tool_name`
- `working_directory`
- `payload.command`
- `payload.path`
- `payload.exit_code`
- `payload.output`

The implementation should tolerate missing payload fields without failing the scan.

### Rule

Each rule will contain:

- `name`
- `description`
- `action_type`
- `pattern`
- `severity`

Compiled regular expressions remain internal implementation detail and are not exposed in JSON or YAML.

### Finding

Each finding will contain:

- rule name
- severity
- description
- action type
- matched value
- timestamp
- working directory
- event ID

### Report

The shared report model will include:

- session ID
- agent name
- total events scanned
- risk level
- list of findings after severity filtering
- summary counts by severity

## Rule Loading and Matching

Built-in rules are defined in Go so the binary works with no configuration.

Custom rule loading behavior for V1:

- Custom rules are optional.
- If supplied, they are appended to built-in rules.
- Rules are not deduplicated or overridden by name in V1.
- Invalid YAML or invalid regex patterns are fatal errors.

Event-to-match-target mapping:

- `command_exec` -> `payload.command`
- `file_read` -> `payload.path`
- `file_write` -> `payload.path`
- `file_delete` -> `payload.path`

Ignored action types:

- `session_start`
- `session_end`
- `notification`
- `tool_use`
- `network_request`
- `unknown`

Matching rules:

- Only rules for the current event action type are evaluated.
- An event may generate multiple findings if multiple rules match.
- Missing or empty match targets do not generate findings.
- Severity ordering is normalized as `low < medium < high < critical`.

## Risk Scoring

Overall session risk derives from the highest severity present after applying `--min-severity` filtering:

- any `critical` -> `CRITICAL`
- any `high` and no `critical` -> `HIGH`
- any `medium` and no higher findings -> `MEDIUM`
- only `low` findings -> `LOW`
- no findings -> `CLEAN`

This ensures both text and JSON outputs use the same risk logic.

## Output Design

### Text Output

The text renderer will follow the PRD layout closely:

- header banner
- top summary with agent, session, event count, findings count, and overall risk
- findings grouped and ordered by severity from highest to lowest
- footer summary with severity counts

Text mode will support colorized severity labels when color is enabled. If `--no-color` is set, or if output is not suitable for color, plain text is rendered.

When there are no findings after filtering, the renderer prints a concise success message including total event count.

### JSON Output

The JSON renderer will emit:

- `session_id`
- `agent_name`
- `total_events`
- `risk_level`
- `findings`
- `summary`

Field names and structure will match the PRD so downstream tooling can rely on stable output.

## Notification Design

Notifications are best-effort and limited to platforms in scope:

- macOS: invoke `osascript`
- Linux: invoke `notify-send` if available
- Windows: no notification support in V1

A notification failure does not fail the scan or change the exit code. It should be treated as a non-fatal best-effort feature.

## Error Handling

Fatal errors:

- invalid command-line values
- unreadable custom rules file
- malformed YAML in custom rules
- regex compilation failure
- unrecoverable stdin read errors

Non-fatal conditions:

- malformed JSON line in stdin
- missing optional event payload fields
- unsupported action types
- notification delivery failure

Malformed JSON lines are skipped to satisfy the requirement that the scanner continue processing incomplete or bad lines gracefully.

## Dependencies

V1 will use only:

- Go standard library
- `gopkg.in/yaml.v3` for YAML parsing
- `github.com/fatih/color` for optional text color output

No other runtime dependencies are required.

## Testing Strategy

Testing will emphasize deterministic unit coverage with realistic fixture data.

### Package tests

- `internal/event`
  - decode representative gryph JSONL events
  - tolerate missing payload fields
  - expose correct match targets for supported action types

- `internal/rules`
  - verify built-in rules produce expected true positives
  - verify representative clean commands and paths do not false-positive
  - verify YAML loading and merge behavior
  - verify severity parsing and threshold comparisons

- `internal/analyzer`
  - scan clean fixture input with zero findings
  - scan risky fixture input with multi-severity findings
  - verify `--session` filtering semantics
  - verify `--min-severity` filtering
  - verify `--fail-on` threshold evaluation
  - verify malformed JSON lines are skipped

- `internal/report`
  - verify text output contains expected sections and summaries
  - verify JSON output serializes the expected schema
  - verify no-findings rendering

- `cmd/sentinel`
  - verify CLI exit codes for clean vs risky input
  - verify invalid flag values return fatal exit code `2`

### Test fixtures

`testdata/` will include:

- `clean-session.jsonl`
- `risky-session.jsonl`

These fixtures should be small, realistic, and stable so tests remain deterministic across platforms.

## Build and Release

The project will provide:

- `make build`
- `make test`
- `make release`

Release builds target:

- macOS amd64
- macOS arm64
- Linux amd64
- Windows amd64

The resulting binaries are standalone and suitable for local CLI usage and CI environments.

## Implementation Notes

To keep V1 focused:

- the analyzer will not connect directly to gryph storage
- the rule engine will remain regex-based rather than introducing a policy DSL
- rule merging will be append-only rather than supporting suppression or override
- report rendering will be deterministic and not depend on terminal width detection

These choices minimize implementation risk while leaving room for V2 features such as watch mode, richer rule configuration, and external alert integrations.
