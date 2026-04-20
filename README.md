# gryph-sentinel

`gryph-sentinel` is a local Go CLI that analyzes `gryph export` JSONL audit logs, applies regex-based security rules, and prints a post-session risk report.

## Usage

Build the binary:

```bash
make build
```

Analyze a gryph export stream:

```bash
gryph export --since 1h | ./bin/gryph-sentinel analyze
```

Analyze a specific session and fail CI on critical findings:

```bash
gryph export --since 1h | ./bin/gryph-sentinel analyze --session abc123 --fail-on critical
```

Use JSON output:

```bash
gryph export --since 1h | ./bin/gryph-sentinel analyze --output json
```

Load extra custom rules:

```bash
gryph export --since 1h | ./bin/gryph-sentinel analyze --rules ./rules.yaml
```

## Flags

- `--rules string` optional path to a custom `rules.yaml`
- `--output string` `text` or `json` (default `text`)
- `--min-severity string` `low`, `medium`, `high`, or `critical` (default `low`)
- `--session string` filter to a specific session ID
- `--fail-on string` exit `1` if a finding at or above this severity exists
- `--notify` send a desktop notification for critical findings on macOS, Linux, Windows, and WSL (Windows fallback)
- `--no-color` disable colored text output

## Local Testing

Run the automated test suite:

```bash
make test
```

Run the scanner against the bundled fixtures:

```bash
cat testdata/clean-session.jsonl | ./bin/gryph-sentinel analyze --no-color
cat testdata/risky-session.jsonl | ./bin/gryph-sentinel analyze --no-color
cat testdata/risky-session.jsonl | ./bin/gryph-sentinel analyze --output json
cat testdata/risky-session.jsonl | ./bin/gryph-sentinel analyze --notify --no-color
```

On WSL, `--notify` first tries Linux `notify-send`. If no Linux desktop notification service is available, it falls back to a Windows notification path.

## Testing With gryph

If you already use `gryph`, the fastest end-to-end check is:

```bash
gryph export --since 1h | ./bin/gryph-sentinel analyze --no-color
```

If you want test data from the `gryph` repository itself, build or install `gryph` first, then export a recent session:

```bash
git clone https://github.com/safedep/gryph.git
cd gryph
go build ./cmd/gryph

# later, from your gryph-sentinel checkout
/path/to/gryph export --since 1h | ./bin/gryph-sentinel analyze --no-color
```

Useful checks:

```bash
/path/to/gryph export --since 1h | ./bin/gryph-sentinel analyze --fail-on critical
/path/to/gryph export --since 1h | ./bin/gryph-sentinel analyze --output json | jq .
/path/to/gryph export --since 1h | ./bin/gryph-sentinel analyze --rules ./rules.yaml
```

## Release Builds

Create release binaries for macOS, Linux, and Windows:

```bash
make release
```

