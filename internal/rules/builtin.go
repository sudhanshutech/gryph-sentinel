package rules

var builtinRules = []Rule{
	{
		Name:        "credential-exfiltration",
		Description: "curl uploading a sensitive file to an external server",
		ActionType:  "command_exec",
		Pattern:     `curl.*(--upload-file|-T|--data-binary).*(\.env|\.pem|credentials)`,
		Severity:    "critical",
	},
	{
		Name:        "outbound-data-transfer",
		Description: "curl or wget making outbound requests",
		ActionType:  "command_exec",
		Pattern:     `(curl|wget).*(https?://)`,
		Severity:    "medium",
	},
	{
		Name:        "shell-pipe-execute",
		Description: "downloading and piping directly to a shell interpreter",
		ActionType:  "command_exec",
		Pattern:     `(curl|wget).*\|\s*(bash|sh|zsh|python|python3)`,
		Severity:    "critical",
	},
	{
		Name:        "destructive-remove",
		Description: "rm -rf on broad or root paths",
		ActionType:  "command_exec",
		Pattern:     `rm\s+-rf\s+(\/|~|\$HOME|\.$|\./$|\.\.$|\.\./)`,
		Severity:    "critical",
	},
	{
		Name:        "privilege-escalation",
		Description: "sudo command execution",
		ActionType:  "command_exec",
		Pattern:     `^sudo\s+`,
		Severity:    "high",
	},
	{
		Name:        "persistence-cron",
		Description: "crontab modification by agent",
		ActionType:  "command_exec",
		Pattern:     `crontab\s+-e`,
		Severity:    "high",
	},
	{
		Name:        "persistence-systemd",
		Description: "systemd service enable or start",
		ActionType:  "command_exec",
		Pattern:     `systemctl\s+(enable|start|daemon-reload)`,
		Severity:    "high",
	},
	{
		Name:        "netcat-usage",
		Description: "netcat - commonly used for exfiltration or reverse shells",
		ActionType:  "command_exec",
		Pattern:     `\bnc\b.*(-e|-c|/bin/sh|/bin/bash)`,
		Severity:    "critical",
	},
	{
		Name:        "sensitive-file-read",
		Description: "agent read a file containing credentials or secrets",
		ActionType:  "file_read",
		Pattern:     `(\.env$|\.pem$|\.key$|id_rsa$|id_ed25519$|credentials$|\.aws/|\.ssh/)`,
		Severity:    "high",
	},
	{
		Name:        "sensitive-file-write",
		Description: "agent wrote to a sensitive path",
		ActionType:  "file_write",
		Pattern:     `(\.ssh/|\.aws/|/etc/passwd|/etc/hosts|\.bashrc$|\.zshrc$)`,
		Severity:    "critical",
	},
	{
		Name:        "sensitive-file-delete",
		Description: "agent deleted a sensitive file",
		ActionType:  "file_delete",
		Pattern:     `(\.env$|\.pem$|\.key$|id_rsa$|\.aws/|\.ssh/)`,
		Severity:    "critical",
	},
	{
		Name:        "crypto-wallet-access",
		Description: "agent accessed a cryptocurrency wallet file",
		ActionType:  "file_read",
		Pattern:     `(wallet\.dat$|keystore/|\.metamask/|\.bitcoin/)`,
		Severity:    "high",
	},
}

func BuiltinRules() []Rule {
	out := make([]Rule, len(builtinRules))
	copy(out, builtinRules)
	return out
}
