package rules

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

func Load(path string) ([]CompiledRule, error) {
	all := BuiltinRules()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read rules file: %w", err)
		}

		var extra ruleFile
		if err := yaml.Unmarshal(data, &extra); err != nil {
			return nil, fmt.Errorf("parse rules file: %w", err)
		}

		all = append(all, extra.Rules...)
	}

	return compileRules(all)
}

func compileRules(rules []Rule) ([]CompiledRule, error) {
	compiled := make([]CompiledRule, 0, len(rules))
	for _, rule := range rules {
		sev, err := ParseSeverity(rule.Severity)
		if err != nil {
			return nil, fmt.Errorf("parse severity for rule %q: %w", rule.Name, err)
		}

		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile rule %q: %w", rule.Name, err)
		}

		rule.ActionType = strings.TrimSpace(rule.ActionType)
		rule.Severity = sev.String()

		compiled = append(compiled, CompiledRule{
			Rule:          rule,
			SeverityValue: sev,
			re:            re,
		})
	}

	return compiled, nil
}
