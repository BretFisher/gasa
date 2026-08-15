package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

var defaultConfigNames = []string{".gasa.yml", ".gasa.yaml"}

type Config struct {
	Rules        ConfigRules       `yaml:"rules"`
	RuleOptions  ConfigRuleOptions `yaml:"rule_options"`
	Overrides    []RuleOverride    `yaml:"overrides"`
	Suppressions []RuleSuppression `yaml:"suppressions"`
}

type ConfigRules struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

type ConfigRuleOptions struct {
	ActionVersionPinning    ActionVersionPinningRuleOptions    `yaml:"workflows/action-version-pinning"`
	UpdateToolConfiguration UpdateToolConfigurationRuleOptions `yaml:"updates/update-tool-configuration"`
}

type ActionVersionPinningRuleOptions struct {
	// IgnoreSameOwner ignores every same-owner mutable ref — actions and
	// reusable workflows alike. Legacy switch kept as shorthand for enabling
	// both narrower options below at once.
	IgnoreSameOwner bool `yaml:"ignore_same_owner"`
	// IgnoreSameOwnerActions ignores mutable refs to actions whose owner
	// matches the repository owner being scanned.
	IgnoreSameOwnerActions bool `yaml:"ignore_same_owner_actions"`
	// IgnoreSameOwnerReusableWorkflows ignores mutable refs to reusable
	// workflow calls (jobs.<id>.uses) whose owner matches the repository
	// owner being scanned.
	IgnoreSameOwnerReusableWorkflows bool `yaml:"ignore_same_owner_reusable_workflows"`
}

type UpdateToolConfigurationRuleOptions struct {
	RequireWorkflows bool `yaml:"require_workflows"`
}

type RuleOverride struct {
	Rule     string `yaml:"rule"`
	Severity string `yaml:"severity"`
}

type RuleSuppression struct {
	Rule      string `yaml:"rule"`
	FindingID string `yaml:"finding_id"`
	Path      string `yaml:"path"`
	Reason    string `yaml:"reason"`
}

func DiscoverConfigPath(dir string) (string, error) {
	for _, name := range defaultConfigNames {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
	}
	return "", nil
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &cfg, nil
}

func LoadConfigFromDir(dir string) (*Config, string, error) {
	path, err := DiscoverConfigPath(dir)
	if err != nil {
		return nil, "", err
	}
	if path == "" {
		return nil, "", nil
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		return nil, "", err
	}
	return cfg, path, nil
}

func (c *Config) severityOverride(ruleName string) string {
	if c == nil {
		return ""
	}
	for _, override := range c.Overrides {
		if override.Rule == ruleName {
			return override.Severity
		}
	}
	return ""
}

func (c *Config) suppressesFinding(f Finding) bool {
	if c == nil {
		return false
	}
	for _, suppression := range c.Suppressions {
		if suppression.Rule != "" && suppression.Rule != f.Rule {
			continue
		}
		if suppression.FindingID != "" && suppression.FindingID != f.ID {
			continue
		}
		if suppression.Path != "" && suppression.Path != f.File {
			continue
		}
		return true
	}
	return false
}

func (c *Config) actionVersionPinningIgnoreSameOwnerActions() bool {
	if c == nil {
		return false
	}
	opts := c.RuleOptions.ActionVersionPinning
	return opts.IgnoreSameOwner || opts.IgnoreSameOwnerActions
}

func (c *Config) actionVersionPinningIgnoreSameOwnerReusableWorkflows() bool {
	if c == nil {
		return false
	}
	opts := c.RuleOptions.ActionVersionPinning
	return opts.IgnoreSameOwner || opts.IgnoreSameOwnerReusableWorkflows
}

func (c *Config) updateToolConfigurationRequireWorkflows() bool {
	if c == nil {
		return false
	}
	return c.RuleOptions.UpdateToolConfiguration.RequireWorkflows
}
