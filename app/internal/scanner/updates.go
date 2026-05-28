package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tailscale/hujson"
	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Dependabot types
// ---------------------------------------------------------------------------

// DependabotConfig represents a dependabot.yml configuration
type DependabotConfig struct {
	Version int                `yaml:"version"`
	Updates []DependabotUpdate `yaml:"updates"`
}

// DependabotUpdate represents a single update configuration
type DependabotUpdate struct {
	PackageEcosystem string `yaml:"package-ecosystem"`
	Directory        string `yaml:"directory"`
	Schedule         struct {
		Interval string `yaml:"interval"`
	} `yaml:"schedule"`
	Cooldown              *DependabotCooldown `yaml:"cooldown"`
	OpenPullRequestsLimit int                 `yaml:"open-pull-requests-limit"`
}

type DependabotCooldown struct {
	DefaultDays int `yaml:"default-days"`
}

// ---------------------------------------------------------------------------
// Renovate types
// ---------------------------------------------------------------------------

// RenovateConfig represents a parsed Renovate configuration file.
// Only the fields relevant to our security checks are decoded.
type RenovateConfig struct {
	Extends         []string              `json:"extends"`
	EnabledManagers []string              `json:"enabledManagers"`
	PinDigests      bool                  `json:"pinDigests"`
	MinReleaseAge   string                `json:"minimumReleaseAge"`
	PackageRules    []RenovatePackageRule `json:"packageRules"`
}

// RenovatePackageRule represents one entry in Renovate's packageRules array.
type RenovatePackageRule struct {
	MatchManagers []string `json:"matchManagers"`
	MatchDepTypes []string `json:"matchDepTypes"`
	PinDigests    bool     `json:"pinDigests"`
	MinReleaseAge string   `json:"minimumReleaseAge"`
}

// renovateConfigPaths is the ordered list of file paths that Renovate checks,
// scoped to GitHub (GitLab paths included because a repo might use both).
var renovateConfigPaths = []string{
	"renovate.json",
	"renovate.json5",
	".github/renovate.json",
	".github/renovate.json5",
	".gitlab/renovate.json",
	".gitlab/renovate.json5",
	".renovaterc",
	".renovaterc.json",
	".renovaterc.json5",
}

func parseRenovateConfig(content string) (*RenovateConfig, error) {
	standardized, err := hujson.Standardize([]byte(content))
	if err != nil {
		return nil, err
	}

	var config RenovateConfig
	if err := json.Unmarshal(standardized, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// ---------------------------------------------------------------------------
// Fact collectors
// ---------------------------------------------------------------------------

func (c *factCollector) collectDependabotFacts(ctx context.Context, owner, repo string, hasWorkflows bool, dbg DebugLogger) DependabotFacts {
	repoFull := owner + "/" + repo
	facts := DependabotFacts{
		Path:         ".github/dependabot.yml",
		HasWorkflows: hasWorkflows,
	}

	if dbg != nil {
		dbg(repoFull, "GET /repos/"+repoFull+"/contents/.github/dependabot.yml")
	}
	fileContent, _, _, err := c.client.Repositories.GetContents(ctx, owner, repo, ".github/dependabot.yml", nil)
	if err != nil {
		if dbg != nil {
			dbg(repoFull, "dependabot.yml not found — trying dependabot.yaml")
		}
		fileContent, _, _, err = c.client.Repositories.GetContents(ctx, owner, repo, ".github/dependabot.yaml", nil)
		if err == nil {
			facts.Path = ".github/dependabot.yaml"
			if dbg != nil {
				dbg(repoFull, "found dependabot config at .github/dependabot.yaml")
			}
		}
	} else {
		if dbg != nil {
			dbg(repoFull, "found dependabot config at .github/dependabot.yml")
		}
	}

	if err != nil {
		facts.Missing = true
		if dbg != nil {
			dbg(repoFull, "no dependabot config found — missing=true")
		}
	} else {
		content, err := decodeContent(fileContent)
		if err == nil {
			facts.Content = content
			var config DependabotConfig
			if err := yaml.Unmarshal([]byte(content), &config); err != nil {
				facts.Invalid = err
				if dbg != nil {
					dbg(repoFull, "dependabot config parse error: "+err.Error())
				}
			} else {
				facts.Config = &config
				coversActions := dependabotCoversActions(&config)
				if dbg != nil {
					dbg(repoFull, fmt.Sprintf("dependabot config parsed: %d update entries, covers-actions=%v", len(config.Updates), coversActions))
				}
				for _, u := range config.Updates {
					if u.PackageEcosystem == "github-actions" && dbg != nil {
						dbg(repoFull, fmt.Sprintf("dependabot github-actions entry: cooldown=%v", u.Cooldown != nil))
					}
				}
			}
		}
	}

	return facts
}

func (c *factCollector) collectRenovateFacts(ctx context.Context, owner, repo string, hasWorkflows bool, dbg DebugLogger) RenovateFacts {
	repoFull := owner + "/" + repo
	facts := RenovateFacts{
		HasWorkflows: hasWorkflows,
	}

	for _, path := range renovateConfigPaths {
		if dbg != nil {
			dbg(repoFull, "GET /repos/"+repoFull+"/contents/"+path)
		}
		fileContent, _, _, err := c.client.Repositories.GetContents(ctx, owner, repo, path, nil)
		if err != nil {
			if dbg != nil {
				dbg(repoFull, "renovate config not found at "+path)
			}
			continue
		}

		content, err := decodeContent(fileContent)
		if err != nil {
			if dbg != nil {
				dbg(repoFull, "renovate config decode error at "+path+": "+err.Error())
			}
			continue
		}

		facts.Path = path
		facts.Content = content
		if dbg != nil {
			dbg(repoFull, "found renovate config at "+path)
		}

		config, err := parseRenovateConfig(content)
		if err != nil {
			facts.Invalid = fmt.Errorf("parse %s: %w", path, err)
			if dbg != nil {
				dbg(repoFull, "renovate config parse error: "+facts.Invalid.Error())
			}
		} else {
			facts.Config = config
			coversActions := renovateCoversActions(config)
			pinned := renovatePinningConfigured(config)
			hasCooldown := renovateCooldownConfigured(config)
			if dbg != nil {
				dbg(repoFull, fmt.Sprintf("renovate config parsed: covers-actions=%v pin-digests=%v cooldown=%v extends=%v",
					coversActions, pinned, hasCooldown, config.Extends))
			}
		}
		return facts
	}

	facts.Missing = true
	if dbg != nil {
		dbg(repoFull, "no renovate config found in any checked path — missing=true")
	}
	return facts
}

// ---------------------------------------------------------------------------
// Rule: updates/update-tool-configuration
// ---------------------------------------------------------------------------

func evaluateUpdateToolConfigurationFacts(facts *ScanFacts) []Finding {
	var findings []Finding

	dep := facts.Dependabot
	ren := facts.Renovate

	// Honour require_workflows option — skip entirely if no workflows
	if facts.UpdateToolConfigurationRequireWorkflows && !dep.HasWorkflows {
		return nil
	}

	hasWorkflows := dep.HasWorkflows // both facts carry the same value

	depOK := !dep.Missing && dep.Invalid == nil && dep.Config != nil
	renOK := !ren.Missing && ren.Invalid == nil && ren.Config != nil

	// --- neither tool is configured ---
	if dep.Missing && ren.Missing {
		return append(findings, Finding{
			ID:          "no-update-tool",
			Severity:    SeverityMedium,
			Title:       "No dependency update tool configured",
			Description: "This repository has neither a Dependabot configuration file nor a Renovate configuration file. Automated dependency update tooling keeps action versions and package dependencies current and helps catch vulnerable or malicious releases.",
			File:        ".github/dependabot.yml",
			Remediation: "Add a `.github/dependabot.yml` (Dependabot) or a `renovate.json` / `.github/renovate.json` (Renovate) to enable automated dependency updates.",
			DocURL:      "https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuring-dependabot-version-updates",
		})
	}

	// --- invalid configs (only report if the other tool is not valid) ---
	if dep.Invalid != nil && !renOK {
		findings = append(findings, Finding{
			ID:          "invalid-dependabot",
			Severity:    SeverityMedium,
			Title:       "Invalid Dependabot configuration",
			Description: fmt.Sprintf("The dependabot configuration file could not be parsed: %v", dep.Invalid),
			File:        dep.Path,
			Remediation: "Fix the YAML syntax in your dependabot.yml file.",
			DocURL:      "https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file",
		})
	}

	if ren.Invalid != nil && !depOK {
		findings = append(findings, Finding{
			ID:          "invalid-renovate",
			Severity:    SeverityMedium,
			Title:       "Invalid Renovate configuration",
			Description: fmt.Sprintf("The Renovate configuration file could not be parsed: %v", ren.Invalid),
			File:        ren.Path,
			Remediation: "Fix the JSON syntax in your Renovate configuration file.",
			DocURL:      "https://docs.renovatebot.com/configuration-options/",
		})
	}

	// If we already have parse errors and no valid tool, stop here.
	if len(findings) > 0 {
		return findings
	}

	// If neither config is valid at this point, nothing more to check.
	if !depOK && !renOK {
		return findings
	}

	// --- github-actions coverage check ---
	if !hasWorkflows {
		return findings
	}

	depCoversActions := depOK && dependabotCoversActions(dep.Config)
	renCoversActions := renOK && renovateCoversActions(ren.Config)

	if !depCoversActions && !renCoversActions {
		// Build a tool-aware remediation message
		var toolNames []string
		if depOK {
			toolNames = append(toolNames, "Dependabot")
		}
		if renOK {
			toolNames = append(toolNames, "Renovate")
		}
		toolDesc := strings.Join(toolNames, " and ")
		if toolDesc == "" {
			toolDesc = "your update tool"
		}

		findings = append(findings, Finding{
			ID:          "update-tool-missing-actions",
			Severity:    SeverityMedium,
			Title:       "Update tool not configured for GitHub Actions",
			Description: fmt.Sprintf("This repository has GitHub Actions workflows but %s is not configured to update them. Action versions will not be automatically kept up to date.", toolDesc),
			File:        updateToolFilePath(dep, ren),
			Remediation: "Configure your update tool to track the github-actions ecosystem.\n\n" +
				"Dependabot (.github/dependabot.yml):\n" +
				"  - package-ecosystem: \"github-actions\"\n" +
				"    directory: \"/\"\n" +
				"    schedule:\n" +
				"      interval: \"weekly\"\n\n" +
				"Renovate (renovate.json / .github/renovate.json):\n" +
				"  { \"enabledManagers\": [\"github-actions\"] }\n" +
				"  (or omit enabledManagers entirely — Renovate auto-detects github-actions)",
			DocURL: "https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#package-ecosystem",
		})
	}

	return findings
}

// dependabotCoversActions returns true when the Dependabot config has a
// github-actions ecosystem entry.
func dependabotCoversActions(cfg *DependabotConfig) bool {
	for _, u := range cfg.Updates {
		if u.PackageEcosystem == "github-actions" {
			return true
		}
	}
	return false
}

// renovateCoversActions returns true when Renovate is configured (or
// auto-configured) to manage GitHub Actions updates.
//
// Renovate enables all managers by default when enabledManagers is absent or
// empty. If the field is explicitly set, "github-actions" must appear in it.
func renovateCoversActions(cfg *RenovateConfig) bool {
	if len(cfg.EnabledManagers) == 0 {
		return true // auto-enabled
	}
	for _, m := range cfg.EnabledManagers {
		if strings.EqualFold(m, "github-actions") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Rule: updates/update-tool-actions-cooldown
// ---------------------------------------------------------------------------

func evaluateUpdateToolActionsCooldownFacts(facts *ScanFacts) []Finding {
	dep := facts.Dependabot
	ren := facts.Renovate

	depOK := !dep.Missing && dep.Invalid == nil && dep.Config != nil
	renOK := !ren.Missing && ren.Invalid == nil && ren.Config != nil

	// Skip entirely when no valid config exists (other rule handles that)
	if !depOK && !renOK {
		return nil
	}

	depHasCooldown := depOK && dependabotActionsCooldownConfigured(dep.Config)
	renHasCooldown := renOK && renovateCooldownConfigured(ren.Config)

	// Pass if either tool has cooldown configured
	if depHasCooldown || renHasCooldown {
		return nil
	}

	// Only emit a finding when at least one tool covers github-actions
	depCoversActions := depOK && dependabotCoversActions(dep.Config)
	renCoversActions := renOK && renovateCoversActions(ren.Config)
	if !depCoversActions && !renCoversActions {
		return nil
	}

	return []Finding{{
		ID:          "update-tool-actions-missing-cooldown",
		Severity:    SeverityLow,
		Title:       "Update tool does not set a cooldown for GitHub Actions updates",
		Description: "Neither Dependabot nor Renovate is configured with a cooldown delay for GitHub Actions updates. A cooldown gives the community time to detect supply-chain attacks before a new action version is automatically adopted.",
		File:        updateToolFilePath(dep, ren),
		Remediation: "Add a cooldown to your update tool configuration.\n\n" +
			"Dependabot (.github/dependabot.yml) — add to the github-actions entry:\n" +
			"  cooldown:\n" +
			"    default-days: 7\n\n" +
			"Renovate (renovate.json / .github/renovate.json) — add globally or in a packageRule:\n" +
			"  { \"minimumReleaseAge\": \"7 days\" }",
		DocURL: "https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#cooldown",
	}}
}

// dependabotActionsCooldownConfigured returns true when the Dependabot config
// has a github-actions entry with a cooldown block.
func dependabotActionsCooldownConfigured(cfg *DependabotConfig) bool {
	for _, u := range cfg.Updates {
		if u.PackageEcosystem == "github-actions" && u.Cooldown != nil {
			return true
		}
	}
	return false
}

// renovateCooldownConfigured returns true when minimumReleaseAge is set at the
// top level of the Renovate config OR in any packageRules entry.
func renovateCooldownConfigured(cfg *RenovateConfig) bool {
	if cfg.MinReleaseAge != "" {
		return true
	}
	for _, pr := range cfg.PackageRules {
		if pr.MinReleaseAge != "" {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Rule: updates/update-tool-actions-pinning
// ---------------------------------------------------------------------------

// Dependabot has no configuration option that pins GitHub Actions to commit
// SHAs (see dependabot/dependabot-core#7913). It preserves whatever pin style
// already exists in workflow files, so this rule can only meaningfully evaluate
// Renovate. For Dependabot-only repos, the workflow-level `action_pinning` rule
// is the source of truth.
func evaluateUpdateToolActionsPinningFacts(facts *ScanFacts) []Finding {
	dep := facts.Dependabot
	ren := facts.Renovate

	renOK := !ren.Missing && ren.Invalid == nil && ren.Config != nil
	if !renOK || !renovateCoversActions(ren.Config) {
		return nil
	}

	if renovatePinningConfigured(ren.Config) {
		return nil
	}

	return []Finding{{
		ID:          "update-tool-actions-not-pinning",
		Severity:    SeverityMedium,
		Title:       "Renovate not configured to pin GitHub Actions to commit SHAs",
		Description: "Renovate covers the github-actions ecosystem but is not configured to pin actions to immutable commit SHAs. Pinning to a SHA prevents a compromised or re-tagged action version from introducing malicious code into your workflows.",
		File:        updateToolFilePath(dep, ren),
		Remediation: "Enable digest pinning in Renovate (renovate.json / .github/renovate.json).\n\n" +
			"Top level:\n" +
			"  { \"pinDigests\": true }\n\n" +
			"Or via preset:\n" +
			"  { \"extends\": [\"helpers:pinGitHubActionDigests\"] }\n\n" +
			"Dependabot has no equivalent option (see https://github.com/dependabot/dependabot-core/issues/7913). For Dependabot-only repos, the action_pinning rule verifies workflow-level SHA pins directly.",
		DocURL: "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
	}}
}

// renovatePinningConfigured returns true when:
//   - the top-level pinDigests is true, OR
//   - extends includes helpers:pinGitHubActionDigests or helpers:pinGitHubActionDigestsToSemver, OR
//   - any packageRules entry has pinDigests: true
func renovatePinningConfigured(cfg *RenovateConfig) bool {
	if cfg.PinDigests {
		return true
	}
	for _, preset := range cfg.Extends {
		if preset == "helpers:pinGitHubActionDigests" || preset == "helpers:pinGitHubActionDigestsToSemver" {
			return true
		}
	}
	for _, pr := range cfg.PackageRules {
		if pr.PinDigests {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// updateToolFilePath returns the best file path to report in a finding — the
// Dependabot path if available, otherwise the Renovate path, otherwise a
// sensible default.
func updateToolFilePath(dep DependabotFacts, ren RenovateFacts) string {
	if !dep.Missing && dep.Path != "" {
		return dep.Path
	}
	if !ren.Missing && ren.Path != "" {
		return ren.Path
	}
	return ".github/dependabot.yml"
}
