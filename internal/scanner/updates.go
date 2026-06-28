package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-github/v84/github"
	"github.com/tailscale/hujson"
	"gopkg.in/yaml.v3"
)

const (
	packageEcosystemGitHubActions = "github-actions"
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
	defaultRenovatePath,
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
		Path:         defaultDependabotPath,
		HasWorkflows: hasWorkflows,
	}

	if dbg != nil {
		dbg(repoFull, "GET /repos/"+repoFull+"/contents/"+defaultDependabotPath)
	}
	fileContent, _, _, err := c.client.Repositories.GetContents(ctx, owner, repo, defaultDependabotPath, nil)
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
	} else if dbg != nil {
		dbg(repoFull, "found dependabot config at .github/dependabot.yml")
	}

	if err != nil {
		facts.Missing = true
		if dbg != nil {
			dbg(repoFull, "no dependabot config found — missing=true")
		}
	} else {
		parseDependabotContent(&facts, fileContent, dbg, repoFull)
	}

	return facts
}

// parseDependabotContent decodes and parses a Dependabot config file into facts.
func parseDependabotContent(facts *DependabotFacts, fileContent *github.RepositoryContent, dbg DebugLogger, repoFull string) {
	content, err := decodeContent(fileContent)
	if err != nil {
		return
	}
	facts.Content = content
	var config DependabotConfig
	if err := yaml.Unmarshal([]byte(content), &config); err != nil {
		facts.Invalid = err
		if dbg != nil {
			dbg(repoFull, "dependabot config parse error: "+err.Error())
		}
		return
	}
	facts.Config = &config
	coversActions := dependabotCoversActions(&config)
	if dbg != nil {
		dbg(repoFull, fmt.Sprintf("dependabot config parsed: %d update entries, covers-actions=%v", len(config.Updates), coversActions))
	}
	for _, u := range config.Updates {
		if u.PackageEcosystem == packageEcosystemGitHubActions && dbg != nil {
			dbg(repoFull, fmt.Sprintf("dependabot github-actions entry: cooldown=%v", u.Cooldown != nil))
		}
	}
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
	dep := facts.Dependabot
	ren := facts.Renovate

	// Honour require_workflows option — skip entirely if no workflows
	if facts.UpdateToolConfigurationRequireWorkflows && !dep.HasWorkflows {
		return nil
	}

	depOK := !dep.Missing && dep.Invalid == nil && dep.Config != nil
	renOK := !ren.Missing && ren.Invalid == nil && ren.Config != nil

	// --- neither tool is configured ---
	if dep.Missing && ren.Missing {
		msg := ruleMessage(ruleNameUpdateToolConfiguration, "no-tool", nil)
		return []Finding{{
			ID:          findingIDNoUpdateTool,
			Severity:    SeverityMedium,
			Title:       msg.Title,
			Description: msg.Description,
			File:        defaultDependabotPath,
			Remediation: msg.Fix,
		}}
	}

	// --- invalid configs (only report if the other tool is not valid) ---
	if findings := collectInvalidConfigFindings(dep, ren, depOK, renOK); len(findings) > 0 {
		return findings
	}

	// If neither config is valid at this point, nothing more to check.
	if !depOK && !renOK {
		return nil
	}

	// --- github-actions coverage check ---
	return checkActionsCoverage(dep, ren, depOK, renOK)
}

// collectInvalidConfigFindings reports parse errors for Dependabot and/or Renovate,
// but only when the sibling tool is also not valid (to avoid double-reporting).
func collectInvalidConfigFindings(dep DependabotFacts, ren RenovateFacts, depOK, renOK bool) []Finding {
	var findings []Finding
	if dep.Invalid != nil && !renOK {
		msg := ruleMessage(ruleNameUpdateToolConfiguration, "invalid-dependabot", map[string]string{"Err": fmt.Sprintf("%v", dep.Invalid)})
		findings = append(findings, Finding{
			ID:          findingIDInvalidDependabot,
			Severity:    SeverityMedium,
			Title:       msg.Title,
			Description: msg.Description,
			File:        dep.Path,
			Remediation: msg.Fix,
		})
	}
	if ren.Invalid != nil && !depOK {
		msg := ruleMessage(ruleNameUpdateToolConfiguration, "invalid-renovate", map[string]string{"Err": fmt.Sprintf("%v", ren.Invalid)})
		findings = append(findings, Finding{
			ID:          "invalid-renovate",
			Severity:    SeverityMedium,
			Title:       msg.Title,
			Description: msg.Description,
			File:        ren.Path,
			Remediation: msg.Fix,
		})
	}
	return findings
}

// checkActionsCoverage checks whether at least one valid update tool covers the
// github-actions ecosystem. Returns an empty slice (nil) if workflows are absent
// or if coverage is already provided.
func checkActionsCoverage(dep DependabotFacts, ren RenovateFacts, depOK, renOK bool) []Finding {
	if !dep.HasWorkflows {
		return nil
	}
	depCoversActions := depOK && dependabotCoversActions(dep.Config)
	renCoversActions := renOK && renovateCoversActions(ren.Config)
	if !depCoversActions && !renCoversActions {
		return []Finding{buildMissingActionsFinding(dep, ren, depOK, renOK)}
	}
	return nil
}

// buildMissingActionsFinding constructs the finding for when no update tool covers GitHub Actions.
func buildMissingActionsFinding(dep DependabotFacts, ren RenovateFacts, depOK, renOK bool) Finding {
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

	msg := ruleMessage(ruleNameUpdateToolConfiguration, "missing-actions", map[string]string{"Tool": toolDesc})
	return Finding{
		ID:          findingIDMissingActionsUpdateTool,
		Severity:    SeverityMedium,
		Title:       msg.Title,
		Description: msg.Description,
		File:        updateToolFilePath(dep, ren),
		Remediation: msg.Fix,
	}
}

// dependabotCoversActions returns true when the Dependabot config has a
// github-actions ecosystem entry.
func dependabotCoversActions(cfg *DependabotConfig) bool {
	for _, u := range cfg.Updates {
		if u.PackageEcosystem == packageEcosystemGitHubActions {
			return true
		}
	}
	return false
}

// renovateCoversActions returns true when Renovate is configured (or
// auto-configured) to manage GitHub Actions updates.
//
// Renovate enables all managers by default when enabledManagers is absent or
// empty. If the field is explicitly set, packageEcosystemGitHubActions must appear in it.
func renovateCoversActions(cfg *RenovateConfig) bool {
	if len(cfg.EnabledManagers) == 0 {
		return true // auto-enabled
	}
	for _, m := range cfg.EnabledManagers {
		if strings.EqualFold(m, packageEcosystemGitHubActions) {
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

	msg := ruleMessage(ruleNameUpdateToolActionsCooldown, "missing-cooldown", nil)
	return []Finding{{
		ID:          findingIDMissingActionsCooldown,
		Severity:    SeverityLow,
		Title:       msg.Title,
		Description: msg.Description,
		File:        updateToolFilePath(dep, ren),
		Remediation: msg.Fix,
	}}
}

// dependabotActionsCooldownConfigured returns true when the Dependabot config
// has a github-actions entry with a cooldown block.
func dependabotActionsCooldownConfigured(cfg *DependabotConfig) bool {
	for _, u := range cfg.Updates {
		if u.PackageEcosystem == packageEcosystemGitHubActions && u.Cooldown != nil {
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

	msg := ruleMessage(ruleNameUpdateToolActionsPinning, "not-pinning", nil)
	return []Finding{{
		ID:          "update-tool-actions-not-pinning",
		Severity:    SeverityMedium,
		Title:       msg.Title,
		Description: msg.Description,
		File:        updateToolFilePath(dep, ren),
		Remediation: msg.Fix,
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
	return defaultDependabotPath
}
