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

	// Probe both known Dependabot config filenames. A clean 404 on every path
	// means the config is genuinely absent; an indeterminate error (timeout,
	// rate limit, 5xx) means we could not determine presence, which is recorded
	// as Unknown + a scan warning rather than silently reported as Missing.
	var indeterminateErr error
	for _, path := range []string{defaultDependabotPath, ".github/dependabot.yaml"} {
		if dbg != nil {
			dbg(repoFull, "GET /repos/"+repoFull+"/contents/"+path)
		}
		fileContent, _, _, err := c.client.Repositories.GetContents(ctx, owner, repo, path, nil)
		if err == nil {
			facts.Path = path
			if dbg != nil {
				dbg(repoFull, "found dependabot config at "+path)
			}
			parseDependabotContent(&facts, fileContent, dbg, repoFull)
			return facts
		}
		if indeterminate(err) {
			indeterminateErr = err
		}
		if dbg != nil {
			dbg(repoFull, "dependabot config not found at "+path)
		}
	}

	if indeterminateErr != nil {
		facts.Unknown = true
		c.addWarning("dependabot config", describeFetchError(indeterminateErr))
		if dbg != nil {
			dbg(repoFull, "dependabot config could not be determined: "+describeFetchError(indeterminateErr))
		}
		return facts
	}

	facts.Missing = true
	if dbg != nil {
		dbg(repoFull, "no dependabot config found — missing=true")
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

	var indeterminateErr error
	for _, path := range renovateConfigPaths {
		if dbg != nil {
			dbg(repoFull, "GET /repos/"+repoFull+"/contents/"+path)
		}
		fileContent, _, _, err := c.client.Repositories.GetContents(ctx, owner, repo, path, nil)
		if err != nil {
			// Keep probing the remaining paths even after an indeterminate
			// error: a later path may still locate the config. Only if none is
			// found do we fall back to Unknown below.
			if indeterminate(err) {
				indeterminateErr = err
			}
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

	if indeterminateErr != nil {
		facts.Unknown = true
		c.addWarning("renovate config", describeFetchError(indeterminateErr))
		if dbg != nil {
			dbg(repoFull, "renovate config could not be determined: "+describeFetchError(indeterminateErr))
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

	if actionsPinningState(dep, ren) != actionsPinningNotConfigured {
		return nil
	}

	msg := ruleMessage(ruleNameUpdateToolActionsPinning, "not-pinning", nil)
	return []Finding{{
		ID:          findingIDActionsNotPinning,
		Severity:    SeverityMedium,
		Title:       msg.Title,
		Description: msg.Description,
		File:        updateToolFilePath(dep, ren),
		Remediation: msg.Fix,
	}}
}

// actionsPinningState is the shared verdict for the update-tool-actions-pinning
// rule, used by both the finding path and the success path so the two can never
// disagree about what "pinning is configured" means.
type actionsPinningVerdict int

const (
	// actionsPinningNotApplicable means no configured update tool covers the
	// github-actions ecosystem, so there is nothing to keep pinned. The
	// update-tool-configuration rule already reports that absence; this rule
	// stays silent rather than double-reporting it.
	actionsPinningNotApplicable actionsPinningVerdict = iota
	// actionsPinningConfigured means at least one tool will keep GitHub Action
	// SHAs current.
	actionsPinningConfigured
	// actionsPinningNotConfigured means a tool covers github-actions but
	// nothing will maintain SHA pins.
	actionsPinningNotConfigured
)

// actionsPinningState decides whether the repository's update tooling will keep
// GitHub Action SHA pins current.
//
// Either tool can satisfy this, for different reasons:
//
//   - Dependabot has no pinning option at all; it preserves whatever reference
//     style a workflow already uses. A github-actions entry is therefore
//     sufficient here — on a SHA-pinned repository Dependabot keeps the SHAs
//     moving. Whether the workflows are pinned in the first place is the
//     action-version-pinning rule's job, and this rule deliberately does not
//     depend on that rule's outcome; rules stand alone.
//   - Renovate does have an explicit option, so it satisfies this rule only
//     when digest pinning is actually enabled.
func actionsPinningState(dep DependabotFacts, ren RenovateFacts) actionsPinningVerdict {
	depOK := !dep.Missing && dep.Invalid == nil && dep.Config != nil
	renOK := !ren.Missing && ren.Invalid == nil && ren.Config != nil

	depCoversActions := depOK && dependabotCoversActions(dep.Config)
	renCoversActions := renOK && renovateCoversActions(ren.Config)

	if !depCoversActions && !renCoversActions {
		return actionsPinningNotApplicable
	}
	if depCoversActions {
		return actionsPinningConfigured
	}
	if renovatePinningConfigured(ren.Config) {
		return actionsPinningConfigured
	}
	return actionsPinningNotConfigured
}

// renovateActionPinningPresets lists the built-in Renovate presets that enable
// GitHub Action digest pinning, either directly or by extending a preset that
// does.
//
// Renovate presets inherit, and this scanner does not fetch and expand preset
// definitions at scan time — doing so would mean network calls to Renovate's
// preset registry on every scan. Instead the small set of built-ins that imply
// action pinning is listed here explicitly.
//
// `config:best-practices` is the one that matters in practice: it is Renovate's
// own recommended starting configuration and it extends
// `helpers:pinGitHubActionDigests`. Matching only the literal helper names
// meant every repository using the recommended config was reported as not
// pinning, which was exactly backwards.
//
// Source of truth: https://docs.renovatebot.com/presets-config/ — re-check this
// list when Renovate changes its built-in preset definitions.
// renovatePresetBestPractices is Renovate's recommended starting configuration.
// It extends helpers:pinGitHubActionDigests, which is why it counts as pinning.
const renovatePresetBestPractices = "config:best-practices"

var renovateActionPinningPresets = map[string]bool{
	"helpers:pinGitHubActionDigests":         true,
	"helpers:pinGitHubActionDigestsToSemver": true,
	renovatePresetBestPractices:              true,
}

// renovatePinningConfigured returns true when:
//   - the top-level pinDigests is true, OR
//   - extends includes a preset that enables GitHub Action digest pinning
//     (directly or transitively — see renovateActionPinningPresets), OR
//   - any packageRules entry has pinDigests: true
//
// Known limitation: a custom or remote preset (`github>org/renovate-config`,
// `local>org/preset`) cannot be resolved without fetching it, so a repository
// that enables pinning only inside such a preset is still reported as not
// pinning. Treating unresolvable presets as "probably pinning" would turn a
// false positive into a false negative, which is the worse failure for a
// security scanner, so the conservative direction is kept deliberately.
func renovatePinningConfigured(cfg *RenovateConfig) bool {
	if cfg.PinDigests {
		return true
	}
	for _, preset := range cfg.Extends {
		if renovateActionPinningPresets[preset] {
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
