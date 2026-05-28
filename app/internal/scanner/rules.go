package scanner

import (
	"fmt"
	"strings"
)

type RuleInfo struct {
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases,omitempty"`
	Title       string   `json:"title"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
}

type rule struct {
	RuleInfo
	run func(*ScanFacts) []Finding
}

func availableRules() []rule {
	return []rule{
		{
			RuleInfo: RuleInfo{
				Name:        "workflows/pull-request-target",
				Aliases:     []string{"pull-request-target"},
				Title:       "Pull Request Target",
				Category:    "Workflows",
				Severity:    SeverityCritical,
				Description: "pull_request_target should not be used in public repos and is highly discouraged in private repos",
			},
			run: evaluateDangerousWorkflowRule,
		},
		{
			RuleInfo: RuleInfo{
				Name:        "workflows/action-version-pinning",
				Aliases:     []string{"action-version-pinning", "action-pinning", "pinning"},
				Title:       "Action Version Pinning",
				Category:    "Workflows",
				Severity:    SeverityHigh,
				Description: "actions referenced by tag or branch instead of a full commit SHA",
			},
			run: evaluateActionVersionPinningRule,
		},
		{
			RuleInfo: RuleInfo{
				Name:        "workflows/workflow-permissions",
				Aliases:     []string{"workflow-permissions", "permissions"},
				Title:       "Workflow Permissions",
				Category:    "Workflows",
				Severity:    SeverityHigh,
				Description: "workflows inherit broad default token permissions without explicit permissions blocks",
			},
			run: evaluateWorkflowPermissionsRule,
		},
		{
			RuleInfo: RuleInfo{
				Name:        "actions/permissions/allowed-actions-policy",
				Aliases:     []string{"allowed-actions-policy", "allowed-actions"},
				Title:       "Allowed Actions Policy",
				Category:    "Settings",
				Severity:    SeverityMedium,
				Description: "repository allows all actions instead of restricting to trusted sources",
			},
			run: evaluateAllowedActionsPolicyRule,
		},
		{
			RuleInfo: RuleInfo{
				Name:        "actions/permissions/workflow/default-workflow-permissions",
				Aliases:     []string{"default-workflow-permissions", "default-permissions"},
				Title:       "Default Workflow Permissions",
				Category:    "Settings",
				Severity:    SeverityHigh,
				Description: "repository default GITHUB_TOKEN is read-write instead of read-only",
			},
			run: evaluateDefaultWorkflowPermissionsRule,
		},
		{
			RuleInfo: RuleInfo{
				Name:        "actions/permissions/workflow/actions-can-approve-prs",
				Aliases:     []string{"actions-can-approve-prs", "approve-prs"},
				Title:       "Actions Can Approve PRs",
				Category:    "Settings",
				Severity:    SeverityMedium,
				Description: "workflows can create and approve pull request reviews",
			},
			run: evaluateActionsCanApprovePRsRule,
		},
		{
			RuleInfo: RuleInfo{
				Name:        "actions/permissions/fork-pr-contributor-approval",
				Aliases:     []string{"fork-pr-contributor-approval", "fork-pr-approval"},
				Title:       "Fork PR Workflow Approval",
				Category:    "Settings",
				Severity:    SeverityHigh,
				Description: "external contributors can trigger fork PR workflows without maintainer approval",
			},
			run: evaluateForkPRContributorApprovalRule,
		},
		{
			RuleInfo: RuleInfo{
				Name:        "updates/update-tool-configuration",
				Aliases:     []string{"update-tool-configuration", "update-tool"},
				Title:       "Update Tool Configuration",
				Category:    "Updates",
				Severity:    SeverityMedium,
				Description: "no dependency update tool configured (Dependabot or Renovate), invalid config, or missing github-actions coverage",
			},
			run: evaluateUpdateToolConfigurationRule,
		},
		{
			RuleInfo: RuleInfo{
				Name:        "updates/update-tool-actions-cooldown",
				Aliases:     []string{"update-tool-actions-cooldown", "actions-cooldown"},
				Title:       "Update Tool GitHub Actions Cooldown",
				Category:    "Updates",
				Severity:    SeverityLow,
				Description: "neither Dependabot nor Renovate sets a cooldown delay for github-actions updates, allowing immediate adoption of potentially malicious new releases",
			},
			run: evaluateUpdateToolActionsCooldownRule,
		},
		{
			RuleInfo: RuleInfo{
				Name:        "updates/update-tool-actions-pinning",
				Aliases:     []string{"update-tool-actions-pinning", "actions-pinning"},
				Title:       "Renovate GitHub Actions Pinning",
				Category:    "Updates",
				Severity:    SeverityMedium,
				Description: "Renovate is not configured to pin GitHub Actions to immutable commit SHAs (Dependabot has no equivalent option)",
			},
			run: evaluateUpdateToolActionsPinningRule,
		},
	}
}

func AvailableRules() []RuleInfo {
	rules := availableRules()
	out := make([]RuleInfo, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.RuleInfo)
	}
	return out
}

func ResolveRuleNames(names []string) ([]RuleInfo, error) {
	rules, err := resolveRules(names, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	out := make([]RuleInfo, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.RuleInfo)
	}
	return out, nil
}

func AvailableCategories() []string {
	seen := make(map[string]bool)
	var categories []string
	for _, r := range availableRules() {
		if !seen[r.Category] {
			seen[r.Category] = true
			categories = append(categories, r.Category)
		}
	}
	return categories
}

func resolveRules(ruleNames, categories, severities []string, cfg *Config) ([]rule, error) {
	rules, lookup, err := allRulesWithLookup(cfg)
	if err != nil {
		return nil, err
	}

	normalizedSeverities, err := normalizeSeverities(severities)
	if err != nil {
		return nil, err
	}

	selected, err := selectRules(ruleNames, categories, rules, lookup, cfg)
	if err != nil {
		return nil, err
	}

	if len(normalizedSeverities) == 0 {
		return selected, nil
	}

	return filterBySeverity(selected, normalizedSeverities, cfg)
}

func selectRules(ruleNames, categories []string, rules []rule, lookup map[string]rule, cfg *Config) ([]rule, error) {
	if len(ruleNames) > 0 {
		return resolveNamedRules(ruleNames, lookup)
	}
	if len(categories) > 0 {
		return filterByCategory(rules, categories)
	}
	return applyConfigRules(rules, lookup, cfg)
}

func applyConfigRules(rules []rule, lookup map[string]rule, cfg *Config) ([]rule, error) {
	if cfg == nil {
		return rules, nil
	}

	selected := rules
	if len(cfg.Rules.Include) > 0 {
		var err error
		selected, err = resolveNamedRules(cfg.Rules.Include, lookup)
		if err != nil {
			return nil, err
		}
	}

	if len(cfg.Rules.Exclude) > 0 {
		return excludeRules(selected, lookup, cfg.Rules.Exclude)
	}

	return selected, nil
}

func excludeRules(selected []rule, lookup map[string]rule, exclude []string) ([]rule, error) {
	excluded, err := resolveNamedRules(exclude, lookup)
	if err != nil {
		return nil, err
	}
	excludedSet := make(map[string]bool, len(excluded))
	for _, r := range excluded {
		excludedSet[r.Name] = true
	}

	filtered := make([]rule, 0, len(selected))
	for _, r := range selected {
		if !excludedSet[r.Name] {
			filtered = append(filtered, r)
		}
	}
	return filtered, nil
}

func allRulesWithLookup(_ *Config) ([]rule, map[string]rule, error) {
	rules := availableRules()

	lookup := make(map[string]rule, len(rules))
	for _, r := range rules {
		if _, exists := lookup[r.Name]; exists {
			return nil, nil, fmt.Errorf("duplicate rule %q", r.Name)
		}
		lookup[r.Name] = r
		for _, alias := range r.Aliases {
			if existing, exists := lookup[alias]; exists && existing.Name != r.Name {
				return nil, nil, fmt.Errorf("duplicate alias %q", alias)
			}
			lookup[alias] = r
		}
	}

	return rules, lookup, nil
}

func filterByCategory(rules []rule, categories []string) ([]rule, error) {
	categorySet := make(map[string]bool, len(categories))
	for _, c := range categories {
		categorySet[strings.ToLower(c)] = true
	}

	var filtered []rule
	for _, r := range rules {
		if categorySet[strings.ToLower(r.Category)] {
			filtered = append(filtered, r)
		}
	}

	if len(filtered) == 0 {
		return nil, fmt.Errorf("no rules found for categories: %s", strings.Join(categories, ", "))
	}

	return filtered, nil
}

func filterBySeverity(rules []rule, severities []string, cfg *Config) ([]rule, error) {
	severitySet := make(map[string]bool, len(severities))
	for _, severity := range severities {
		severitySet[severity] = true
	}

	filtered := make([]rule, 0, len(rules))
	for _, r := range rules {
		if severitySet[effectiveRuleSeverity(r, cfg)] {
			filtered = append(filtered, r)
		}
	}

	if len(filtered) == 0 {
		return nil, fmt.Errorf("no rules found for severities: %s", strings.Join(severities, ", "))
	}

	return filtered, nil
}

func effectiveRuleSeverity(r rule, cfg *Config) string {
	if cfg != nil {
		if override := normalizeSeverity(cfg.severityOverride(r.Name)); isValidSeverity(override) {
			return override
		}
	}
	return r.Severity
}

func buildRuleSuccessFinding(r rule, facts *ScanFacts, cfg *Config) *Finding {
	severity := effectiveRuleSeverity(r, cfg)

	switch r.Name {
	case "workflows/pull-request-target":
		return successFinding(r.Name, severity, "Workflow files", "SUCCESS pull_request_target event is not used", "No workflow uses `pull_request_target`, which avoids an event that should never be used in public repositories and is highly discouraged in private repositories.")
	case "workflows/action-version-pinning":
		return successFinding(r.Name, severity, "Workflow files", "SUCCESS Action versions are pinned safely", "All detected third-party actions are pinned to immutable commit SHAs instead of mutable tags or branches.")
	case "workflows/workflow-permissions":
		return successFinding(r.Name, severity, "Workflow files", "SUCCESS Workflow permissions are explicit", "All parsed workflows define explicit `permissions`, which avoids inheriting overly broad default token access.")
	case "actions/permissions/allowed-actions-policy":
		return allowedActionsSuccessFinding(r.Name, severity, facts)
	case "actions/permissions/workflow/default-workflow-permissions":
		return defaultWorkflowPermissionsSuccessFinding(r.Name, severity, facts)
	case "actions/permissions/workflow/actions-can-approve-prs":
		return actionsApprovePRsSuccessFinding(r.Name, severity, facts)
	case "actions/permissions/fork-pr-contributor-approval":
		return forkPRApprovalSuccessFinding(r.Name, severity, facts)
	case "updates/update-tool-configuration":
		return updateToolConfigurationSuccessFinding(r.Name, severity, facts)
	case "updates/update-tool-actions-cooldown":
		return updateToolActionsCooldownSuccessFinding(r.Name, severity, facts)
	case "updates/update-tool-actions-pinning":
		return updateToolActionsPinningSuccessFinding(r.Name, severity, facts)
	default:
		return successFinding(r.Name, severity, r.Category+" checks", "SUCCESS Rule passed", "This rule did not detect any matching insecure configuration in the repository.")
	}
}

func successFinding(ruleName, severity, location, title, description string) *Finding {
	return &Finding{
		ID:          "success-" + sanitizeID(ruleName),
		Rule:        ruleName,
		Category:    ruleCategory(ruleName),
		Severity:    severity,
		Success:     true,
		Title:       title,
		Description: description,
		Location:    location,
		Remediation: "No action needed.",
	}
}

func allowedActionsSuccessFinding(ruleName, severity string, facts *ScanFacts) *Finding {
	permissions := facts.ActionsSettings.Permissions
	if !actionsSettingsEnabled(facts) {
		return successFinding(ruleName, severity, "Repository Actions settings", "SUCCESS GitHub Actions are disabled for this repository", "GitHub Actions are disabled, so unrestricted third-party actions cannot run in this repository.")
	}
	if permissions == nil || permissions.AllowedActions == nil {
		return nil
	}
	switch *permissions.AllowedActions {
	case "local_only":
		return successFinding(ruleName, severity, "Repository Actions settings", "SUCCESS Allowed actions policy is tightly restricted", "Only actions defined inside this repository are allowed, which blocks third-party public actions entirely.")
	case "selected":
		return successFinding(ruleName, severity, "Repository Actions settings", "SUCCESS Allowed actions policy is restricted", "The repository does not allow all public actions by default, which limits execution to an approved set of trusted actions.")
	default:
		return nil
	}
}

func defaultWorkflowPermissionsSuccessFinding(ruleName, severity string, facts *ScanFacts) *Finding {
	if !actionsSettingsEnabled(facts) {
		return successFinding(ruleName, severity, "Repository Actions settings", "SUCCESS Default workflow permissions are safely constrained", "GitHub Actions are disabled for this repository, so workflows do not receive repository token permissions.")
	}
	perms := facts.ActionsSettings.DefaultWorkflowPermissions
	if perms == nil || perms.DefaultWorkflowPermissions == nil || *perms.DefaultWorkflowPermissions != "read" {
		return nil
	}
	return successFinding(ruleName, severity, "Repository Actions settings", "SUCCESS Default workflow permissions are read-only", "The repository default for `GITHUB_TOKEN` is read-only, which limits workflow access unless a workflow explicitly requests more.")
}

func actionsApprovePRsSuccessFinding(ruleName, severity string, facts *ScanFacts) *Finding {
	if !actionsSettingsEnabled(facts) {
		return successFinding(ruleName, severity, "Repository Actions settings", "SUCCESS GitHub Actions cannot approve pull requests here", "GitHub Actions are disabled for this repository, so workflows cannot create or approve pull request reviews.")
	}
	perms := facts.ActionsSettings.DefaultWorkflowPermissions
	if perms == nil || perms.CanApprovePullRequestReviews == nil || *perms.CanApprovePullRequestReviews {
		return nil
	}
	return successFinding(ruleName, severity, "Repository Actions settings", "SUCCESS GitHub Actions cannot approve pull requests", "The repository does not allow workflows to create and approve pull request reviews, which helps preserve human review controls.")
}

func forkPRApprovalSuccessFinding(ruleName, severity string, facts *ScanFacts) *Finding {
	if !actionsSettingsEnabled(facts) {
		return successFinding(ruleName, severity, "Repository Actions settings", "SUCCESS Fork pull request workflows are safely constrained", "GitHub Actions are disabled for this repository, so fork pull request workflows cannot run.")
	}
	policy := facts.ActionsSettings.ForkPRContributorApproval
	if policy == nil || policy.ApprovalPolicy != "all_external_contributors" {
		return nil
	}
	return successFinding(ruleName, severity, "Repository Actions settings", "SUCCESS Fork pull request workflows require full external approval", "Fork pull request workflows require approval from all external contributors before they can run, reducing the risk of untrusted code execution.")
}

func updateToolConfigurationSuccessFinding(ruleName, severity string, facts *ScanFacts) *Finding {
	dep := facts.Dependabot
	ren := facts.Renovate

	depOK := !dep.Missing && dep.Invalid == nil && dep.Config != nil
	renOK := !ren.Missing && ren.Invalid == nil && ren.Config != nil

	if !depOK && !renOK {
		return nil
	}

	// If workflows exist, at least one tool must cover github-actions
	if dep.HasWorkflows {
		depCoversActions := depOK && dependabotCoversActions(dep.Config)
		renCoversActions := renOK && renovateCoversActions(ren.Config)
		if !depCoversActions && !renCoversActions {
			return nil
		}
	}

	var toolNames []string
	if depOK {
		toolNames = append(toolNames, "Dependabot")
	}
	if renOK {
		toolNames = append(toolNames, "Renovate")
	}
	toolDesc := strings.Join(toolNames, " and ")
	return successFinding(ruleName, severity, "Dependency update tool configuration",
		"SUCCESS Dependency update tool is configured correctly",
		fmt.Sprintf("%s is configured with valid configuration and includes GitHub Actions updates when workflows are present.", toolDesc))
}

func updateToolActionsCooldownSuccessFinding(ruleName, severity string, facts *ScanFacts) *Finding {
	dep := facts.Dependabot
	ren := facts.Renovate

	depOK := !dep.Missing && dep.Invalid == nil && dep.Config != nil
	renOK := !ren.Missing && ren.Invalid == nil && ren.Config != nil

	if !depOK && !renOK {
		return nil
	}

	depHasCooldown := depOK && dependabotActionsCooldownConfigured(dep.Config)
	renHasCooldown := renOK && renovateCooldownConfigured(ren.Config)

	if !depHasCooldown && !renHasCooldown {
		return nil
	}

	return successFinding(ruleName, severity, "Dependency update tool configuration",
		"SUCCESS GitHub Actions update cooldown is configured",
		"A cooldown delay for GitHub Actions updates is configured, giving the community time to detect supply-chain attacks before a new version is automatically adopted.")
}

func updateToolActionsPinningSuccessFinding(ruleName, severity string, facts *ScanFacts) *Finding {
	ren := facts.Renovate
	renOK := !ren.Missing && ren.Invalid == nil && ren.Config != nil
	if !renOK || !renovateCoversActions(ren.Config) {
		return nil
	}
	if !renovatePinningConfigured(ren.Config) {
		return nil
	}

	return successFinding(ruleName, severity, "Dependency update tool configuration",
		"SUCCESS Renovate is configured to pin GitHub Actions to commit SHAs",
		"Renovate is configured to pin GitHub Actions to immutable commit SHAs, preventing compromised or re-tagged versions from introducing malicious code.")
}

func ruleCategory(ruleName string) string {
	switch {
	case strings.HasPrefix(ruleName, "workflows/"):
		return "Workflows"
	case strings.HasPrefix(ruleName, "actions/"):
		return "Settings"
	case strings.HasPrefix(ruleName, "updates/"):
		return "Updates"
	default:
		return ""
	}
}

func resolveNamedRules(names []string, lookup map[string]rule) ([]rule, error) {
	resolved := make([]rule, 0, len(names))
	seen := make(map[string]bool)
	for _, name := range names {
		r, ok := lookup[name]
		if !ok {
			return nil, fmt.Errorf("unknown rule %q", name)
		}
		if seen[r.Name] {
			continue
		}
		seen[r.Name] = true
		resolved = append(resolved, r)
	}
	return resolved, nil
}

func filterFindings(findings []Finding, keep func(Finding) bool) []Finding {
	filtered := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if keep(f) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func appendSettingsAccessFinding(findings []Finding, facts *ScanFacts) []Finding {
	if facts.ActionsSettings.AccessFinding == nil {
		return findings
	}
	return append(findings, *facts.ActionsSettings.AccessFinding)
}

func actionsSettingsEnabled(facts *ScanFacts) bool {
	permissions := facts.ActionsSettings.Permissions
	if permissions == nil {
		return false
	}
	return permissions.Enabled == nil || *permissions.Enabled
}

func evaluateDangerousWorkflowRule(facts *ScanFacts) []Finding {
	var findings []Finding
	for _, wf := range facts.Workflows {
		if !wf.Valid || !hasDangerousTrigger(wf.Workflow.On) {
			continue
		}
		findings = append(findings, Finding{
			ID:          fmt.Sprintf("dangerous-trigger-%s", wf.Path),
			Severity:    SeverityCritical,
			Title:       "pull_request_target event is used",
			Description: "This workflow uses `pull_request_target`. That event should never be used in a public repository and is highly discouraged in a private repository because it runs in the context of the base branch with access to a more trusted token and potentially secrets.",
			File:        wf.Path,
			Remediation: "Use the `pull_request` event instead. If you cannot avoid `pull_request_target`, keep the workflow limited to trusted base-branch code only and never check out or execute untrusted pull request code.",
			DocURL:      "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
		})
	}
	return findings
}

func shortActionName(name string) string {
	// Shorten "owner/repo/extra/path" to "owner/repo"
	parts := strings.SplitN(name, "/", 3)
	if len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return name
}

func evaluateActionVersionPinningRule(facts *ScanFacts) []Finding {
	var findings []Finding
	for _, wf := range facts.Workflows {
		actions := findUnpinnedActions(wf.Content)
		if wf.Valid && wf.Workflow != nil {
			actions = findUnpinnedActionsInWorkflow(wf.Workflow, wf.Content)
		}
		for _, action := range actions {
			if shouldIgnoreActionVersionPinning(action.name, facts) {
				continue
			}
			findings = append(findings, Finding{
				ID:       fmt.Sprintf("unpinned-%s-%s", wf.Path, sanitizeID(action.name)),
				Severity: SeverityHigh,
				Title:    fmt.Sprintf("Unpinned Action: %s", shortActionName(action.name)),
				Description: fmt.Sprintf("This action uses a mutable reference '%s'. "+
					"Tags and branches can be moved, potentially introducing malicious code.",
					action.version),
				File: wf.Path,
				Line: action.line,
				Remediation: fmt.Sprintf("Pin to a specific commit SHA instead of '%s'.",
					action.version),
				DocURL: "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
			})
		}
	}
	return findings
}

func shouldIgnoreActionVersionPinning(actionName string, facts *ScanFacts) bool {
	if facts == nil || !facts.ActionVersionPinningIgnoreSameOwner {
		return false
	}
	if strings.HasPrefix(actionName, "./") {
		return true
	}
	actionOwner, ok := actionRefOwner(actionName)
	if !ok {
		return false
	}
	return strings.EqualFold(actionOwner, facts.RepositoryOwner)
}

func actionRefOwner(actionName string) (string, bool) {
	if strings.HasPrefix(actionName, "./") || strings.HasPrefix(actionName, "docker://") {
		return "", false
	}
	parts := strings.Split(actionName, "/")
	if len(parts) < 2 || parts[0] == "" {
		return "", false
	}
	return parts[0], true
}

func evaluateWorkflowPermissionsRule(facts *ScanFacts) []Finding {
	var findings []Finding
	for _, wf := range facts.Workflows {
		if !wf.Valid || hasExplicitPermissions(wf.Workflow) {
			continue
		}
		findings = append(findings, Finding{
			ID:       fmt.Sprintf("no-permissions-%s", wf.Path),
			Severity: SeverityHigh,
			Title:    "No explicit permissions defined",
			Description: "This workflow does not define explicit permissions. It inherits default permissions " +
				"which may be overly broad (often read-write access to all scopes).",
			File: wf.Path,
			Remediation: "Add a 'permissions:' block at the workflow or job level with minimal required permissions. " +
				"Start with 'permissions: {}' (no permissions) and add only what's needed.",
			DocURL: "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token",
		})
	}
	return findings
}

func evaluateAllowedActionsPolicyRule(facts *ScanFacts) []Finding {
	findings := make([]Finding, 0)
	findings = appendSettingsAccessFinding(findings, facts)

	permissions := facts.ActionsSettings.Permissions
	if !actionsSettingsEnabled(facts) || permissions.AllowedActions == nil {
		return findings
	}

	if *permissions.AllowedActions == "all" {
		findings = append(findings, Finding{
			ID:          "settings-all-actions-allowed",
			Severity:    SeverityMedium,
			Title:       "All GitHub Actions are allowed",
			Description: "This repository allows all GitHub Actions to run without restriction. This means any public action can be used, including potentially malicious ones.",
			Remediation: "Restrict allowed actions to 'selected' and specify trusted action sources. Go to Settings > Actions > General > Actions permissions.",
			DocURL:      "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#allowing-select-actions-to-run",
		})
	}

	return findings
}

func evaluateDefaultWorkflowPermissionsRule(facts *ScanFacts) []Finding {
	findings := make([]Finding, 0)
	findings = appendSettingsAccessFinding(findings, facts)

	perms := facts.ActionsSettings.DefaultWorkflowPermissions
	if !actionsSettingsEnabled(facts) || perms == nil {
		return findings
	}

	if perms.DefaultWorkflowPermissions != nil && *perms.DefaultWorkflowPermissions == "write" {
		findings = append(findings, Finding{
			ID:          "settings-default-permissions-write",
			Severity:    SeverityHigh,
			Title:       "Default workflow permissions are read-write",
			Description: "The default GITHUB_TOKEN permissions for this repository are set to read-write. This gives all workflows broad write access to the repository unless explicitly restricted per-workflow.",
			Remediation: "WARNING: Before changing this setting, verify all workflows have explicit permissions blocks (see workflow-permissions rule). Changing to read-only will break workflows that need write access but don't explicitly define permissions. Once workflows are updated, set default workflow permissions to 'Read repository contents and packages permissions' in Settings > Actions > General > Workflow permissions.",
			DocURL:      "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#setting-the-permissions-of-the-github_token-for-your-repository",
		})
	}

	return findings
}

func evaluateActionsCanApprovePRsRule(facts *ScanFacts) []Finding {
	findings := make([]Finding, 0)
	findings = appendSettingsAccessFinding(findings, facts)

	perms := facts.ActionsSettings.DefaultWorkflowPermissions
	if !actionsSettingsEnabled(facts) || perms == nil || perms.CanApprovePullRequestReviews == nil || !*perms.CanApprovePullRequestReviews {
		return findings
	}

	findings = append(findings, Finding{
		ID:          "settings-actions-can-approve-prs",
		Severity:    SeverityMedium,
		Title:       "GitHub Actions can approve pull requests",
		Description: "GitHub Actions workflows are allowed to create and approve pull request reviews. This could be exploited to bypass required reviews.",
		Remediation: "Disable 'Allow GitHub Actions to create and approve pull requests' in Settings > Actions > General > Workflow permissions unless specifically needed.",
		DocURL:      "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository",
	})

	return findings
}

func evaluateForkPRContributorApprovalRule(facts *ScanFacts) []Finding {
	findings := make([]Finding, 0)
	findings = appendSettingsAccessFinding(findings, facts)

	policy := facts.ActionsSettings.ForkPRContributorApproval
	if !actionsSettingsEnabled(facts) || policy == nil || policy.ApprovalPolicy == "all_external_contributors" {
		return findings
	}

	findings = append(findings, Finding{
		ID:          "settings-fork-pr-contributor-approval-too-permissive",
		Severity:    SeverityHigh,
		Title:       "Fork PR workflows do not require approval from all external contributors",
		Description: "The repository's 'Approval for running fork pull request workflows from contributors' setting is less restrictive than 'Require approval for all external contributors'. Some external contributors can trigger workflows without a maintainer reviewing the run first.",
		Remediation: "Set 'Approval for running fork pull request workflows from contributors' to 'Require approval for all external contributors' in Settings > Actions > General > Fork pull request workflows from outside collaborators.",
		DocURL:      "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository",
	})

	return findings
}

func evaluateUpdateToolConfigurationRule(facts *ScanFacts) []Finding {
	return evaluateUpdateToolConfigurationFacts(facts)
}

func evaluateUpdateToolActionsCooldownRule(facts *ScanFacts) []Finding {
	return evaluateUpdateToolActionsCooldownFacts(facts)
}

func evaluateUpdateToolActionsPinningRule(facts *ScanFacts) []Finding {
	return evaluateUpdateToolActionsPinningFacts(facts)
}

func applyRuleConfig(findings []Finding, r rule, cfg *Config) []Finding {
	for i := range findings {
		findings[i].Rule = r.Name
		findings[i].Category = r.Category
		if override := effectiveRuleSeverity(r, cfg); override != "" {
			findings[i].Severity = override
		}
	}
	return findings
}

func applySuppressions(findings []Finding, cfg *Config) []Finding {
	if cfg == nil || len(cfg.Suppressions) == 0 {
		return findings
	}
	return filterFindings(findings, func(f Finding) bool {
		return !cfg.suppressesFinding(f)
	})
}
