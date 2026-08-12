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
	// DocFile is the slug of this rule's page under docs/rules/ (without the
	// .md extension). It is the single source of truth that binds a rule to its
	// in-repo documentation; DocURL() turns it into a link for reports.
	DocFile string `json:"doc_file,omitempty"`
}

// docsBaseURL is where the rule markdown pages are published. Reports link here
// (the repo's own rule pages) rather than to external GitHub/Renovate docs; the
// external links live in each page's "References" section instead.
const docsBaseURL = "https://github.com/bretfisher/gasa/blob/main/docs/rules/"

// DocURL returns the absolute link to this rule's documentation page, or "" if
// the rule has no DocFile. An absolute URL is used (not a relative path) because
// the HTML report is a standalone file that may be opened or shared anywhere.
func (r RuleInfo) DocURL() string {
	if r.DocFile == "" {
		return ""
	}
	return docsBaseURL + r.DocFile + ".md"
}

type rule struct {
	RuleInfo
	run func(*ScanFacts) []Finding
}

// runFuncs binds each rule's stable name to its firing logic. This is the only
// rule "table" that stays in Go: metadata and report copy now come from the
// docs/rules/*.md front-matter registry, while the actual detection logic — the
// part that is genuinely code — lives here, keyed by the same name the
// front-matter declares.
var runFuncs = map[string]func(*ScanFacts) []Finding{
	ruleNamePullRequestTarget:          evaluateDangerousWorkflowRule,
	ruleNameActionVersionPinning:       evaluateActionVersionPinningRule,
	ruleNameWorkflowPermissions:        evaluateWorkflowPermissionsRule,
	ruleNameWriteAllPermissions:        evaluateWriteAllPermissionsRule,
	ruleNameAllowedActionsPolicy:       evaluateAllowedActionsPolicyRule,
	ruleNameDefaultWorkflowPermissions: evaluateDefaultWorkflowPermissionsRule,
	ruleNameActionsCanApprovePRs:       evaluateActionsCanApprovePRsRule,
	ruleNameForkPRContributorApproval:  evaluateForkPRContributorApprovalRule,
	ruleNameSHAPinningRequired:         evaluateSHAPinningRequiredRule,
	ruleNameUpdateToolConfiguration:    evaluateUpdateToolConfigurationRule,
	ruleNameUpdateToolActionsCooldown:  evaluateUpdateToolActionsCooldownRule,
	ruleNameUpdateToolActionsPinning:   evaluateUpdateToolActionsPinningRule,
}

// availableRules joins the loaded documentation (metadata, ordered by the
// front-matter `order` field) with the firing logic in runFuncs. A doc without
// a matching runFunc is skipped; TestRuleDocsCoverage guarantees that never
// happens for a shipped rule.
func availableRules() []rule {
	docs := loadedRuleDocs()
	out := make([]rule, 0, len(docs))
	for _, doc := range docs {
		runFn, ok := runFuncs[doc.Name]
		if !ok {
			continue
		}
		out = append(out, rule{
			RuleInfo: RuleInfo{
				Name:        doc.Name,
				Aliases:     doc.Aliases,
				Title:       doc.Title,
				Category:    doc.Category,
				Severity:    doc.Severity,
				Description: doc.Description,
				DocFile:     doc.DocFile,
			},
			run: runFn,
		})
	}
	return out
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
	finding := successFindingForRule(r, facts, cfg)
	// Stamp the rule's doc page onto passing checks too, so the HTML report
	// links every finding (success or not) back to its in-repo rule page.
	if finding != nil {
		finding.DocURL = r.DocURL()
	}
	return finding
}

func successFindingForRule(r rule, facts *ScanFacts, cfg *Config) *Finding {
	severity := effectiveRuleSeverity(r, cfg)

	switch r.Name {
	case ruleNamePullRequestTarget:
		return successMessage(r.Name, severity, "Workflow files", "pass", nil)
	case ruleNameActionVersionPinning:
		return successMessage(r.Name, severity, "Workflow files", "pass", nil)
	case ruleNameWorkflowPermissions:
		return successMessage(r.Name, severity, "Workflow files", "pass", nil)
	case ruleNameWriteAllPermissions:
		return successMessage(r.Name, severity, "Workflow files", "pass", nil)
	case ruleNameAllowedActionsPolicy:
		return allowedActionsSuccessFinding(r.Name, severity, facts)
	case ruleNameDefaultWorkflowPermissions:
		return defaultWorkflowPermissionsSuccessFinding(r.Name, severity, facts)
	case ruleNameActionsCanApprovePRs:
		return actionsApprovePRsSuccessFinding(r.Name, severity, facts)
	case ruleNameForkPRContributorApproval:
		return forkPRApprovalSuccessFinding(r.Name, severity, facts)
	case ruleNameSHAPinningRequired:
		return shaPinningRequiredSuccessFinding(r.Name, severity, facts)
	case ruleNameUpdateToolConfiguration:
		return updateToolConfigurationSuccessFinding(r.Name, severity, facts)
	case ruleNameUpdateToolActionsCooldown:
		return updateToolActionsCooldownSuccessFinding(r.Name, severity, facts)
	case ruleNameUpdateToolActionsPinning:
		return updateToolActionsPinningSuccessFinding(r.Name, severity, facts)
	default:
		return successFinding(r.Name, severity, r.Category+" checks", "Rule passed", "This rule did not detect any matching insecure configuration in the repository.")
	}
}

// successMessage renders a rule's pass message (`msgKey`) from front-matter and
// wraps it in a success Finding. Use this instead of successFinding when the
// copy lives in docs/rules/*.md (the normal case).
func successMessage(ruleName, severity, location, msgKey string, data any) *Finding {
	msg := ruleMessage(ruleName, msgKey, data)
	return successFinding(ruleName, severity, location, msg.Title, msg.Description)
}

func successFinding(ruleName, severity, location, title, description string) *Finding {
	return &Finding{
		ID:       "success-" + sanitizeID(ruleName),
		Rule:     ruleName,
		Category: ruleCategory(ruleName),
		Severity: severity,
		Success:  true,
		// The "SUCCESS " prefix is presentation, applied here rather than stored
		// in every front-matter pass title.
		Title:       "SUCCESS " + title,
		Description: description,
		Location:    location,
		Remediation: "No action needed.",
	}
}

func allowedActionsSuccessFinding(ruleName, severity string, facts *ScanFacts) *Finding {
	permissions := facts.ActionsSettings.Permissions
	if !actionsSettingsEnabled(facts) {
		if !actionsObservedDisabled(facts) {
			// The settings were never read. Claiming they are safely disabled
			// would invent an observation.
			return nil
		}
		return successMessage(ruleName, severity, "Repository Actions settings", "pass-disabled", nil)
	}
	if permissions == nil || permissions.AllowedActions == nil {
		return nil
	}
	switch *permissions.AllowedActions {
	case "local_only":
		return successMessage(ruleName, severity, "Repository Actions settings", "pass-local-only", nil)
	case actionsAllowedSelected:
		return successMessage(ruleName, severity, "Repository Actions settings", "pass-selected", nil)
	default:
		return nil
	}
}

func defaultWorkflowPermissionsSuccessFinding(ruleName, severity string, facts *ScanFacts) *Finding {
	if !actionsSettingsEnabled(facts) {
		if !actionsObservedDisabled(facts) {
			// The settings were never read. Claiming they are safely disabled
			// would invent an observation.
			return nil
		}
		return successMessage(ruleName, severity, "Repository Actions settings", "pass-disabled", nil)
	}
	perms := facts.ActionsSettings.DefaultWorkflowPermissions
	if perms == nil || perms.DefaultWorkflowPermissions == nil || *perms.DefaultWorkflowPermissions != permissionsRead {
		return nil
	}
	return successMessage(ruleName, severity, "Repository Actions settings", "pass-read", nil)
}

func actionsApprovePRsSuccessFinding(ruleName, severity string, facts *ScanFacts) *Finding {
	if !actionsSettingsEnabled(facts) {
		if !actionsObservedDisabled(facts) {
			// The settings were never read. Claiming they are safely disabled
			// would invent an observation.
			return nil
		}
		return successMessage(ruleName, severity, "Repository Actions settings", "pass-disabled", nil)
	}
	perms := facts.ActionsSettings.DefaultWorkflowPermissions
	if perms == nil || perms.CanApprovePullRequestReviews == nil || *perms.CanApprovePullRequestReviews {
		return nil
	}
	return successMessage(ruleName, severity, "Repository Actions settings", "pass-cannot-approve", nil)
}

func forkPRApprovalSuccessFinding(ruleName, severity string, facts *ScanFacts) *Finding {
	if !actionsSettingsEnabled(facts) {
		if !actionsObservedDisabled(facts) {
			// The settings were never read. Claiming they are safely disabled
			// would invent an observation.
			return nil
		}
		return successMessage(ruleName, severity, "Repository Actions settings", "pass-disabled", nil)
	}
	if facts.ActionsSettings.ForkPRApprovalNotApplicable {
		return successMessage(ruleName, severity, "Repository Actions settings", "pass-not-applicable", nil)
	}
	policy := facts.ActionsSettings.ForkPRContributorApproval
	if policy == nil || policy.ApprovalPolicy != forkPRApprovalAllExternal {
		return nil
	}
	return successMessage(ruleName, severity, "Repository Actions settings", "pass-all-external", nil)
}

func shaPinningRequiredSuccessFinding(ruleName, severity string, facts *ScanFacts) *Finding {
	if !actionsSettingsEnabled(facts) {
		if !actionsObservedDisabled(facts) {
			// The settings were never read. Claiming they are safely disabled
			// would invent an observation.
			return nil
		}
		return successMessage(ruleName, severity, "Repository Actions settings", "pass-disabled", nil)
	}
	permissions := facts.ActionsSettings.Permissions
	if permissions.SHAPinningRequired == nil || !*permissions.SHAPinningRequired {
		return nil
	}
	return successMessage(ruleName, severity, "Repository Actions settings", "pass", nil)
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
	return successMessage(ruleName, severity, "Dependency update tool configuration", "pass", map[string]string{"Tool": toolDesc})
}

func updateToolActionsCooldownSuccessFinding(ruleName, severity string, facts *ScanFacts) *Finding {
	dep := facts.Dependabot
	ren := facts.Renovate

	depOK := !dep.Missing && dep.Invalid == nil && dep.Config != nil
	renOK := !ren.Missing && ren.Invalid == nil && ren.Config != nil

	// No update tool at all: there is no cooldown to set. update-tool-configuration
	// reports the absence; this rule says so rather than going quiet.
	if !depOK && !renOK {
		return successMessage(ruleName, severity, "Dependency update tool configuration", "pass-not-applicable", nil)
	}

	if depOK && dependabotActionsCooldownConfigured(dep.Config) ||
		renOK && renovateCooldownConfigured(ren.Config) {
		return successMessage(ruleName, severity, "Dependency update tool configuration", "pass", nil)
	}

	// Reaching here with no cooldown means the rule already emitted its finding,
	// unless nothing covers github-actions — in which case a cooldown for action
	// updates is moot and the rule must still report that, not vanish.
	coversActions := depOK && dependabotCoversActions(dep.Config) ||
		renOK && renovateCoversActions(ren.Config)
	if !coversActions {
		return successMessage(ruleName, severity, "Dependency update tool configuration", "pass-not-applicable", nil)
	}
	return nil
}

func updateToolActionsPinningSuccessFinding(ruleName, severity string, facts *ScanFacts) *Finding {
	switch actionsPinningState(facts.Dependabot, facts.Renovate) {
	case actionsPinningConfigured:
		return successMessage(ruleName, severity, "Dependency update tool configuration", "pass", nil)
	case actionsPinningNotApplicable:
		// Nothing covers github-actions, so there are no action SHAs for an
		// update tool to keep current. Say so rather than reporting nothing.
		return successMessage(ruleName, severity, "Dependency update tool configuration", "pass-not-applicable", nil)
	default:
		return nil
	}
}

func ruleCategory(ruleName string) string {
	switch {
	case strings.HasPrefix(ruleName, "workflows/"):
		return categoryWorkflows
	case strings.HasPrefix(ruleName, "actions/"):
		return categorySettings
	case strings.HasPrefix(ruleName, "updates/"):
		return categoryUpdates
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

// undeterminedSettingFinding reports that a rule could not be evaluated because
// its input could not be read.
//
// This exists so a rule never silently produces nothing. "No finding" is
// indistinguishable from "clean" in every report format, so a check that
// quietly disappears reads as a pass — the most dangerous possible failure for a
// security scanner. Severity is info: it is not a vulnerability, it is a hole in
// the scan's coverage, and it should not inflate the finding counts operators
// triage on.
//
// The ID mirrors the success-finding scheme (one per rule) so two rules reading
// the same refused endpoint do not collide and get deduplicated away.
func undeterminedSettingFinding(ruleName, setting, cause string) Finding {
	return Finding{
		ID:       "undetermined-" + sanitizeID(ruleName),
		Rule:     ruleName,
		Category: ruleCategory(ruleName),
		Severity: SeverityInfo,
		Title:    "Could not determine " + setting,
		Description: "This check did not run because the " + setting + " could not be read: " + cause +
			". The result is unknown — treat it as unchecked, not as passing.",
		Location:    "Repository Actions settings",
		Remediation: "Re-run with a token that has repository admin access (fine-grained `Administration: Read`, or classic PAT `repo`), or review the setting manually under Settings → Actions → General.",
	}
}

// undeterminedFindingFor returns a "could not determine" finding when the given
// setting was not readable, or nil when it was. A non-nil result means the rule
// must stop rather than evaluate a nil value it cannot interpret.
func undeterminedFindingFor(facts *ScanFacts, ruleName, setting string) *Finding {
	cause, ok := facts.ActionsSettings.undeterminedCause(setting)
	if !ok {
		return nil
	}
	f := undeterminedSettingFinding(ruleName, setting, cause)
	return &f
}

func actionsSettingsEnabled(facts *ScanFacts) bool {
	permissions := facts.ActionsSettings.Permissions
	if permissions == nil {
		return false
	}
	return permissions.Enabled == nil || *permissions.Enabled
}

// actionsObservedDisabled reports that GitHub actually told us Actions is
// switched off for this repository.
//
// This is deliberately narrower than !actionsSettingsEnabled(), which is also
// true when Permissions is nil — that is, when the settings read failed and the
// scanner knows nothing. Conflating the two let a failed read be reported as
// the success "GitHub Actions are disabled for this repository", asserting a
// fact never observed. Absence of evidence is not evidence of absence.
func actionsObservedDisabled(facts *ScanFacts) bool {
	permissions := facts.ActionsSettings.Permissions
	return permissions != nil && permissions.Enabled != nil && !*permissions.Enabled
}

func evaluateDangerousWorkflowRule(facts *ScanFacts) []Finding {
	var findings []Finding
	for _, wf := range facts.Workflows {
		if !wf.Valid || !hasDangerousTrigger(wf.Workflow.On) {
			continue
		}
		msg := ruleMessage(ruleNamePullRequestTarget, "used", nil)
		findings = append(findings, Finding{
			ID:          fmt.Sprintf("dangerous-trigger-%s", wf.Path),
			Severity:    SeverityCritical,
			Title:       msg.Title,
			Description: msg.Description,
			File:        wf.Path,
			Remediation: msg.Fix,
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
			msg := ruleMessage(ruleNameActionVersionPinning, "unpinned", map[string]string{
				"Action": shortActionName(action.name),
				"Ref":    action.version,
			})
			findings = append(findings, Finding{
				// The ref is part of the ID because one file can reference the
				// same action at two different mutable refs — actions/checkout@v4
				// in one job and @v3 in another. Keying on path+name alone made
				// those two findings share an ID, and dedupeFindings silently
				// dropped the second: a real unpinned action disappearing from
				// the report because a sibling finding got there first.
				ID:          fmt.Sprintf("unpinned-%s-%s-%s", wf.Path, sanitizeID(action.name), sanitizeID(action.version)),
				Severity:    SeverityHigh,
				Title:       msg.Title,
				Description: msg.Description,
				File:        wf.Path,
				Line:        action.line,
				Remediation: msg.Fix,
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
		// A file with no jobs is not a workflow GitHub would ever run — most
		// often a stray config file parked in .github/workflows. Reporting
		// "No explicit permissions defined" at high severity misdiagnoses it:
		// the problem is the file, not its permissions block. Skip it and let
		// the parse/validity checks own that case.
		if wf.Workflow != nil && len(wf.Workflow.Jobs) == 0 {
			continue
		}
		msg := ruleMessage(ruleNameWorkflowPermissions, "no-permissions", nil)
		findings = append(findings, Finding{
			ID:          fmt.Sprintf("no-permissions-%s", wf.Path),
			Severity:    SeverityHigh,
			Title:       msg.Title,
			Description: msg.Description,
			File:        wf.Path,
			Remediation: msg.Fix,
		})
	}
	return findings
}

// evaluateWriteAllPermissionsRule flags `permissions: write-all` at the
// workflow or job level. Deliberately narrow: only the literal write-all is
// unambiguous enough to flag without a false-positive boundary — individual
// write scopes are routinely legitimate, and workflow-permissions already
// covers the missing-permissions case. Jobless files are skipped for the same
// reason workflow-permissions skips them: they are not runnable workflows, and
// the collector already reports them as an incomplete-scan warning.
func evaluateWriteAllPermissionsRule(facts *ScanFacts) []Finding {
	var findings []Finding
	for _, wf := range facts.Workflows {
		if !wf.Valid || len(wf.Workflow.Jobs) == 0 {
			continue
		}
		for _, grant := range writeAllGrants(wf.Workflow) {
			msg := ruleMessage(ruleNameWriteAllPermissions, "write-all", map[string]string{"Where": grant.where})
			findings = append(findings, Finding{
				ID:          grant.findingID(wf.Path),
				Severity:    SeverityHigh,
				Title:       msg.Title,
				Description: msg.Description,
				File:        wf.Path,
				Remediation: msg.Fix,
			})
		}
	}
	return findings
}

func evaluateAllowedActionsPolicyRule(facts *ScanFacts) []Finding {
	findings := make([]Finding, 0)
	findings = appendSettingsAccessFinding(findings, facts)

	if undetermined := undeterminedFindingFor(facts, ruleNameAllowedActionsPolicy, settingAllowedActions); undetermined != nil {
		return append(findings, *undetermined)
	}

	permissions := facts.ActionsSettings.Permissions
	if !actionsSettingsEnabled(facts) || permissions.AllowedActions == nil {
		return findings
	}

	if *permissions.AllowedActions == actionsAllowedAll {
		msg := ruleMessage(ruleNameAllowedActionsPolicy, "all-allowed", nil)
		findings = append(findings, Finding{
			ID:          findingIDAllActionsAllowed,
			Severity:    SeverityMedium,
			Title:       msg.Title,
			Description: msg.Description,
			Remediation: msg.Fix,
		})
	}

	return findings
}

func evaluateDefaultWorkflowPermissionsRule(facts *ScanFacts) []Finding {
	findings := make([]Finding, 0)
	findings = appendSettingsAccessFinding(findings, facts)

	if undetermined := undeterminedFindingFor(facts, ruleNameDefaultWorkflowPermissions, settingWorkflowPermissions); undetermined != nil {
		return append(findings, *undetermined)
	}

	perms := facts.ActionsSettings.DefaultWorkflowPermissions
	if !actionsSettingsEnabled(facts) || perms == nil {
		return findings
	}

	if perms.DefaultWorkflowPermissions != nil && *perms.DefaultWorkflowPermissions == permissionsWrite {
		msg := ruleMessage(ruleNameDefaultWorkflowPermissions, "read-write", nil)
		findings = append(findings, Finding{
			ID:          findingIDDefaultPermissionsWrite,
			Severity:    SeverityHigh,
			Title:       msg.Title,
			Description: msg.Description,
			Remediation: msg.Fix,
		})
	}

	return findings
}

func evaluateActionsCanApprovePRsRule(facts *ScanFacts) []Finding {
	findings := make([]Finding, 0)
	findings = appendSettingsAccessFinding(findings, facts)

	if undetermined := undeterminedFindingFor(facts, ruleNameActionsCanApprovePRs, settingWorkflowPermissions); undetermined != nil {
		return append(findings, *undetermined)
	}

	perms := facts.ActionsSettings.DefaultWorkflowPermissions
	if !actionsSettingsEnabled(facts) || perms == nil || perms.CanApprovePullRequestReviews == nil || !*perms.CanApprovePullRequestReviews {
		return findings
	}

	msg := ruleMessage(ruleNameActionsCanApprovePRs, "can-approve", nil)
	findings = append(findings, Finding{
		ID:          findingIDActionsCanApprovePRs,
		Severity:    SeverityMedium,
		Title:       msg.Title,
		Description: msg.Description,
		Remediation: msg.Fix,
	})

	return findings
}

func evaluateForkPRContributorApprovalRule(facts *ScanFacts) []Finding {
	findings := make([]Finding, 0)
	findings = appendSettingsAccessFinding(findings, facts)

	// Nothing to flag where the control does not exist.
	if facts.ActionsSettings.ForkPRApprovalNotApplicable {
		return findings
	}

	if undetermined := undeterminedFindingFor(facts, ruleNameForkPRContributorApproval, settingForkPRApproval); undetermined != nil {
		return append(findings, *undetermined)
	}

	policy := facts.ActionsSettings.ForkPRContributorApproval
	if !actionsSettingsEnabled(facts) || policy == nil || policy.ApprovalPolicy == forkPRApprovalAllExternal {
		return findings
	}

	msg := ruleMessage(ruleNameForkPRContributorApproval, "too-permissive", nil)
	findings = append(findings, Finding{
		ID:          findingIDForkPRTooPermissive,
		Severity:    SeverityHigh,
		Title:       msg.Title,
		Description: msg.Description,
		Remediation: msg.Fix,
	})

	return findings
}

// evaluateSHAPinningRequiredRule checks the repository setting that makes SHA
// pinning an enforced rule rather than a convention. It rides in the same
// /actions/permissions response the allowed-actions rule reads, so it costs no
// additional API call. Complements action-version-pinning: that rule proves the
// files are pinned today, this setting stops an unpinned reference running
// tomorrow.
func evaluateSHAPinningRequiredRule(facts *ScanFacts) []Finding {
	findings := make([]Finding, 0)
	findings = appendSettingsAccessFinding(findings, facts)

	if undetermined := undeterminedFindingFor(facts, ruleNameSHAPinningRequired, settingSHAPinning); undetermined != nil {
		return append(findings, *undetermined)
	}

	permissions := facts.ActionsSettings.Permissions
	if !actionsSettingsEnabled(facts) || permissions.SHAPinningRequired == nil {
		return findings
	}

	if !*permissions.SHAPinningRequired {
		msg := ruleMessage(ruleNameSHAPinningRequired, "not-required", nil)
		findings = append(findings, Finding{
			ID:          findingIDSHAPinningNotRequired,
			Severity:    SeverityMedium,
			Title:       msg.Title,
			Description: msg.Description,
			Remediation: msg.Fix,
		})
	}

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
	// Only a user's explicit severity override replaces what a finding chose for
	// itself. Stamping the rule's default severity onto every finding discarded
	// the deliberate `info` on the access and "could not determine" findings, so
	// a check that merely could not be evaluated was reported at the full
	// severity of the rule it belongs to — a coverage hole rendered as a
	// high-severity vulnerability.
	override := ""
	if cfg != nil {
		if s := normalizeSeverity(cfg.severityOverride(r.Name)); isValidSeverity(s) {
			override = s
		}
	}

	for i := range findings {
		findings[i].Rule = r.Name
		findings[i].Category = r.Category
		findings[i].DocURL = r.DocURL()
		switch {
		case override != "":
			findings[i].Severity = override
		case findings[i].Severity == "":
			findings[i].Severity = r.Severity
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
