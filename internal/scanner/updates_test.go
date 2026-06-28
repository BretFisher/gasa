package scanner

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/google/go-github/v84/github"
)

func encodedContent(path, content string) map[string]any {
	encoded := base64.StdEncoding.EncodeToString([]byte(content))
	return map[string]any{
		"type":     "file",
		"name":     path,
		"path":     path,
		"content":  encoded,
		"encoding": "base64",
	}
}

// ---------------------------------------------------------------------------
// update-tool-configuration: no tool configured
// ---------------------------------------------------------------------------

func TestEvaluateUpdateToolConfiguration_NoConfig(t *testing.T) {
	s, mux := newTestScanner(t, false)
	handle404(mux,
		"/repos/owner/repo/contents/.github/dependabot.yml",
		"/repos/owner/repo/contents/.github/dependabot.yaml",
		"/repos/owner/repo/contents/renovate.json",
		"/repos/owner/repo/contents/renovate.json5",
		"/repos/owner/repo/contents/.github/renovate.json",
		"/repos/owner/repo/contents/.github/renovate.json5",
		"/repos/owner/repo/contents/.gitlab/renovate.json",
		"/repos/owner/repo/contents/.gitlab/renovate.json5",
		"/repos/owner/repo/contents/.renovaterc",
		"/repos/owner/repo/contents/.renovaterc.json",
		"/repos/owner/repo/contents/.renovaterc.json5",
	)
	findings := collectAndEvaluateUpdateToolConfiguration(t, s)
	if len(findings) != 1 || findings[0].ID != "no-update-tool" {
		t.Fatalf("findings = %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// update-tool-configuration: require_workflows option
// ---------------------------------------------------------------------------

func TestEvaluateUpdateToolConfiguration_RequireWorkflowsSkipsWhenNoWorkflowYAML(t *testing.T) {
	facts := &ScanFacts{
		UpdateToolConfigurationRequireWorkflows: true,
		Dependabot: DependabotFacts{
			Missing:      true,
			HasWorkflows: false,
		},
		Renovate: RenovateFacts{
			Missing:      true,
			HasWorkflows: false,
		},
	}

	findings := evaluateUpdateToolConfigurationFacts(facts)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestEvaluateUpdateToolConfiguration_RequireWorkflowsStillChecksWhenWorkflowYAMLExists(t *testing.T) {
	facts := &ScanFacts{
		UpdateToolConfigurationRequireWorkflows: true,
		Dependabot: DependabotFacts{
			Missing:      true,
			HasWorkflows: true,
		},
		Renovate: RenovateFacts{
			Missing:      true,
			HasWorkflows: true,
		},
	}

	findings := evaluateUpdateToolConfigurationFacts(facts)
	if len(findings) != 1 || findings[0].ID != "no-update-tool" {
		t.Fatalf("findings = %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// update-tool-configuration: invalid configs
// ---------------------------------------------------------------------------

func TestEvaluateUpdateToolConfiguration_InvalidYAML(t *testing.T) {
	s, mux := newTestScanner(t, false)
	handleJSON(mux, "/repos/owner/repo/contents/.github/dependabot.yml", encodedContent(".github/dependabot.yml", "version: ["))
	handle404(mux,
		"/repos/owner/repo/contents/renovate.json",
		"/repos/owner/repo/contents/renovate.json5",
		"/repos/owner/repo/contents/.github/renovate.json",
		"/repos/owner/repo/contents/.github/renovate.json5",
		"/repos/owner/repo/contents/.gitlab/renovate.json",
		"/repos/owner/repo/contents/.gitlab/renovate.json5",
		"/repos/owner/repo/contents/.renovaterc",
		"/repos/owner/repo/contents/.renovaterc.json",
		"/repos/owner/repo/contents/.renovaterc.json5",
	)
	findings := collectAndEvaluateUpdateToolConfiguration(t, s)
	if len(findings) != 1 || findings[0].ID != "invalid-dependabot" {
		t.Fatalf("findings = %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// update-tool-configuration: missing github-actions coverage
// ---------------------------------------------------------------------------

func TestEvaluateUpdateToolConfiguration_MissingActionsEcosystem(t *testing.T) {
	s, mux := newTestScanner(t, false)
	config := "version: 2\nupdates:\n  - package-ecosystem: gomod\n    directory: /\n    schedule:\n      interval: weekly\n"
	handleJSON(mux, "/repos/owner/repo/contents/.github/dependabot.yml", encodedContent(".github/dependabot.yml", config))
	handle404(mux,
		"/repos/owner/repo/contents/renovate.json",
		"/repos/owner/repo/contents/renovate.json5",
		"/repos/owner/repo/contents/.github/renovate.json",
		"/repos/owner/repo/contents/.github/renovate.json5",
		"/repos/owner/repo/contents/.gitlab/renovate.json",
		"/repos/owner/repo/contents/.gitlab/renovate.json5",
		"/repos/owner/repo/contents/.renovaterc",
		"/repos/owner/repo/contents/.renovaterc.json",
		"/repos/owner/repo/contents/.renovaterc.json5",
	)
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows", []*github.RepositoryContent{{Path: github.Ptr(".github/workflows/ci.yml"), Name: github.Ptr("ci.yml")}})
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows/ci.yml", encodedContent(".github/workflows/ci.yml", "on: pull_request\n"))

	findings := collectAndEvaluateUpdateToolConfiguration(t, s)
	if len(findings) != 1 || findings[0].ID != "update-tool-missing-actions" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestEvaluateUpdateToolConfiguration_IgnoresOtherEcosystems(t *testing.T) {
	s, mux := newTestScanner(t, false)
	config := "version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n"
	handleJSON(mux, "/repos/owner/repo/contents/.github/dependabot.yml", encodedContent(".github/dependabot.yml", config))
	handle404(mux,
		"/repos/owner/repo/contents/renovate.json",
		"/repos/owner/repo/contents/renovate.json5",
		"/repos/owner/repo/contents/.github/renovate.json",
		"/repos/owner/repo/contents/.github/renovate.json5",
		"/repos/owner/repo/contents/.gitlab/renovate.json",
		"/repos/owner/repo/contents/.gitlab/renovate.json5",
		"/repos/owner/repo/contents/.renovaterc",
		"/repos/owner/repo/contents/.renovaterc.json",
		"/repos/owner/repo/contents/.renovaterc.json5",
	)
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows", []*github.RepositoryContent{{Path: github.Ptr(".github/workflows/ci.yml"), Name: github.Ptr("ci.yml")}})
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows/ci.yml", encodedContent(".github/workflows/ci.yml", "on: pull_request\n"))

	findings := collectAndEvaluateUpdateToolConfiguration(t, s)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestCollectDependabotFacts_DebugLogsKeyDecisions(t *testing.T) {
	s, mux := newTestScanner(t, false)
	config := "version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n    cooldown:\n      default-days: 7\n"
	handleJSON(mux, "/repos/owner/repo/contents/.github/dependabot.yml", encodedContent(".github/dependabot.yml", config))

	var lines []string
	dbg := func(repo, msg string) {
		lines = append(lines, repo+"|"+msg)
	}

	facts := newTestFactCollector(s).collectDependabotFacts(context.Background(), "owner", "repo", true, dbg)
	if facts.Config == nil {
		t.Fatalf("expected parsed config, got %+v", facts)
	}
	requireContainsLine(t, lines, "GET /repos/owner/repo/contents/.github/dependabot.yml")
	requireContainsLine(t, lines, "found dependabot config at .github/dependabot.yml")
	requireContainsLine(t, lines, "dependabot config parsed: 1 update entries, covers-actions=true")
	requireContainsLine(t, lines, "dependabot github-actions entry: cooldown=true")
	for _, line := range lines {
		if !strings.HasPrefix(line, "owner/repo|") {
			t.Fatalf("debug line %q missing repo prefix", line)
		}
	}
}

func TestCollectRenovateFacts_DebugLogsKeyDecisions(t *testing.T) {
	s, mux := newTestScanner(t, false)
	config := "{\n  \"enabledManagers\": [\"github-actions\"],\n  \"pinDigests\": true,\n  \"minimumReleaseAge\": \"7 days\",\n  \"extends\": [\"config:best-practices\"]\n}"
	handle404(mux,
		"/repos/owner/repo/contents/renovate.json",
		"/repos/owner/repo/contents/renovate.json5",
	)
	handleJSON(mux, "/repos/owner/repo/contents/.github/renovate.json", encodedContent(".github/renovate.json", config))

	var lines []string
	dbg := func(repo, msg string) {
		lines = append(lines, repo+"|"+msg)
	}

	facts := newTestFactCollector(s).collectRenovateFacts(context.Background(), "owner", "repo", true, dbg)
	if facts.Config == nil {
		t.Fatalf("expected parsed config, got %+v", facts)
	}
	requireContainsLine(t, lines, "GET /repos/owner/repo/contents/renovate.json")
	requireContainsLine(t, lines, "renovate config not found at renovate.json")
	requireContainsLine(t, lines, "GET /repos/owner/repo/contents/.github/renovate.json")
	requireContainsLine(t, lines, "found renovate config at .github/renovate.json")
	requireContainsLine(t, lines, "renovate config parsed: covers-actions=true pin-digests=true cooldown=true")
	for _, line := range lines {
		if !strings.HasPrefix(line, "owner/repo|") {
			t.Fatalf("debug line %q missing repo prefix", line)
		}
	}
}

// ---------------------------------------------------------------------------
// Incomplete-scan reporting: indeterminate errors must not look like "absent"
// ---------------------------------------------------------------------------

func TestCollectRenovateFacts_IndeterminateErrorMarksUnknown(t *testing.T) {
	s, mux := newTestScanner(t, false)
	handle500(mux, renovateServerPaths()...)

	collector := newTestFactCollector(s)
	facts := collector.collectRenovateFacts(context.Background(), "owner", "repo", true, nil)

	if facts.Missing {
		t.Fatalf("Missing = true; an indeterminate error must not be reported as absent")
	}
	if !facts.Unknown {
		t.Fatalf("Unknown = false; want true on an indeterminate error")
	}
	if len(collector.warnings) != 1 || collector.warnings[0].Area != "renovate config" {
		t.Fatalf("warnings = %+v, want one 'renovate config' warning", collector.warnings)
	}
}

// A single indeterminate error must taint the "Missing" conclusion even when
// every other path returns a clean 404 — we genuinely don't know about the one
// path that failed.
func TestCollectRenovateFacts_OneIndeterminatePathTaintsMissing(t *testing.T) {
	s, mux := newTestScanner(t, false)
	handle500(mux, "/repos/owner/repo/contents/renovate.json")
	handle404(mux, renovateServerPaths()[1:]...)

	collector := newTestFactCollector(s)
	facts := collector.collectRenovateFacts(context.Background(), "owner", "repo", true, nil)

	if facts.Missing || !facts.Unknown {
		t.Fatalf("Missing=%v Unknown=%v, want Missing=false Unknown=true", facts.Missing, facts.Unknown)
	}
}

func TestCollectRenovateFacts_AllNotFoundIsMissing(t *testing.T) {
	s, mux := newTestScanner(t, false)
	handle404(mux, renovateServerPaths()...)

	collector := newTestFactCollector(s)
	facts := collector.collectRenovateFacts(context.Background(), "owner", "repo", true, nil)

	if !facts.Missing || facts.Unknown {
		t.Fatalf("Missing=%v Unknown=%v, want Missing=true Unknown=false", facts.Missing, facts.Unknown)
	}
	if len(collector.warnings) != 0 {
		t.Fatalf("warnings = %+v, want none for a clean all-404 result", collector.warnings)
	}
}

func TestCollectDependabotFacts_IndeterminateErrorMarksUnknown(t *testing.T) {
	s, mux := newTestScanner(t, false)
	handle500(mux,
		"/repos/owner/repo/contents/.github/dependabot.yml",
		"/repos/owner/repo/contents/.github/dependabot.yaml",
	)

	collector := newTestFactCollector(s)
	facts := collector.collectDependabotFacts(context.Background(), "owner", "repo", true, nil)

	if facts.Missing || !facts.Unknown {
		t.Fatalf("Missing=%v Unknown=%v, want Missing=false Unknown=true", facts.Missing, facts.Unknown)
	}
	if len(collector.warnings) != 1 || collector.warnings[0].Area != "dependabot config" {
		t.Fatalf("warnings = %+v, want one 'dependabot config' warning", collector.warnings)
	}
}

func TestCollectWorkflowFacts_IndeterminateDirErrorWarns(t *testing.T) {
	s, mux := newTestScanner(t, false)
	handle500(mux, "/repos/owner/repo/contents/.github/workflows")

	collector := newTestFactCollector(s)
	workflows := collector.collectWorkflowFacts(context.Background(), "owner", "repo", nil)

	if len(workflows) != 0 {
		t.Fatalf("workflows = %+v, want none", workflows)
	}
	if len(collector.warnings) != 1 || collector.warnings[0].Area != "workflows" {
		t.Fatalf("warnings = %+v, want one 'workflows' warning", collector.warnings)
	}
}

// When presence is unknown (an indeterminate fetch error), the rule must NOT
// claim "no update tool" — that would be a false finding invented from a
// transient failure. This is the concrete bug the Unknown/Missing split fixes.
func TestEvaluateUpdateToolConfiguration_UnknownDoesNotReportNoTool(t *testing.T) {
	facts := &ScanFacts{
		Dependabot: DependabotFacts{Unknown: true, HasWorkflows: true},
		Renovate:   RenovateFacts{Unknown: true, HasWorkflows: true},
	}
	if findings := evaluateUpdateToolConfigurationFacts(facts); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none when tool presence is unknown", findings)
	}
}

// Contrast: when both tools are definitively absent (clean 404s), the no-tool
// finding still fires. Guards against the fix over-suppressing real findings.
func TestEvaluateUpdateToolConfiguration_BothMissingReportsNoTool(t *testing.T) {
	facts := &ScanFacts{
		Dependabot: DependabotFacts{Missing: true, HasWorkflows: true},
		Renovate:   RenovateFacts{Missing: true, HasWorkflows: true},
	}
	findings := evaluateUpdateToolConfigurationFacts(facts)
	if len(findings) != 1 || findings[0].ID != findingIDNoUpdateTool {
		t.Fatalf("findings = %+v, want one %q finding", findings, findingIDNoUpdateTool)
	}
}

// renovateServerPaths returns the API server paths for every renovate config
// location, derived from the production path list so the two never drift.
func renovateServerPaths() []string {
	paths := make([]string, len(renovateConfigPaths))
	for i, p := range renovateConfigPaths {
		paths[i] = "/repos/owner/repo/contents/" + p
	}
	return paths
}

// ---------------------------------------------------------------------------
// update-tool-actions-cooldown: Dependabot
// ---------------------------------------------------------------------------

func TestEvaluateUpdateToolActionsCooldown_DependabotMissingCooldown(t *testing.T) {
	facts := &ScanFacts{Dependabot: DependabotFacts{
		Path: ".github/dependabot.yml",
		Config: &DependabotConfig{Version: 2, Updates: []DependabotUpdate{{
			PackageEcosystem: "github-actions",
			Directory:        "/",
		}}},
	}}

	findings := evaluateUpdateToolActionsCooldownFacts(facts)
	if len(findings) != 1 || findings[0].ID != "update-tool-actions-missing-cooldown" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestEvaluateUpdateToolActionsCooldown_DependabotCooldownSet(t *testing.T) {
	facts := &ScanFacts{Dependabot: DependabotFacts{
		Path: ".github/dependabot.yml",
		Config: &DependabotConfig{Version: 2, Updates: []DependabotUpdate{{
			PackageEcosystem: "github-actions",
			Directory:        "/",
			Cooldown:         &DependabotCooldown{DefaultDays: 7},
		}}},
	}}

	findings := evaluateUpdateToolActionsCooldownFacts(facts)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// update-tool-actions-cooldown: Renovate
// ---------------------------------------------------------------------------

func TestEvaluateUpdateToolActionsCooldown_RenovateTopLevelMinReleaseAge(t *testing.T) {
	facts := &ScanFacts{
		Renovate: RenovateFacts{
			Path: ".github/renovate.json",
			Config: &RenovateConfig{
				MinReleaseAge: "7 days",
			},
		},
	}
	findings := evaluateUpdateToolActionsCooldownFacts(facts)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestEvaluateUpdateToolActionsCooldown_RenovatePackageRuleMinReleaseAge(t *testing.T) {
	facts := &ScanFacts{
		Renovate: RenovateFacts{
			Path: ".github/renovate.json",
			Config: &RenovateConfig{
				PackageRules: []RenovatePackageRule{
					{MatchManagers: []string{"github-actions"}, MinReleaseAge: "7 days"},
				},
			},
		},
	}
	findings := evaluateUpdateToolActionsCooldownFacts(facts)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestEvaluateUpdateToolActionsCooldown_RenovateNoCooldown(t *testing.T) {
	facts := &ScanFacts{
		Renovate: RenovateFacts{
			Path:   ".github/renovate.json",
			Config: &RenovateConfig{},
		},
	}
	findings := evaluateUpdateToolActionsCooldownFacts(facts)
	if len(findings) != 1 || findings[0].ID != "update-tool-actions-missing-cooldown" {
		t.Fatalf("findings = %+v", findings)
	}
}

// Either tool having cooldown makes rule pass
func TestEvaluateUpdateToolActionsCooldown_RenovatePassesDespiteDependabotNoCooldown(t *testing.T) {
	facts := &ScanFacts{
		Dependabot: DependabotFacts{
			Path: ".github/dependabot.yml",
			Config: &DependabotConfig{Version: 2, Updates: []DependabotUpdate{{
				PackageEcosystem: "github-actions",
				Directory:        "/",
				// no cooldown
			}}},
		},
		Renovate: RenovateFacts{
			Path:   ".github/renovate.json",
			Config: &RenovateConfig{MinReleaseAge: "3 days"},
		},
	}
	findings := evaluateUpdateToolActionsCooldownFacts(facts)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none (Renovate covers cooldown)", findings)
	}
}

// ---------------------------------------------------------------------------
// update-tool-actions-pinning: Dependabot
// ---------------------------------------------------------------------------

// Dependabot has no option to pin actions to commit SHAs, so this rule must
// no-op when only Dependabot is configured — Dependabot alone can neither pass
// nor fail it. The workflow-level action_pinning rule covers that case.
func TestEvaluateUpdateToolActionsPinning_DependabotOnly_NoOp(t *testing.T) {
	facts := &ScanFacts{
		Dependabot: DependabotFacts{
			Path: ".github/dependabot.yml",
			Config: &DependabotConfig{Version: 2, Updates: []DependabotUpdate{{
				PackageEcosystem: "github-actions",
				Directory:        "/",
			}}},
		},
	}
	findings := evaluateUpdateToolActionsPinningFacts(facts)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

// ---------------------------------------------------------------------------
// update-tool-actions-pinning: Renovate
// ---------------------------------------------------------------------------

func TestEvaluateUpdateToolActionsPinning_RenovateTopLevelPinDigests(t *testing.T) {
	facts := &ScanFacts{
		Renovate: RenovateFacts{
			Path:   ".github/renovate.json5",
			Config: &RenovateConfig{PinDigests: true},
		},
	}
	findings := evaluateUpdateToolActionsPinningFacts(facts)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestEvaluateUpdateToolActionsPinning_RenovatePinPreset(t *testing.T) {
	facts := &ScanFacts{
		Renovate: RenovateFacts{
			Path:   ".github/renovate.json",
			Config: &RenovateConfig{Extends: []string{"config:best-practices", "helpers:pinGitHubActionDigests"}},
		},
	}
	findings := evaluateUpdateToolActionsPinningFacts(facts)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestEvaluateUpdateToolActionsPinning_RenovatePackageRulePinDigests(t *testing.T) {
	facts := &ScanFacts{
		Renovate: RenovateFacts{
			Path: ".github/renovate.json",
			Config: &RenovateConfig{
				PackageRules: []RenovatePackageRule{
					{MatchManagers: []string{"github-actions"}, PinDigests: true},
				},
			},
		},
	}
	findings := evaluateUpdateToolActionsPinningFacts(facts)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestEvaluateUpdateToolActionsPinning_NeitherToolPins(t *testing.T) {
	facts := &ScanFacts{
		Renovate: RenovateFacts{
			Path:   ".github/renovate.json",
			Config: &RenovateConfig{EnabledManagers: []string{"github-actions"}},
		},
	}
	findings := evaluateUpdateToolActionsPinningFacts(facts)
	if len(findings) != 1 || findings[0].ID != "update-tool-actions-not-pinning" {
		t.Fatalf("findings = %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// Renovate: github-actions coverage detection
// ---------------------------------------------------------------------------

func TestRenovateCoversActions_NoEnabledManagers(t *testing.T) {
	cfg := &RenovateConfig{}
	if !renovateCoversActions(cfg) {
		t.Fatal("expected renovate to cover actions when enabledManagers is absent")
	}
}

func TestRenovateCoversActions_ExplicitlyEnabled(t *testing.T) {
	cfg := &RenovateConfig{EnabledManagers: []string{"dockerfile", "github-actions"}}
	if !renovateCoversActions(cfg) {
		t.Fatal("expected renovate to cover actions when explicitly listed")
	}
}

func TestRenovateCoversActions_ExplicitlyNotEnabled(t *testing.T) {
	cfg := &RenovateConfig{EnabledManagers: []string{"dockerfile"}}
	if renovateCoversActions(cfg) {
		t.Fatal("expected renovate NOT to cover actions when github-actions is not in enabledManagers")
	}
}

// ---------------------------------------------------------------------------
// Renovate config parsing
// ---------------------------------------------------------------------------

func TestParseRenovateConfig_HuJSON(t *testing.T) {
	input := `{
	// Renovate configs commonly contain comments.
	"extends": [
		"github>org/renovate-config//presets",
	],
	"labels": ["docs:https://example.com/renovate", "literal /* not a comment */ value"],
	/* block comment */
	"enabledManagers": ["github-actions"],
	"pinDigests": true,
	"minimumReleaseAge": "7 days",
}`

	cfg, err := parseRenovateConfig(input)
	if err != nil {
		t.Fatalf("parseRenovateConfig() error = %v", err)
	}
	if len(cfg.Extends) != 1 || cfg.Extends[0] != "github>org/renovate-config//presets" {
		t.Fatalf("extends = %v", cfg.Extends)
	}
	if !cfg.PinDigests {
		t.Fatal("expected pinDigests to parse as true")
	}
	if cfg.MinReleaseAge != "7 days" {
		t.Fatalf("minimumReleaseAge = %q", cfg.MinReleaseAge)
	}
}

func collectAndEvaluateUpdateToolConfiguration(t *testing.T, s *Scanner) []Finding {
	t.Helper()
	collector := newTestFactCollector(s)
	workflows := collector.collectWorkflowFacts(context.Background(), "owner", "repo", nil)
	hasWorkflows := len(workflows) > 0
	facts := &ScanFacts{
		Workflows:  workflows,
		Dependabot: collector.collectDependabotFacts(context.Background(), "owner", "repo", hasWorkflows, nil),
		Renovate:   collector.collectRenovateFacts(context.Background(), "owner", "repo", hasWorkflows, nil),
	}
	return evaluateUpdateToolConfigurationFacts(facts)
}
