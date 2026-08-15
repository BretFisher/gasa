package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-github/v90/github"
)

func TestLoadConfigFromDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gasa.yml")
	content := `rules:
  include:
    - workflows/action-version-pinning
rule_options:
  workflows/action-version-pinning:
    ignore_same_owner: true
  updates/update-tool-configuration:
    require_workflows: true
overrides:
  - rule: workflows/action-version-pinning
    severity: critical
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	cfg, loadedPath, err := LoadConfigFromDir(dir)
	if err != nil {
		t.Fatalf("LoadConfigFromDir() error: %v", err)
	}
	if loadedPath != path {
		t.Fatalf("loadedPath = %q, want %q", loadedPath, path)
	}
	if cfg == nil {
		t.Fatalf("cfg = nil")
	}
	if !cfg.actionVersionPinningIgnoreSameOwner() {
		t.Fatal("expected ignore_same_owner to be enabled")
	}
	if !cfg.updateToolConfigurationRequireWorkflows() {
		t.Fatal("expected require_workflows to be enabled")
	}
}

func TestScanRepoWithOptions_CLIRulesOverrideConfigAndSuppressions(t *testing.T) {
	s, mux := newTestScanner(t, false)

	handleJSON(mux, "/repos/owner/repo", map[string]any{"full_name": "owner/repo", "default_branch": "main"})
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows", []*github.RepositoryContent{{
		Name: github.Ptr("ci.yml"),
		Path: github.Ptr(".github/workflows/ci.yml"),
	}})
	workflow2 := "on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows/ci.yml", encodedContent(".github/workflows/ci.yml", workflow2))
	handle404(mux,
		"/repos/owner/repo/actions/permissions",
		"/repos/owner/repo/contents/.github/dependabot.yml",
		"/repos/owner/repo/contents/.github/dependabot.yaml",
	)

	result, err := s.ScanRepoWithOptions(context.Background(), "owner", "repo", ScanOptions{
		RuleNames: []string{"workflows/workflow-permissions"},
		Config: &Config{
			Rules: ConfigRules{Include: []string{"workflows/action-version-pinning"}},
			Suppressions: []RuleSuppression{{
				Rule: "workflows/workflow-permissions",
				Path: ".github/workflows/ci.yml",
			}},
		},
	})
	if err != nil {
		t.Fatalf("ScanRepoWithOptions() error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %+v, want none", result.Findings)
	}
}

func TestScanRepoWithOptions_SeverityFilterUsesConfigOverride(t *testing.T) {
	s, mux := newTestScanner(t, false)

	handleJSON(mux, "/repos/owner/repo", map[string]any{"full_name": "owner/repo", "default_branch": "main"})
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows", []*github.RepositoryContent{{
		Name: github.Ptr("ci.yml"),
		Path: github.Ptr(".github/workflows/ci.yml"),
	}})
	workflow := "on: pull_request\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows/ci.yml", encodedContent(".github/workflows/ci.yml", workflow))
	handle404(mux,
		"/repos/owner/repo/actions/permissions",
		"/repos/owner/repo/contents/.github/dependabot.yml",
		"/repos/owner/repo/contents/.github/dependabot.yaml",
	)

	result, err := s.ScanRepoWithOptions(context.Background(), "owner", "repo", ScanOptions{
		Severities: []string{SeverityCritical},
		Config: &Config{
			Overrides: []RuleOverride{{Rule: "workflows/action-version-pinning", Severity: SeverityCritical}},
		},
	})
	if err != nil {
		t.Fatalf("ScanRepoWithOptions() error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("len(result.Findings) = %d, want 1\nfindings=%+v", len(result.Findings), result.Findings)
	}
	if result.Findings[0].Rule != "workflows/action-version-pinning" {
		t.Fatalf("finding rule = %q, want action version pinning", result.Findings[0].Rule)
	}
	if result.Findings[0].Severity != SeverityCritical {
		t.Fatalf("finding severity = %q, want %q", result.Findings[0].Severity, SeverityCritical)
	}
}

func TestScanRepoWithOptions_ActionVersionPinningIgnoreSameOwner(t *testing.T) {
	s, mux := newTestScanner(t, false)

	handleJSON(mux, "/repos/owner/repo", map[string]any{"full_name": "owner/repo", "default_branch": "main"})
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows", []*github.RepositoryContent{{
		Name: github.Ptr("ci.yml"),
		Path: github.Ptr(".github/workflows/ci.yml"),
	}})
	workflow := "on: pull_request\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: owner/internal-action@v1\n"
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows/ci.yml", encodedContent(".github/workflows/ci.yml", workflow))
	handle404(mux,
		"/repos/owner/repo/actions/permissions",
		"/repos/owner/repo/contents/.github/dependabot.yml",
		"/repos/owner/repo/contents/.github/dependabot.yaml",
	)

	result, err := s.ScanRepoWithOptions(context.Background(), "owner", "repo", ScanOptions{
		RuleNames: []string{"workflows/action-version-pinning"},
		Config: &Config{
			RuleOptions: ConfigRuleOptions{
				ActionVersionPinning: ActionVersionPinningRuleOptions{IgnoreSameOwner: true},
			},
		},
	})
	if err != nil {
		t.Fatalf("ScanRepoWithOptions() error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %+v, want none", result.Findings)
	}
}
