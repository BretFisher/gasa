package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-github/v84/github"
	"gopkg.in/yaml.v3"
)

func TestHasDangerousTrigger(t *testing.T) {
	tests := []struct {
		name string
		on   interface{}
		want bool
	}{
		{name: "string dangerous", on: "pull_request_target", want: true},
		{name: "string safe", on: "pull_request", want: false},
		{name: "list dangerous", on: []interface{}{"push", "pull_request_target"}, want: true},
		{name: "list safe", on: []interface{}{"push", "pull_request"}, want: false},
		{name: "map dangerous", on: map[string]interface{}{"pull_request_target": map[string]interface{}{}}, want: true},
		{name: "map safe", on: map[string]interface{}{"push": nil}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasDangerousTrigger(tt.on); got != tt.want {
				t.Fatalf("hasDangerousTrigger() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindUnpinnedActions(t *testing.T) {
	content := "steps:\n  - uses: actions/checkout@v4\n  - uses: actions/setup-go@main\n  - uses: actions/cache@0123456789012345678901234567890123456789\n  - uses: actions/upload-artifact@0123456789012345678901234567890123456789012345678901234567890123\n  - uses: ./local-action\n  - uses: docker://alpine:latest\n"
	refs := findUnpinnedActions(content)
	if len(refs) != 2 {
		t.Fatalf("findUnpinnedActions() len = %d, want 2", len(refs))
	}
	if refs[0].name != "actions/checkout" || refs[0].line != 2 {
		t.Fatalf("first ref = %+v", refs[0])
	}
	if refs[1].name != "actions/setup-go" || refs[1].line != 3 {
		t.Fatalf("second ref = %+v", refs[1])
	}
}

func TestFindUnpinnedActionsInWorkflowUsesParsedYAML(t *testing.T) {
	content := `# uses: evil/comment-only@main
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: "actions/checkout@v4"
      - uses: actions/cache@0123456789012345678901234567890123456789
      - uses: ./local-action
      - uses: docker://alpine:latest
  reusable:
    uses: owner/repo/.github/workflows/reuse.yml@main
`
	workflow := &WorkflowFile{}
	if err := yaml.Unmarshal([]byte(content), workflow); err != nil {
		t.Fatalf("yaml.Unmarshal() error: %v", err)
	}

	refs := findUnpinnedActionsInWorkflow(workflow, content)
	if len(refs) != 2 {
		t.Fatalf("findUnpinnedActionsInWorkflow() len = %d, want 2\nrefs=%+v", len(refs), refs)
	}
	if refs[0].name != "actions/checkout" || refs[0].version != "v4" || refs[0].line != 6 {
		t.Fatalf("first ref = %+v", refs[0])
	}
	if refs[1].name != "owner/repo/.github/workflows/reuse.yml" || refs[1].version != "main" || refs[1].line != 11 {
		t.Fatalf("second ref = %+v", refs[1])
	}
}

func TestEvaluateActionVersionPinningRuleFallsBackToRegexForInvalidYAML(t *testing.T) {
	facts := &ScanFacts{Workflows: []WorkflowFact{{
		Path:    ".github/workflows/bad.yml",
		Content: "jobs:\n  build: [\n    steps:\n      - uses: actions/checkout@v4\n",
		Valid:   false,
	}}}

	findings := evaluateActionVersionPinningRule(facts)
	if len(findings) != 1 {
		t.Fatalf("findings len = %d, want 1\nfindings=%+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Title, "actions/checkout") {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestEvaluateActionVersionPinningRule_IgnoreSameOwner(t *testing.T) {
	facts := &ScanFacts{
		RepositoryOwner:                     "BretFisher",
		ActionVersionPinningIgnoreSameOwner: true,
		Workflows: []WorkflowFact{{
			Path:    ".github/workflows/ci.yml",
			Content: "steps:\n  - uses: BretFisher/internal-action@v1\n  - uses: actions/checkout@v4\n",
		}},
	}

	findings := evaluateActionVersionPinningRule(facts)
	if len(findings) != 1 {
		t.Fatalf("findings len = %d, want 1\nfindings=%+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Title, "actions/checkout") {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestEvaluateActionVersionPinningRule_SameOwnerStillFlaggedByDefault(t *testing.T) {
	facts := &ScanFacts{
		RepositoryOwner: "bretfisher",
		Workflows: []WorkflowFact{{
			Path:    ".github/workflows/ci.yml",
			Content: "steps:\n  - uses: bretfisher/internal-action@v1\n",
		}},
	}

	findings := evaluateActionVersionPinningRule(facts)
	if len(findings) != 1 {
		t.Fatalf("findings len = %d, want 1\nfindings=%+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Title, "bretfisher/internal-action") {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestIsSHA(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want bool
	}{
		{name: "sha1", ref: "0123456789012345678901234567890123456789", want: true},
		{name: "sha256", ref: "0123456789012345678901234567890123456789012345678901234567890123", want: true},
		{name: "sha1 uppercase", ref: "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD", want: true},
		{name: "39 hex", ref: "012345678901234567890123456789012345678", want: false},
		{name: "41 hex", ref: "01234567890123456789012345678901234567890", want: false},
		{name: "63 hex", ref: "012345678901234567890123456789012345678901234567890123456789012", want: false},
		{name: "65 hex", ref: "01234567890123456789012345678901234567890123456789012345678901234", want: false},
		{name: "short SHA", ref: "0123456789", want: false},
		{name: "non-hex SHA", ref: "012345678901234567890123456789012345678g", want: false},
		{name: "tag", ref: "v4", want: false},
		{name: "branch", ref: "main", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSHA(tt.ref); got != tt.want {
				t.Fatalf("isSHA(%q) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}

func TestHasExplicitPermissions(t *testing.T) {
	workflowLevel := &WorkflowFile{Permissions: map[string]interface{}{"contents": "read"}}
	if !hasExplicitPermissions(workflowLevel) {
		t.Fatal("workflow-level permissions should be explicit")
	}

	jobLevel := &WorkflowFile{Jobs: map[string]WorkflowJob{
		"build": {Permissions: map[string]interface{}{"contents": "read"}},
		"test":  {Permissions: map[string]interface{}{"actions": "read"}},
	}}
	if !hasExplicitPermissions(jobLevel) {
		t.Fatal("all job-level permissions should be explicit")
	}

	partial := &WorkflowFile{Jobs: map[string]WorkflowJob{
		"build": {Permissions: map[string]interface{}{"contents": "read"}},
		"test":  {},
	}}
	if hasExplicitPermissions(partial) {
		t.Fatal("partial job-level permissions should not be explicit")
	}

	none := &WorkflowFile{}
	if hasExplicitPermissions(none) {
		t.Fatal("empty workflow should not be explicit")
	}
}

// Every workflow rule skips files it could not parse, so a repository whose
// only workflow is unparsable produces zero findings. Without an incomplete
// marker that is indistinguishable from a clean scan — a pass for a file nobody
// checked. The parse error used to surface only under --debug.
func TestCollectWorkflowFacts_UnparseableWorkflowMarksScanIncomplete(t *testing.T) {
	s, mux := newTestScanner(t, false)
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows", []*github.RepositoryContent{{
		Path: github.Ptr(".github/workflows/broken.yml"),
		Name: github.Ptr("broken.yml"),
	}})
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows/broken.yml",
		encodedContent(".github/workflows/broken.yml", "jobs:\n  build: [\n    steps:\n"))

	collector := newTestFactCollector(s)
	workflows := collector.collectWorkflowFacts(context.Background(), "owner", "repo", nil)

	// The file is still collected — action-version-pinning falls back to its
	// regex path for unparsable YAML — but it is not marked Valid.
	if len(workflows) != 1 || workflows[0].Valid {
		t.Fatalf("workflows = %+v, want one collected but invalid workflow", workflows)
	}
	if len(collector.warnings) != 1 {
		t.Fatalf("warnings = %+v, want one parse warning", collector.warnings)
	}
	if !strings.Contains(collector.warnings[0].Area, "broken.yml") {
		t.Fatalf("warning should name the file, got %+v", collector.warnings[0])
	}

	// The rules that require a parsed workflow stay quiet, which is exactly why
	// the warning above has to exist.
	facts := &ScanFacts{Workflows: workflows}
	if findings := evaluateDangerousWorkflowRule(facts); len(findings) != 0 {
		t.Fatalf("dangerous-trigger findings = %+v, want none for an unparsed file", findings)
	}
	if findings := evaluateWorkflowPermissionsRule(facts); len(findings) != 0 {
		t.Fatalf("workflow-permissions findings = %+v, want none for an unparsed file", findings)
	}
}

// One file can reference the same action at two different mutable refs. The
// finding ID keyed only on path+action name, so both findings collided and
// dedupeFindings dropped the second — a real unpinned action vanishing from the
// report because a sibling got there first.
func TestEvaluateActionVersionPinningRule_SameActionTwoRefsBothReported(t *testing.T) {
	content := `jobs:
  build:
    steps:
      - uses: actions/checkout@v4
  release:
    steps:
      - uses: actions/checkout@v3
`
	workflow := &WorkflowFile{}
	if err := yaml.Unmarshal([]byte(content), workflow); err != nil {
		t.Fatalf("yaml.Unmarshal() error: %v", err)
	}

	facts := &ScanFacts{Workflows: []WorkflowFact{{
		Path:     ".github/workflows/ci.yml",
		Content:  content,
		Workflow: workflow,
		Valid:    true,
	}}}

	findings := dedupeFindings(evaluateActionVersionPinningRule(facts))
	if len(findings) != 2 {
		t.Fatalf("findings = %+v, want both unpinned refs reported", findings)
	}
	if findings[0].ID == findings[1].ID {
		t.Fatalf("finding IDs collide (%q); dedupe would drop one", findings[0].ID)
	}
}

// A file that parses as YAML but defines no jobs is not a runnable workflow —
// typically a stray config file in .github/workflows. It used to draw a
// high-severity "No explicit permissions defined", which misdiagnoses the
// problem: the file is the problem, not its permissions block. It is now
// reported as an incomplete-scan warning instead, so it is neither misreported
// nor silently dropped.
func TestWorkflowWithNoJobs_WarnsInsteadOfClaimingMissingPermissions(t *testing.T) {
	s, mux := newTestScanner(t, false)
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows", []*github.RepositoryContent{{
		Path: github.Ptr(".github/workflows/config.yml"),
		Name: github.Ptr("config.yml"),
	}})
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows/config.yml",
		encodedContent(".github/workflows/config.yml", "some_setting: true\nanother: value\n"))

	collector := newTestFactCollector(s)
	workflows := collector.collectWorkflowFacts(context.Background(), "owner", "repo", nil)

	if len(collector.warnings) != 1 || !strings.Contains(collector.warnings[0].Detail, "no jobs") {
		t.Fatalf("warnings = %+v, want one 'no jobs' warning", collector.warnings)
	}

	findings := evaluateWorkflowPermissionsRule(&ScanFacts{Workflows: workflows})
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none — a jobless file has no permissions to declare", findings)
	}
}

// A real workflow that happens to declare no permissions must still be flagged;
// the jobless skip above must not swallow the genuine case.
func TestEvaluateWorkflowPermissionsRule_RealWorkflowStillFlagged(t *testing.T) {
	content := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	workflow := &WorkflowFile{}
	if err := yaml.Unmarshal([]byte(content), workflow); err != nil {
		t.Fatalf("yaml.Unmarshal() error: %v", err)
	}

	findings := evaluateWorkflowPermissionsRule(&ScanFacts{Workflows: []WorkflowFact{{
		Path:     ".github/workflows/ci.yml",
		Content:  content,
		Workflow: workflow,
		Valid:    true,
	}}})
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want one no-permissions finding", findings)
	}
}

func TestEvaluateWorkflowRules_Integration(t *testing.T) {
	content := "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
	workflow := &WorkflowFile{}
	if err := yaml.Unmarshal([]byte(content), workflow); err != nil {
		t.Fatalf("unexpected yaml error: %v", err)
	}

	facts := &ScanFacts{Workflows: []WorkflowFact{{
		Path:     ".github/workflows/ci.yml",
		Content:  content,
		Workflow: workflow,
		Valid:    true,
	}}}
	findings := evaluateDangerousWorkflowRule(facts)
	findings = append(findings, evaluateActionVersionPinningRule(facts)...)
	findings = append(findings, evaluateWorkflowPermissionsRule(facts)...)
	if len(findings) != 3 {
		t.Fatalf("findings len = %d, want 3", len(findings))
	}
}

func TestSanitizeID(t *testing.T) {
	got := sanitizeID("actions/checkout@v4")
	want := "actions-checkout-v4"
	if got != want {
		t.Fatalf("sanitizeID() = %s, want %s", got, want)
	}
}

// write-all is the broadest possible grant, and it PASSES workflow-permissions
// by design (that rule checks presence, not breadth). This rule closes the gap.
func TestEvaluateWriteAllPermissionsRule(t *testing.T) {
	parse := func(t *testing.T, content string) []WorkflowFact {
		t.Helper()
		workflow := &WorkflowFile{}
		if err := yaml.Unmarshal([]byte(content), workflow); err != nil {
			t.Fatalf("yaml.Unmarshal() error: %v", err)
		}
		return []WorkflowFact{{Path: ".github/workflows/ci.yml", Content: content, Workflow: workflow, Valid: true}}
	}

	t.Run("workflow level", func(t *testing.T) {
		facts := &ScanFacts{Workflows: parse(t, "on: push\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")}
		findings := evaluateWriteAllPermissionsRule(facts)
		if len(findings) != 1 || findings[0].ID != "write-all-.github/workflows/ci.yml" {
			t.Fatalf("findings = %+v, want one workflow-level finding", findings)
		}
		if findings[0].Severity != SeverityHigh {
			t.Fatalf("severity = %q, want high", findings[0].Severity)
		}
		// The same workflow must PASS the presence check: explicit-but-broad is
		// exactly the split the two rules exist to express.
		if presence := evaluateWorkflowPermissionsRule(facts); len(presence) != 0 {
			t.Fatalf("workflow-permissions findings = %+v, want none for explicit permissions", presence)
		}
	})

	t.Run("job level, deterministic order", func(t *testing.T) {
		content := "on: push\npermissions: {}\njobs:\n  zeta:\n    permissions: write-all\n    runs-on: ubuntu-latest\n    steps: [{run: echo hi}]\n  alpha:\n    permissions: write-all\n    runs-on: ubuntu-latest\n    steps: [{run: echo hi}]\n"
		findings := evaluateWriteAllPermissionsRule(&ScanFacts{Workflows: parse(t, content)})
		if len(findings) != 2 {
			t.Fatalf("findings = %+v, want two job-level findings", findings)
		}
		if findings[0].ID != "write-all-.github/workflows/ci.yml-alpha" || findings[1].ID != "write-all-.github/workflows/ci.yml-zeta" {
			t.Fatalf("job findings must be name-sorted for deterministic output, got %q then %q", findings[0].ID, findings[1].ID)
		}
	})

	t.Run("read-all and scoped writes are not flagged", func(t *testing.T) {
		for _, content := range []string{
			"on: push\npermissions: read-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: [{run: echo hi}]\n",
			"on: push\npermissions:\n  contents: write\n  issues: write\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: [{run: echo hi}]\n",
		} {
			if findings := evaluateWriteAllPermissionsRule(&ScanFacts{Workflows: parse(t, content)}); len(findings) != 0 {
				t.Fatalf("findings = %+v, want none for:\n%s", findings, content)
			}
		}
	})

	t.Run("jobless and unparsed files are skipped", func(t *testing.T) {
		facts := &ScanFacts{Workflows: []WorkflowFact{
			{Path: "a.yml", Valid: false, Content: "permissions: write-all"},
			{Path: "b.yml", Valid: true, Workflow: &WorkflowFile{Permissions: "write-all"}},
		}}
		if findings := evaluateWriteAllPermissionsRule(facts); len(findings) != 0 {
			t.Fatalf("findings = %+v, want none", findings)
		}
	})
}

// pull_request_target's blast radius depends on whether an external contributor
// can open a PR at all. The severity must track that — and must fail severe
// when the policy is unknown, so a new GitHub enum value can only over-report.
func TestEvaluateDangerousWorkflowRule_SeverityTracksPRCreationPolicy(t *testing.T) {
	prtWorkflow := func(t *testing.T) []WorkflowFact {
		t.Helper()
		content := "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
		workflow := &WorkflowFile{}
		if err := yaml.Unmarshal([]byte(content), workflow); err != nil {
			t.Fatalf("yaml.Unmarshal() error: %v", err)
		}
		return []WorkflowFact{{Path: ".github/workflows/prt.yml", Content: content, Workflow: workflow, Valid: true}}
	}

	cases := []struct {
		name         string
		facts        *ScanFacts
		wantSeverity string
		wantRestrict bool
	}{
		{"public, policy all", &ScanFacts{Repository: &github.Repository{Private: github.Ptr(false)}, PullRequestCreationPolicy: "all"}, SeverityCritical, false},
		{"public, policy unknown stays critical", &ScanFacts{Repository: &github.Repository{}}, SeverityCritical, false},
		{"public, collaborators only", &ScanFacts{Repository: &github.Repository{Private: github.Ptr(false)}, PullRequestCreationPolicy: "collaborators_only"}, SeverityMedium, true},
		{"private repository", &ScanFacts{Repository: &github.Repository{Private: github.Ptr(true)}, PullRequestCreationPolicy: "all"}, SeverityMedium, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.facts.Workflows = prtWorkflow(t)
			findings := evaluateDangerousWorkflowRule(tc.facts)
			if len(findings) != 1 {
				t.Fatalf("findings = %+v, want one", findings)
			}
			if findings[0].Severity != tc.wantSeverity {
				t.Fatalf("severity = %q, want %q", findings[0].Severity, tc.wantSeverity)
			}
			restricted := strings.Contains(findings[0].Title, "restricted")
			if restricted != tc.wantRestrict {
				t.Fatalf("title = %q, restricted-variant = %v, want %v", findings[0].Title, restricted, tc.wantRestrict)
			}
		})
	}
}
