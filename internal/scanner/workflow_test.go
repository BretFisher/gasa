package scanner

import (
	"strings"
	"testing"

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
