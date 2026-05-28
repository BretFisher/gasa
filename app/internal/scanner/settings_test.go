package scanner

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestEvaluateActionsSettings_AllActionsAllowed(t *testing.T) {
	s, mux := newTestScanner(t, true)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "all"})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "all_external_contributors"})

	findings := collectAndEvaluateActionsSettings(t, s)
	if len(findings) != 1 || findings[0].ID != "settings-all-actions-allowed" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestEvaluateActionsSettings_LocalOnly(t *testing.T) {
	s, mux := newTestScanner(t, false)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "local_only"})
	findings := collectAndEvaluateActionsSettings(t, s)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestEvaluateActionsSettings_Selected(t *testing.T) {
	s, mux := newTestScanner(t, false)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	findings := collectAndEvaluateActionsSettings(t, s)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestEvaluateActionsSettings_Disabled(t *testing.T) {
	s, mux := newTestScanner(t, false)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": false, "allowed_actions": "all"})
	findings := collectAndEvaluateActionsSettings(t, s)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}

func TestEvaluateActionsSettings_Unauthenticated(t *testing.T) {
	s, mux := newTestScanner(t, false)
	mux.HandleFunc("/repos/owner/repo/actions/permissions", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"forbidden"}`))
	})
	findings := collectAndEvaluateActionsSettings(t, s)
	if len(findings) != 1 || findings[0].ID != "settings-check-unavailable" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestEvaluateActionsSettings_AuthFailed(t *testing.T) {
	s, mux := newTestScanner(t, true)
	mux.HandleFunc("/repos/owner/repo/actions/permissions", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"forbidden"}`))
	})
	findings := collectAndEvaluateActionsSettings(t, s)
	if len(findings) != 1 || findings[0].ID != "settings-check-failed" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestCollectActionsSettingsFacts_DebugLogsValues(t *testing.T) {
	s, mux := newTestScanner(t, true)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "all_external_contributors"})

	var lines []string
	dbg := func(repo, msg string) {
		lines = append(lines, repo+"|"+msg)
	}

	facts := newTestFactCollector(s).collectActionsSettingsFacts(context.Background(), "owner", "repo", dbg)
	if facts.Permissions == nil {
		t.Fatalf("expected permissions facts, got %+v", facts)
	}
	requireContainsLine(t, lines, "GET /repos/owner/repo/actions/permissions")
	requireContainsLine(t, lines, `actions/permissions: enabled=true allowed_actions="selected"`)
	requireContainsLine(t, lines, `workflow permissions: default="read" can_approve_prs=false`)
	requireContainsLine(t, lines, "fork-pr-approval: policy=all_external_contributors")
	for _, line := range lines {
		if !strings.HasPrefix(line, "owner/repo|") {
			t.Fatalf("debug line %q missing repo prefix", line)
		}
	}
}

func TestEvaluateDefaultWorkflowPermissions_WriteAndApprove(t *testing.T) {
	s, mux := newTestScanner(t, true)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "write", "can_approve_pull_request_reviews": true})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "all_external_contributors"})
	findings := collectAndEvaluateActionsSettings(t, s)
	if len(findings) != 2 {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestEvaluateDefaultWorkflowPermissions_Read(t *testing.T) {
	s, mux := newTestScanner(t, true)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "all_external_contributors"})
	findings := collectAndEvaluateActionsSettings(t, s)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestEvaluateForkPRApprovalPolicy(t *testing.T) {
	s, mux := newTestScanner(t, true)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "first_time_contributors"})
	findings := collectAndEvaluateActionsSettings(t, s)
	if len(findings) != 1 || findings[0].ID != "settings-fork-pr-contributor-approval-too-permissive" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestEvaluateForkPRApprovalPolicy_AllExternal(t *testing.T) {
	s, mux := newTestScanner(t, true)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "all_external_contributors"})
	findings := collectAndEvaluateActionsSettings(t, s)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestEvaluateForkPRApprovalPolicy_ForbiddenSkips(t *testing.T) {
	s, mux := newTestScanner(t, true)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false})
	mux.HandleFunc("/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"forbidden"}`))
	})
	findings := collectAndEvaluateActionsSettings(t, s)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v", findings)
	}
}

func collectAndEvaluateActionsSettings(t *testing.T, s *Scanner) []Finding {
	t.Helper()
	facts := &ScanFacts{ActionsSettings: newTestFactCollector(s).collectActionsSettingsFacts(context.Background(), "owner", "repo", nil)}
	findings := evaluateAllowedActionsPolicyRule(facts)
	findings = append(findings, evaluateDefaultWorkflowPermissionsRule(facts)...)
	findings = append(findings, evaluateActionsCanApprovePRsRule(facts)...)
	findings = append(findings, evaluateForkPRContributorApprovalRule(facts)...)
	return dedupeFindings(findings)
}
