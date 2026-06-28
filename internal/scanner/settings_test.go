package scanner

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-github/v84/github"
)

func TestIsAccessDenied(t *testing.T) {
	resp := func(status int, rateLimited bool) *github.Response {
		h := http.Header{}
		if rateLimited {
			h.Set("X-RateLimit-Remaining", "0")
		}
		return &github.Response{Response: &http.Response{StatusCode: status, Header: h}}
	}
	tests := []struct {
		name string
		resp *github.Response
		want bool
	}{
		{"nil response (transport error)", nil, false},
		{"404 not found", resp(http.StatusNotFound, false), true},
		{"403 permissions", resp(http.StatusForbidden, false), true},
		{"403 primary rate limit", resp(http.StatusForbidden, true), false},
		{"429 too many requests", resp(http.StatusTooManyRequests, false), false},
		{"500 server error", resp(http.StatusInternalServerError, false), false},
		{"200 ok", resp(http.StatusOK, false), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAccessDenied(tt.resp); got != tt.want {
				t.Fatalf("isAccessDenied() = %v, want %v", got, tt.want)
			}
		})
	}
}

// A permissions denial (403) is surfaced as an actionable AccessFinding and must
// NOT also be counted as an incomplete check — otherwise every under-scoped scan
// would carry a noisy, misleading warning. The remediation must name the exact
// scope/permission for each token type so the user can fix it without guessing.
func TestCollectActionsSettings_PermissionDeniedGivesActionableFinding(t *testing.T) {
	s, mux := newTestScanner(t, true)
	mux.HandleFunc("/repos/owner/repo/actions/permissions", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	collector := newTestFactCollector(s)
	facts := collector.collectActionsSettingsFacts(context.Background(), "owner", "repo", nil)

	if facts.AccessFinding == nil {
		t.Fatalf("expected an AccessFinding for denied settings")
	}
	if facts.AccessFinding.ID != findingIDSettingsCheckFailed {
		t.Fatalf("AccessFinding.ID = %q, want %q", facts.AccessFinding.ID, findingIDSettingsCheckFailed)
	}
	// The remediation must be specific enough to act on without guessing.
	for _, want := range []string{"repo", "Administration", "gh auth refresh", "SSO"} {
		if !strings.Contains(facts.AccessFinding.Remediation, want) {
			t.Errorf("remediation missing actionable detail %q:\n%s", want, facts.AccessFinding.Remediation)
		}
	}
	if len(collector.warnings) != 0 {
		t.Fatalf("permission denial must not produce incomplete warnings, got %+v", collector.warnings)
	}
}

// A transient failure (5xx) IS indeterminate: it must warn (so the partial scan
// is visible) and must NOT masquerade as a permissions problem.
func TestCollectActionsSettings_TransientErrorIsIncompleteNotDenial(t *testing.T) {
	s, mux := newTestScanner(t, true)
	handle500(mux, "/repos/owner/repo/actions/permissions")

	collector := newTestFactCollector(s)
	facts := collector.collectActionsSettingsFacts(context.Background(), "owner", "repo", nil)

	if len(collector.warnings) != 1 || collector.warnings[0].Area != "actions settings" {
		t.Fatalf("transient settings error should warn once, got %+v", collector.warnings)
	}
	if facts.AccessFinding != nil {
		t.Fatalf("transient error must not produce a permissions AccessFinding, got %+v", facts.AccessFinding)
	}
}

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
	mux.HandleFunc("/repos/owner/repo/actions/permissions", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte(`{"message":"forbidden"}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	})
	findings := collectAndEvaluateActionsSettings(t, s)
	if len(findings) != 1 || findings[0].ID != "settings-check-unavailable" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestEvaluateActionsSettings_AuthFailed(t *testing.T) {
	s, mux := newTestScanner(t, true)
	mux.HandleFunc("/repos/owner/repo/actions/permissions", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte(`{"message":"forbidden"}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
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

func TestEvaluateDefaultWorkflowPermissions_RemediationWarning(t *testing.T) {
	s, mux := newTestScanner(t, true)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "write", "can_approve_pull_request_reviews": false})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "all_external_contributors"})
	findings := collectAndEvaluateActionsSettings(t, s)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	finding := findings[0]
	if finding.ID != "settings-default-permissions-write" {
		t.Fatalf("expected finding ID 'settings-default-permissions-write', got %s", finding.ID)
	}
	// Verify the remediation includes the warning about breaking workflows
	if !strings.Contains(finding.Remediation, "WARNING") {
		t.Errorf("remediation missing WARNING: %s", finding.Remediation)
	}
	if !strings.Contains(finding.Remediation, "verify all workflows have explicit permissions blocks") {
		t.Errorf("remediation missing warning about verifying workflows: %s", finding.Remediation)
	}
	if !strings.Contains(finding.Remediation, "workflow-permissions rule") {
		t.Errorf("remediation missing reference to workflow-permissions rule: %s", finding.Remediation)
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
	mux.HandleFunc("/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte(`{"message":"forbidden"}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	})
	findings := collectAndEvaluateActionsSettings(t, s)
	if len(findings) != 0 {
		t.Fatalf("findings = %+v", findings)
	}
}

// A 404 on the main settings call (GitHub hides repos you can't admin behind a
// 404, not just 403) must be treated identically to a 403 denial.
func TestCollectActionsSettings_NotFoundTreatedAsDenial(t *testing.T) {
	s, mux := newTestScanner(t, true)
	handle404(mux, "/repos/owner/repo/actions/permissions")

	collector := newTestFactCollector(s)
	facts := collector.collectActionsSettingsFacts(context.Background(), "owner", "repo", nil)

	if facts.AccessFinding == nil || facts.AccessFinding.ID != findingIDSettingsCheckFailed {
		t.Fatalf("AccessFinding = %+v, want %q", facts.AccessFinding, findingIDSettingsCheckFailed)
	}
	if len(collector.warnings) != 0 {
		t.Fatalf("a 404 denial must not warn, got %+v", collector.warnings)
	}
}

// The unauthenticated finding must tell the user how to authenticate.
func TestCollectActionsSettings_UnauthenticatedRemediationIsActionable(t *testing.T) {
	s, mux := newTestScanner(t, false)
	handle404(mux, "/repos/owner/repo/actions/permissions")

	facts := newTestFactCollector(s).collectActionsSettingsFacts(context.Background(), "owner", "repo", nil)

	if facts.AccessFinding == nil || facts.AccessFinding.ID != findingIDSettingsCheckUnavailable {
		t.Fatalf("AccessFinding = %+v, want %q", facts.AccessFinding, findingIDSettingsCheckUnavailable)
	}
	for _, want := range []string{"GITHUB_TOKEN", "--token-stdin", "gh auth login"} {
		if !strings.Contains(facts.AccessFinding.Remediation, want) {
			t.Errorf("unauthenticated remediation missing %q:\n%s", want, facts.AccessFinding.Remediation)
		}
	}
}

// The two authenticated sub-calls (default workflow permissions, fork-PR
// approval) each warn when they fail transiently — so a partial settings read
// is never silently dropped.
func TestFetchAuthenticatedSettings_TransientErrorsWarn(t *testing.T) {
	s, mux := newTestScanner(t, true)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	handle500(mux,
		"/repos/owner/repo/actions/permissions/workflow",
		"/repos/owner/repo/actions/permissions/fork-pr-contributor-approval",
	)

	collector := newTestFactCollector(s)
	facts := collector.collectActionsSettingsFacts(context.Background(), "owner", "repo", nil)

	if facts.AccessFinding != nil {
		t.Fatalf("main call succeeded; no AccessFinding expected, got %+v", facts.AccessFinding)
	}
	if facts.DefaultWorkflowPermissions != nil || facts.ForkPRContributorApproval != nil {
		t.Fatalf("sub-call values should be unset on error")
	}
	gotAreas := map[string]bool{}
	for _, w := range collector.warnings {
		gotAreas[w.Area] = true
	}
	for _, want := range []string{"workflow default permissions", "fork-PR contributor approval"} {
		if !gotAreas[want] {
			t.Errorf("missing transient warning for %q; warnings=%+v", want, collector.warnings)
		}
	}
}

// A 403/404 on the sub-calls is a determinate denial: skipped, with neither a
// finding nor an incomplete warning (the main settings finding already explains
// the missing permission). This covers the default-workflow-permissions skip
// branch that the fork-PR test does not.
func TestFetchAuthenticatedSettings_DeniedSkipsQuietly(t *testing.T) {
	s, mux := newTestScanner(t, true)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	mux.HandleFunc("/repos/owner/repo/actions/permissions/workflow", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	handle404(mux, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval")

	collector := newTestFactCollector(s)
	facts := collector.collectActionsSettingsFacts(context.Background(), "owner", "repo", nil)

	if len(collector.warnings) != 0 {
		t.Fatalf("denied sub-calls must not warn, got %+v", collector.warnings)
	}
	if facts.DefaultWorkflowPermissions != nil || facts.ForkPRContributorApproval != nil {
		t.Fatalf("denied sub-call values should be unset")
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
