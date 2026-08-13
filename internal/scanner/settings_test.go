package scanner

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-github/v90/github"
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

// A refused fork-PR sub-call must be reported as undetermined, not skipped. The
// top-level settings call succeeded, so no access finding is recorded, and the
// rule used to emit nothing at all — leaving a high-severity check silently
// absent from a report that still looked clean.
func TestEvaluateForkPRApprovalPolicy_ForbiddenReportsUndetermined(t *testing.T) {
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
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one undetermined finding", findings)
	}
	f := findings[0]
	if f.Rule != ruleNameForkPRContributorApproval {
		t.Fatalf("rule = %q, want %q", f.Rule, ruleNameForkPRContributorApproval)
	}
	if f.Severity != SeverityInfo {
		t.Fatalf("severity = %q, want info — a coverage hole is not a vulnerability", f.Severity)
	}
	if f.Success {
		t.Fatal("an undetermined check must never be recorded as a success")
	}
	if !strings.Contains(f.Description, "403") {
		t.Fatalf("description should name the cause, got %q", f.Description)
	}
}

// Both rules that read /actions/permissions/workflow must report undetermined
// when it is refused, and their findings must not collide under dedupe.
func TestEvaluateWorkflowSettings_ForbiddenReportsUndeterminedForBothRules(t *testing.T) {
	s, mux := newTestScanner(t, true)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	mux.HandleFunc("/repos/owner/repo/actions/permissions/workflow", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "all_external_contributors"})

	findings := collectAndEvaluateActionsSettings(t, s)
	got := make(map[string]bool)
	for _, f := range findings {
		got[f.Rule] = true
	}
	for _, want := range []string{ruleNameDefaultWorkflowPermissions, ruleNameActionsCanApprovePRs} {
		if !got[want] {
			t.Fatalf("rule %q did not report undetermined; findings = %+v", want, findings)
		}
	}
}

// An absent allowed_actions value on an enabled repository is undetermined, not
// clean. GitHub omits it when an org or enterprise policy governs the repo.
func TestEvaluateAllowedActions_AbsentValueReportsUndetermined(t *testing.T) {
	s, mux := newTestScanner(t, true)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "all_external_contributors"})

	facts := &ScanFacts{ActionsSettings: newTestFactCollector(s).collectActionsSettingsFacts(context.Background(), "owner", "repo", nil)}
	findings := evaluateAllowedActionsPolicyRule(facts)
	if len(findings) != 1 || findings[0].Rule != ruleNameAllowedActionsPolicy {
		t.Fatalf("findings = %+v, want one undetermined allowed-actions finding", findings)
	}
	if findings[0].Severity != SeverityInfo || findings[0].Success {
		t.Fatalf("undetermined finding = %+v, want info severity and not a success", findings[0])
	}
}

// A transient failure on the top-level settings call produces no access
// finding, so before this was fixed every settings rule fell through to its
// success helper and reported "GitHub Actions are disabled for this repository"
// — a claim about a setting the scanner never read. All four rules must instead
// report undetermined, and the scan must be marked incomplete.
func TestCollectActionsSettings_TransientErrorIsNotReportedAsDisabled(t *testing.T) {
	s, mux := newTestScanner(t, true)
	mux.HandleFunc("/repos/owner/repo/actions/permissions", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	collector := newTestFactCollector(s)
	facts := &ScanFacts{ActionsSettings: collector.collectActionsSettingsFacts(context.Background(), "owner", "repo", nil)}

	if len(collector.warnings) == 0 {
		t.Fatal("a transient settings failure must mark the scan incomplete")
	}

	for _, tc := range []struct {
		name string
		run  func(*ScanFacts) []Finding
		rule string
	}{
		{"allowed-actions", evaluateAllowedActionsPolicyRule, ruleNameAllowedActionsPolicy},
		{"default-workflow-permissions", evaluateDefaultWorkflowPermissionsRule, ruleNameDefaultWorkflowPermissions},
		{"actions-can-approve-prs", evaluateActionsCanApprovePRsRule, ruleNameActionsCanApprovePRs},
		{"fork-pr-approval", evaluateForkPRContributorApprovalRule, ruleNameForkPRContributorApproval},
		{"sha-pinning-required", evaluateSHAPinningRequiredRule, ruleNameSHAPinningRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings := tc.run(facts)
			if len(findings) != 1 || findings[0].Rule != tc.rule {
				t.Fatalf("findings = %+v, want one undetermined finding for %s", findings, tc.rule)
			}
			if findings[0].Success {
				t.Fatal("an unread setting must never be reported as a success")
			}
		})
	}
}

// actionsObservedDisabled must separate "GitHub said Actions is off" from "we
// never managed to ask". Only the first may be reported as a pass.
func TestActionsObservedDisabled_RequiresAnActualObservation(t *testing.T) {
	unread := &ScanFacts{}
	if actionsObservedDisabled(unread) {
		t.Fatal("a nil Permissions pointer means unread, not disabled")
	}

	disabled := &ScanFacts{ActionsSettings: ActionsSettingsFacts{
		Permissions: &github.ActionsPermissionsRepository{Enabled: github.Ptr(false)},
	}}
	if !actionsObservedDisabled(disabled) {
		t.Fatal("enabled:false was observed and must count as disabled")
	}

	enabled := &ScanFacts{ActionsSettings: ActionsSettingsFacts{
		Permissions: &github.ActionsPermissionsRepository{Enabled: github.Ptr(true)},
	}}
	if actionsObservedDisabled(enabled) {
		t.Fatal("enabled:true is not disabled")
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

// A 403/404 on the sub-calls leaves the values unset and raises no incomplete
// warning — the denial is determinate as an HTTP outcome, so it is not a
// transient failure. The rules still surface it as an undetermined finding
// (see the ForbiddenReportsUndetermined tests); this test covers only the
// collection side.
func TestFetchAuthenticatedSettings_DeniedLeavesValuesUnset(t *testing.T) {
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

// GitHub answers the fork-PR approval endpoint with 422 on private repositories
// ("Fork PR approval is not allowed for private repositories"). That is a
// determinate answer about the repository, not a failed read, so it must not
// produce an undetermined finding or an incomplete-scan warning — doing so
// reported a control that cannot exist as unverified on every private scan.
func TestForkPRApproval_UnsupportedOnPrivateRepoIsNotApplicable(t *testing.T) {
	s, mux := newTestScanner(t, true)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false})
	mux.HandleFunc("/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		if _, err := w.Write([]byte(`{"message":"Fork PR approval is not allowed for private repositories."}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	})

	collector := newTestFactCollector(s)
	facts := &ScanFacts{ActionsSettings: collector.collectActionsSettingsFacts(context.Background(), "owner", "repo", nil)}

	if !facts.ActionsSettings.ForkPRApprovalNotApplicable {
		t.Fatal("expected the 422 to be recorded as not applicable")
	}
	if len(collector.warnings) != 0 {
		t.Fatalf("a setting that does not exist must not mark the scan incomplete, got %+v", collector.warnings)
	}
	if findings := evaluateForkPRContributorApprovalRule(facts); len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}

	success := forkPRApprovalSuccessFinding(ruleNameForkPRContributorApproval, SeverityHigh, facts)
	if success == nil {
		t.Fatal("expected a success finding explaining the setting does not apply")
	}
	if !strings.Contains(success.Title, "does not apply") {
		t.Fatalf("success title = %q, want it to say the setting does not apply", success.Title)
	}
}

// A finding that deliberately sets its own severity must keep it. Stamping the
// rule's severity over every finding reported "could not determine" — a gap in
// coverage — at the full severity of the rule, inflating the counts operators
// trust.
func TestApplyRuleConfig_PreservesDeliberateFindingSeverity(t *testing.T) {
	r := rule{RuleInfo: RuleInfo{Name: ruleNameForkPRContributorApproval, Severity: SeverityHigh, Category: categorySettings}}

	got := applyRuleConfig([]Finding{{ID: "undetermined-x", Severity: SeverityInfo}}, r, nil)
	if got[0].Severity != SeverityInfo {
		t.Fatalf("severity = %q, want info to survive", got[0].Severity)
	}

	// A finding that sets nothing still inherits the rule's severity.
	got = applyRuleConfig([]Finding{{ID: "plain"}}, r, nil)
	if got[0].Severity != SeverityHigh {
		t.Fatalf("severity = %q, want the rule default when the finding sets none", got[0].Severity)
	}

	// An explicit user override still wins.
	cfg := &Config{Overrides: []RuleOverride{{Rule: ruleNameForkPRContributorApproval, Severity: "low"}}}
	got = applyRuleConfig([]Finding{{ID: "undetermined-x", Severity: SeverityInfo}}, r, cfg)
	if got[0].Severity != SeverityLow {
		t.Fatalf("severity = %q, want the config override to win", got[0].Severity)
	}
}

// The SHA-pinning setting rides in the same /actions/permissions response the
// allowed-actions rule reads, so this rule costs no additional API call — and
// it has to handle every state that response can be in.
func TestEvaluateSHAPinningRequiredRule(t *testing.T) {
	collect := func(t *testing.T, payload map[string]any) *ScanFacts {
		t.Helper()
		s, mux := newTestScanner(t, true)
		handleJSON(mux, "/repos/owner/repo/actions/permissions", payload)
		handleJSON(mux, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false})
		handleJSON(mux, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "all_external_contributors"})
		return &ScanFacts{ActionsSettings: newTestFactCollector(s).collectActionsSettingsFacts(context.Background(), "owner", "repo", nil)}
	}

	t.Run("not required is a medium finding", func(t *testing.T) {
		facts := collect(t, map[string]any{"enabled": true, "allowed_actions": "selected", "sha_pinning_required": false})
		findings := evaluateSHAPinningRequiredRule(facts)
		if len(findings) != 1 || findings[0].ID != findingIDSHAPinningNotRequired {
			t.Fatalf("findings = %+v, want one not-required finding", findings)
		}
		if findings[0].Severity != SeverityMedium {
			t.Fatalf("severity = %q, want medium", findings[0].Severity)
		}
	})

	t.Run("required passes", func(t *testing.T) {
		facts := collect(t, map[string]any{"enabled": true, "allowed_actions": "selected", "sha_pinning_required": true})
		if findings := evaluateSHAPinningRequiredRule(facts); len(findings) != 0 {
			t.Fatalf("findings = %+v, want none", findings)
		}
		if shaPinningRequiredSuccessFinding(ruleNameSHAPinningRequired, SeverityMedium, facts) == nil {
			t.Fatal("expected a success finding when enforcement is on")
		}
	})

	t.Run("absent value is undetermined, not clean", func(t *testing.T) {
		facts := collect(t, map[string]any{"enabled": true, "allowed_actions": "selected"})
		findings := evaluateSHAPinningRequiredRule(facts)
		if len(findings) != 1 || findings[0].Severity != SeverityInfo || findings[0].Success {
			t.Fatalf("findings = %+v, want one info undetermined finding", findings)
		}
		if shaPinningRequiredSuccessFinding(ruleNameSHAPinningRequired, SeverityMedium, facts) != nil {
			t.Fatal("an unread setting must never be reported as a success")
		}
	})

	t.Run("actions observed disabled passes with its own message", func(t *testing.T) {
		facts := collect(t, map[string]any{"enabled": false})
		if findings := evaluateSHAPinningRequiredRule(facts); len(findings) != 0 {
			t.Fatalf("findings = %+v, want none", findings)
		}
		success := shaPinningRequiredSuccessFinding(ruleNameSHAPinningRequired, SeverityMedium, facts)
		if success == nil || !strings.Contains(success.Title, "Actions are disabled") {
			t.Fatalf("success = %+v, want the disabled pass", success)
		}
	})
}
