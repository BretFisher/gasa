package scanner

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/go-github/v84/github"
)

// isAccessDenied reports whether resp is a determinate "no access" response: a
// 404, or a 403 that is not a rate limit. These mean the setting cannot be read
// for a stable reason (token scope, SSO, repo policy) and are already surfaced
// to the user as an AccessFinding — so they must NOT be counted as an
// incomplete check. A rate-limit 403, a 429, a 5xx, or a transport error
// (resp == nil) is indeterminate and should be flagged.
func isAccessDenied(resp *github.Response) bool {
	if resp == nil || resp.Response == nil {
		return false
	}
	switch resp.StatusCode {
	case http.StatusNotFound:
		return true
	case http.StatusForbidden:
		return !isPrimaryRateLimitResponse(resp.Response)
	default:
		return false
	}
}

// isForkPRApprovalUnsupported reports whether GitHub answered the fork-PR
// contributor approval endpoint with "this setting does not apply here".
//
// Private repositories return 422 with "Fork PR approval is not allowed for
// private repositories". That is a determinate answer about the repository, not
// a failure to read it, so it must not be treated as an access denial or a
// transient error — both of those would report a control that cannot exist as
// unverified.
func isForkPRApprovalUnsupported(resp *github.Response) bool {
	return resp != nil && resp.Response != nil && resp.StatusCode == http.StatusUnprocessableEntity
}

func (c *factCollector) collectActionsSettingsFacts(ctx context.Context, owner, repo string, dbg DebugLogger) ActionsSettingsFacts {
	facts := ActionsSettingsFacts{}
	repoFull := owner + "/" + repo

	if dbg != nil {
		dbg(repoFull, "GET /repos/"+repoFull+"/actions/permissions")
	}
	permissions, resp, err := c.client.Repositories.GetActionsPermissions(ctx, owner, repo)
	if err != nil {
		c.recordSettingsFetchFailure(&facts, resp, err, repoFull, dbg)
		return facts
	}
	if dbg != nil {
		enabled := permissions.GetEnabled()
		allowedActions := permissions.GetAllowedActions()
		dbg(repoFull, fmt.Sprintf("actions/permissions: enabled=%v allowed_actions=%q", enabled, allowedActions))
	}

	facts.Permissions = permissions
	// Actions is enabled but GitHub did not report a policy value. Observed when
	// an org or enterprise policy governs the repository. Without this the rule
	// would emit neither a finding nor a success and vanish from the report.
	if permissions.AllowedActions == nil && (permissions.Enabled == nil || *permissions.Enabled) {
		facts.markUndetermined(settingAllowedActions, "GitHub did not report an allowed-actions value for this repository")
		if dbg != nil {
			dbg(repoFull, "actions/permissions: allowed_actions absent — undetermined")
		}
	}
	if permissions.Enabled != nil && !*permissions.Enabled {
		if dbg != nil {
			dbg(repoFull, "actions disabled for this repo — skipping workflow/fork-pr settings")
		}
		return facts
	}

	if c.authenticated {
		fetchAuthenticatedActionsSettings(ctx, c, owner, repo, &facts, repoFull, dbg)
	} else if dbg != nil {
		dbg(repoFull, "unauthenticated — skipping workflow permissions and fork-pr-approval checks")
	}

	return facts
}

// recordSettingsFetchFailure classifies a failed top-level Actions settings
// read. Three distinct causes get three distinct messages:
//
//   - unauthenticated      → tell them to supply a token
//   - authenticated denial → tell them exactly which permission to add
//   - transient (5xx, …)   → an incomplete-scan warning with the real cause
//
// A denial is determinate and fully explained by its finding, so it is NOT also
// counted as incomplete — that would double-report and erode trust in the
// incomplete warning.
func (c *factCollector) recordSettingsFetchFailure(facts *ActionsSettingsFacts, resp *github.Response, err error, repoFull string, dbg DebugLogger) {
	switch {
	case !c.authenticated:
		setUnauthenticatedAccessFinding(facts)
	case isAccessDenied(resp):
		setAccessDeniedFinding(facts)
	default:
		// Transient failure: unlike the two cases above it produces no access
		// finding, so without marking every setting undetermined the rules would
		// fall through to their success helpers. Those read "Actions disabled"
		// off a nil Permissions pointer and would report that as a pass — a
		// claim about a setting the scanner never managed to read.
		cause := describeFetchError(err)
		c.addWarning("actions settings", cause)
		for _, setting := range []string{settingAllowedActions, settingWorkflowPermissions, settingForkPRApproval} {
			facts.markUndetermined(setting, cause)
		}
	}
	if dbg != nil {
		dbg(repoFull, "actions/permissions fetch error: "+err.Error())
	}
}

// setAccessDeniedFinding records that an authenticated token was accepted but
// lacks the repository-admin permission needed to read Actions settings. The
// remediation names the exact scope/permission for both token types so the user
// can fix it without guessing — reading these settings requires repo admin even
// on public repos, and GitHub returns 403/404 when it is missing.
func setAccessDeniedFinding(facts *ActionsSettingsFacts) {
	facts.AccessFinding = &Finding{
		ID:       findingIDSettingsCheckFailed,
		Severity: SeverityInfo,
		Title:    "Actions settings check skipped — token lacks repo admin access",
		Description: "The token was accepted but cannot read this repository's Actions security settings " +
			"(allowed-actions policy, default workflow permissions, fork-PR approval), so those checks were skipped. " +
			"Reading them requires admin access to the repository.",
		Remediation: "Grant the token repository admin access, then re-run:\n" +
			"  • classic PAT: add the `repo` scope (full control of private repositories)\n" +
			"  • fine-grained PAT: set Repository permissions → `Administration` to Read-only\n" +
			"  • gh CLI token: run `gh auth refresh -s repo` (or use a PAT with the scopes above)\n" +
			"If the repository belongs to an org with SSO enforced, also authorize the token for that org. " +
			"Alternatively, review the settings manually under Settings → Actions → General.",
	}
}

// setUnauthenticatedAccessFinding records that Actions settings could not be
// read because no token was supplied. These settings are never available
// anonymously, so the fix is to authenticate.
func setUnauthenticatedAccessFinding(facts *ActionsSettingsFacts) {
	facts.AccessFinding = &Finding{
		ID:          findingIDSettingsCheckUnavailable,
		Severity:    SeverityInfo,
		Title:       "Actions settings check requires authentication",
		Description: "Repository Actions settings (allowed-actions policy, default workflow permissions, fork-PR approval) can only be read with an authenticated GitHub token that has repository admin access.",
		Remediation: "Authenticate with a token that has repo admin access: set GITHUB_TOKEN, pass one via --token-stdin, or sign in with the gh CLI (`gh auth login`). See the access-denied guidance for the exact scopes.",
	}
}

// fetchAuthenticatedActionsSettings retrieves workflow permissions and fork-PR
// approval policy, which require an authenticated token.
func fetchAuthenticatedActionsSettings(ctx context.Context, c *factCollector, owner, repo string, facts *ActionsSettingsFacts, repoFull string, dbg DebugLogger) {
	if dbg != nil {
		dbg(repoFull, "GET /repos/"+repoFull+"/actions/permissions/workflow")
	}
	perms, resp, err := c.client.Repositories.GetDefaultWorkflowPermissions(ctx, owner, repo)
	switch {
	case err == nil:
		facts.DefaultWorkflowPermissions = perms
		if dbg != nil {
			dbg(repoFull, fmt.Sprintf("workflow permissions: default=%q can_approve_prs=%v",
				perms.GetDefaultWorkflowPermissions(), perms.GetCanApprovePullRequestReviews()))
		}
	case isAccessDenied(resp):
		// Determinate as an HTTP outcome, but NOT determinate as a security
		// answer: the settings are whatever they are, we simply could not read
		// them. Recording it lets the rules report "could not determine" rather
		// than disappearing from the report entirely.
		facts.markUndetermined(settingWorkflowPermissions, fmt.Sprintf("GitHub returned %d — the token cannot read this setting", resp.StatusCode))
		if dbg != nil {
			dbg(repoFull, fmt.Sprintf("workflow permissions fetch: status %d — undetermined", resp.StatusCode))
		}
	default:
		facts.markUndetermined(settingWorkflowPermissions, describeFetchError(err))
		c.addWarning("workflow default permissions", describeFetchError(err))
		if dbg != nil {
			dbg(repoFull, "workflow permissions fetch could not be determined: "+describeFetchError(err))
		}
	}

	if dbg != nil {
		dbg(repoFull, "GET /repos/"+repoFull+"/actions/permissions/fork-pr-contributor-approval")
	}
	policy, resp, err := c.client.Actions.GetForkPRContributorApprovalPermissions(ctx, owner, repo)
	switch {
	case err == nil:
		facts.ForkPRContributorApproval = policy
		if dbg != nil {
			dbg(repoFull, "fork-pr-approval: policy="+policy.ApprovalPolicy)
		}
	case isForkPRApprovalUnsupported(resp):
		facts.ForkPRApprovalNotApplicable = true
		if dbg != nil {
			dbg(repoFull, "fork-pr-approval: not applicable to this repository (HTTP 422)")
		}
	case isAccessDenied(resp):
		facts.markUndetermined(settingForkPRApproval, fmt.Sprintf("GitHub returned %d — the token cannot read this setting", resp.StatusCode))
		if dbg != nil {
			dbg(repoFull, fmt.Sprintf("fork-pr-approval fetch: status %d — undetermined", resp.StatusCode))
		}
	default:
		facts.markUndetermined(settingForkPRApproval, describeFetchError(err))
		c.addWarning("fork-PR contributor approval", describeFetchError(err))
		if dbg != nil {
			dbg(repoFull, "fork-pr-approval fetch could not be determined: "+describeFetchError(err))
		}
	}
}
