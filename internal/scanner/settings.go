package scanner

import (
	"context"
	"fmt"
)

func (c *factCollector) collectActionsSettingsFacts(ctx context.Context, owner, repo string, dbg DebugLogger) ActionsSettingsFacts {
	facts := ActionsSettingsFacts{}
	repoFull := owner + "/" + repo

	if dbg != nil {
		dbg(repoFull, "GET /repos/"+repoFull+"/actions/permissions")
	}
	permissions, _, err := c.client.Repositories.GetActionsPermissions(ctx, owner, repo)
	if err != nil {
		setAccessFinding(&facts, c.authenticated)
		if dbg != nil {
			dbg(repoFull, "actions/permissions fetch error: "+err.Error())
		}
		return facts
	}
	if dbg != nil {
		enabled := permissions.GetEnabled()
		allowedActions := permissions.GetAllowedActions()
		dbg(repoFull, fmt.Sprintf("actions/permissions: enabled=%v allowed_actions=%q", enabled, allowedActions))
	}

	facts.Permissions = permissions
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

// setAccessFinding populates facts.AccessFinding with the appropriate finding
// depending on whether the caller was authenticated.
func setAccessFinding(facts *ActionsSettingsFacts, authenticated bool) {
	if authenticated {
		facts.AccessFinding = &Finding{
			ID:          findingIDSettingsCheckFailed,
			Severity:    SeverityInfo,
			Title:       "Actions settings check failed",
			Description: "Could not read repository Actions settings. Your token may lack the required permissions (classic PAT `repo` scope or fine-grained `Administration: Read`).",
			Remediation: "Ensure your token has admin access to this repository, or manually review Settings > Actions > General.",
		}
	} else {
		facts.AccessFinding = &Finding{
			ID:          findingIDSettingsCheckUnavailable,
			Severity:    SeverityInfo,
			Title:       "Actions settings check requires authentication",
			Description: "Repository Actions settings (allowed actions policy, default permissions) can only be checked with an authenticated GitHub token.",
			Remediation: "Set GITHUB_TOKEN, pass a token with --token-stdin, or install the gh CLI to enable this check.",
		}
	}
}

// fetchAuthenticatedActionsSettings retrieves workflow permissions and fork-PR
// approval policy, which require an authenticated token.
func fetchAuthenticatedActionsSettings(ctx context.Context, c *factCollector, owner, repo string, facts *ActionsSettingsFacts, repoFull string, dbg DebugLogger) {
	if dbg != nil {
		dbg(repoFull, "GET /repos/"+repoFull+"/actions/permissions/workflow")
	}
	perms, resp, err := c.client.Repositories.GetDefaultWorkflowPermissions(ctx, owner, repo)
	if err == nil {
		facts.DefaultWorkflowPermissions = perms
		if dbg != nil {
			dbg(repoFull, fmt.Sprintf("workflow permissions: default=%q can_approve_prs=%v",
				perms.GetDefaultWorkflowPermissions(), perms.GetCanApprovePullRequestReviews()))
		}
	} else if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
		if dbg != nil {
			dbg(repoFull, fmt.Sprintf("workflow permissions fetch: status %d — skipped", resp.StatusCode))
		}
	}

	if dbg != nil {
		dbg(repoFull, "GET /repos/"+repoFull+"/actions/permissions/fork-pr-contributor-approval")
	}
	policy, resp, err := c.client.Actions.GetForkPRContributorApprovalPermissions(ctx, owner, repo)
	if err == nil {
		facts.ForkPRContributorApproval = policy
		if dbg != nil {
			dbg(repoFull, "fork-pr-approval: policy="+policy.ApprovalPolicy)
		}
	} else if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
		if dbg != nil {
			dbg(repoFull, fmt.Sprintf("fork-pr-approval fetch: status %d — skipped", resp.StatusCode))
		}
	}
}
