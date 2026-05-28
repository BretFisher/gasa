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
		if c.authenticated {
			facts.AccessFinding = &Finding{
				ID:          "settings-check-failed",
				Severity:    SeverityInfo,
				Title:       "Actions settings check failed",
				Description: "Could not read repository Actions settings. Your token may lack the required permissions (classic PAT `repo` scope or fine-grained `Administration: Read`).",
				Remediation: "Ensure your token has admin access to this repository, or manually review Settings > Actions > General.",
				DocURL:      "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository",
			}
		} else {
			facts.AccessFinding = &Finding{
				ID:          "settings-check-unavailable",
				Severity:    SeverityInfo,
				Title:       "Actions settings check requires authentication",
				Description: "Repository Actions settings (allowed actions policy, default permissions) can only be checked with an authenticated GitHub token.",
				Remediation: "Set GITHUB_TOKEN, pass a token with --token-stdin, or install the gh CLI to enable this check.",
				DocURL:      "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository",
			}
		}
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
	} else if dbg != nil {
		dbg(repoFull, "unauthenticated — skipping workflow permissions and fork-pr-approval checks")
	}

	return facts
}
