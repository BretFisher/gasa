# Actions Can Approve Pull Requests

| | |
|---|---|
| **Severity** | Medium |
| **Check ID** | `actions_settings` |
| **Auth required** | Yes |
| **Minimum fine-grained permission** | `Administration: Read` |
| **Classic PAT** | `repo` |

## What it checks

Whether GitHub Actions is allowed to create and approve pull request reviews.

## How the scanner evaluates it

The scanner calls:

- `GET /repos/{owner}/{repo}/actions/permissions/workflow`

It reads:

- `can_approve_pull_request_reviews`

Behavior:

- if `can_approve_pull_request_reviews == true`, it creates a medium finding
- if the value is `false`, it treats that as the desired setting
- if GitHub returns `403` or `404`, the scanner silently skips this sub-check
- if the repository Actions settings endpoint itself cannot be read, the CLI can return an informational `settings-check-unavailable` or `settings-check-failed` finding for this rule

This rule uses the repository Actions settings API, so full scans need fine-grained `Administration: Read` repository permission, or classic PAT `repo`.

## Why this matters

If workflows can approve PRs, automation can satisfy required-review rules. That weakens the human review gate and can be abused by compromised workflows or over-broad automation.

## Bad example

```text
Settings > Actions > General > Workflow permissions
  Allow GitHub Actions to create and approve pull requests: enabled
```

## Good example

```text
Settings > Actions > General > Workflow permissions
  Allow GitHub Actions to create and approve pull requests: disabled
```

## References

- `app/internal/scanner/settings.go`
- [Get default workflow permissions for a repository](https://docs.github.com/en/rest/actions/permissions#get-default-workflow-permissions-for-a-repository)
