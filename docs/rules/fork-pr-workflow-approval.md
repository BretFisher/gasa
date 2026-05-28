# Fork PR Workflow Approval

| | |
|---|---|
| **Severity** | High |
| **Check ID** | `actions_settings` |
| **Auth required** | Yes |
| **Minimum fine-grained permission** | `Administration: Read` |
| **Classic PAT** | `repo` |

## What it checks

Whether the public-repo setting `Approval for running fork pull request workflows from contributors` is set to `all_external_contributors`.

## How the scanner evaluates it

The scanner calls:

- `GET /repos/{owner}/{repo}/actions/permissions/fork-pr-contributor-approval`

It reads:

- `approval_policy`

Allowed GitHub values are:

- `first_time_contributors_new_to_github`
- `first_time_contributors`
- `all_external_contributors`

Behavior:

- if the value is anything other than `all_external_contributors`, it creates a high finding
- if the value is `all_external_contributors`, it treats that as the desired setting
- if GitHub returns `403` or `404`, the scanner silently skips this sub-check
- if the repository Actions settings endpoint itself cannot be read, the CLI can return an informational `settings-check-unavailable` or `settings-check-failed` finding for this rule

This rule uses the repository Actions settings API, so full scans need fine-grained `Administration: Read` repository permission, or classic PAT `repo`.

## Why this matters

Fork PR workflows run attacker-controlled code paths more often than normal internal workflows. Requiring approval for all external contributors adds a human approval gate before those runs start.

## Bad example

```text
Settings > Actions > General > Approval for running fork pull request workflows from contributors
  Require approval for first-time contributors
```

## Good example

```text
Settings > Actions > General > Approval for running fork pull request workflows from contributors
  Require approval for all external contributors
```

## References

- `app/internal/scanner/settings.go`
- [Get fork PR contributor approval permissions for a repository](https://docs.github.com/en/rest/actions/permissions#get-fork-pr-contributor-approval-permissions-for-a-repository)
