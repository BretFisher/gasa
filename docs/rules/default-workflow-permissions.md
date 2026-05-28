# Default Workflow Permissions

| | |
|---|---|
| **Severity** | High |
| **Check ID** | `actions_settings` |
| **Auth required** | Yes |
| **Minimum fine-grained permission** | `Administration: Read` |
| **Classic PAT** | `repo` |

## What it checks

Whether the repository default `GITHUB_TOKEN` permission level is `read` or `write`.

## How the scanner evaluates it

The scanner calls:

- `GET /repos/{owner}/{repo}/actions/permissions/workflow`

It reads:

- `default_workflow_permissions`

Behavior:

- if `default_workflow_permissions == write`, it creates a high finding
- if `default_workflow_permissions == read`, it treats that as the desired setting
- if GitHub returns `403` or `404`, the scanner silently skips this sub-check
- if the repository Actions settings endpoint itself cannot be read, the CLI can return an informational `settings-check-unavailable` or `settings-check-failed` finding for this rule

This rule uses the repository Actions settings API, so full scans need fine-grained `Administration: Read` repository permission, or classic PAT `repo`.

## Why this matters

This is the fallback permission level workflows inherit when they do not define their own `permissions:` block. `write` gives broad write capability by default. `read` forces workflows to explicitly request elevated access.

## Bad example

```text
Settings > Actions > General > Workflow permissions
  Read and write permissions
```

## Good example

```text
Settings > Actions > General > Workflow permissions
  Read repository contents and packages permissions
```

## Good workflow example after locking this down

```yaml
permissions:
  contents: read
  issues: write
```

## References

- `app/internal/scanner/settings.go`
- [Get default workflow permissions for a repository](https://docs.github.com/en/rest/actions/permissions#get-default-workflow-permissions-for-a-repository)
