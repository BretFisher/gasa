---
name: actions/permissions/workflow/default-workflow-permissions
order: 5
title: Default Workflow Permissions
category: Settings
severity: high
aliases: [default-workflow-permissions, default-permissions]
description: repository default GITHUB_TOKEN is read-write instead of read-only
messages:
  read-write:
    title: Default workflow permissions are read-write
    description: >-
      The default GITHUB_TOKEN permissions for this repository are set to
      read-write. This gives all workflows broad write access to the repository
      unless explicitly restricted per-workflow.
    fix: >-
      WARNING: Before changing this setting, verify all workflows have explicit
      permissions blocks (see workflow-permissions rule). Changing to read-only
      will break workflows that need write access but don't explicitly define
      permissions. Once workflows are updated, set default workflow permissions
      to 'Read repository contents and packages permissions' in Settings >
      Actions > General > Workflow permissions.
  pass-disabled:
    title: Default workflow permissions are safely constrained
    description: >-
      GitHub Actions are disabled for this repository, so workflows do not
      receive repository token permissions.
  pass-read:
    title: Default workflow permissions are read-only
    description: >-
      The repository default for `GITHUB_TOKEN` is read-only, which limits
      workflow access unless a workflow explicitly requests more.
---

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

## ⚠️ Important Warning

**Changing this setting from "write" to "read" can break existing workflows** that require write permissions but don't have explicit `permissions:` blocks defined.

Before changing the repository default to read-only:

1. **First**, ensure all workflows that need write access have explicit `permissions:` blocks (checked by the `workflow-permissions` rule)
2. **Then**, change the repository default setting to read-only

If you change the repository setting first, workflows that depend on inherited write permissions will fail until you add explicit permission blocks to them.

See the `workflow-permissions` rule documentation for guidance on adding explicit permissions to workflows.

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

- `internal/scanner/settings.go`
- [Get default workflow permissions for a repository](https://docs.github.com/en/rest/actions/permissions#get-default-workflow-permissions-for-a-repository)
