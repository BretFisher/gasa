# Allowed Actions Policy

| | |
|---|---|
| **Severity** | Medium |
| **Check ID** | `actions_settings` |
| **Auth required** | Yes |
| **Minimum fine-grained permission** | `Administration: Read` |
| **Classic PAT** | `repo` |

## What it checks

Whether the repository allows all actions, only local actions, or a selected allowlist.

## How the scanner evaluates it

The scanner calls:

- `GET /repos/{owner}/{repo}/actions/permissions`

It reads:

- `enabled`
- `allowed_actions`

Behavior:

- if Actions is disabled (`enabled == false`), the rule returns no finding
- if `allowed_actions == all`, it creates a medium finding
- if `allowed_actions == local_only`, it creates an informational "good" finding
- if `allowed_actions == selected`, it treats that as the desired setting
- if the repository settings endpoint is unavailable without auth, the CLI can return an informational `settings-check-unavailable` finding for this rule
- if the CLI is authenticated but still cannot read the setting, it can return an informational `settings-check-failed` finding for this rule

This rule uses the repository Actions settings API, so full scans need fine-grained `Administration: Read` repository permission, or classic PAT `repo`.

## Why this matters

Allowing all actions means any public action or reusable workflow can be introduced into a workflow without repository-level restriction. Restricting to selected actions reduces supply chain exposure.

## Bad example

```text
Settings > Actions > General > Actions permissions
  Allow all actions and reusable workflows
```

## Good example

```text
Settings > Actions > General > Actions permissions
  Allow select actions and reusable workflows
  actions/*
  github/*
  your-org/*
```

## References

- `internal/scanner/settings.go`
- [Get GitHub Actions permissions for a repository](https://docs.github.com/en/rest/actions/permissions#get-github-actions-permissions-for-a-repository)
