---
name: actions/permissions/allowed-actions-policy
order: 4
title: Allowed Actions Policy
category: Settings
severity: medium
aliases: [allowed-actions-policy, allowed-actions]
description: repository allows all actions instead of restricting to trusted sources
messages:
  all-allowed:
    title: All GitHub Actions are allowed
    description: >-
      This repository allows all GitHub Actions to run without restriction. This
      means any public action can be used, including potentially malicious ones.
    fix: >-
      Restrict allowed actions to 'selected' and specify trusted action sources.
      Go to Settings > Actions > General > Actions permissions.
  pass-disabled:
    title: GitHub Actions are disabled for this repository
    description: >-
      GitHub Actions are disabled, so unrestricted third-party actions cannot run
      in this repository.
  pass-local-only:
    title: Allowed actions policy is tightly restricted
    description: >-
      Only actions defined inside this repository are allowed, which blocks
      third-party public actions entirely.
  pass-selected:
    title: Allowed actions policy is restricted
    description: >-
      The repository does not allow all public actions by default, which limits
      execution to an approved set of trusted actions.
---

# Allowed Actions Policy

| | |
|---|---|
| **Severity** | Medium |
| **Rule name** | `actions/permissions/allowed-actions-policy` |
| **Aliases** | `allowed-actions-policy`, `allowed-actions` |
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

- if Actions is disabled (`enabled == false`), the rule passes — unrestricted third-party
  actions cannot run in a repository where Actions cannot run at all. This requires GitHub
  to have actually reported `enabled: false`; a settings read that failed is undetermined,
  not disabled
- if `allowed_actions == all`, it creates a medium finding
- if `allowed_actions == local_only`, the rule passes — only actions defined inside the
  repository can run, which blocks third-party public actions entirely
- if `allowed_actions == selected`, it treats that as the desired setting
- if Actions is enabled but GitHub reports no `allowed_actions` value at all (observed when
  an org or enterprise policy governs the repository), the rule reports an informational
  `undetermined-*` finding rather than staying silent — an unreadable setting is unknown,
  not clean
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
