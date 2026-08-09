---
name: actions/permissions/fork-pr-contributor-approval
order: 7
title: Fork PR Workflow Approval
category: Settings
severity: high
aliases: [fork-pr-contributor-approval, fork-pr-approval]
description: external contributors can trigger fork PR workflows without maintainer approval
messages:
  too-permissive:
    title: Fork PR workflows do not require approval from all external contributors
    description: >-
      The repository's 'Approval for running fork pull request workflows from
      contributors' setting is less restrictive than 'Require approval for all
      external contributors'. Some external contributors can trigger workflows
      without a maintainer reviewing the run first.
    fix: >-
      Set 'Approval for running fork pull request workflows from contributors' to
      'Require approval for all external contributors' in Settings > Actions >
      General > Fork pull request workflows from outside collaborators.
  pass-disabled:
    title: Fork pull request workflows are safely constrained
    description: >-
      GitHub Actions are disabled for this repository, so fork pull request
      workflows cannot run.
  pass-all-external:
    title: Fork pull request workflows require full external approval
    description: >-
      Fork pull request workflows require approval from all external contributors
      before they can run, reducing the risk of untrusted code execution.
---

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
- if GitHub returns `403` or `404`, the value cannot be read and the rule reports an
  informational `undetermined-*` finding rather than staying silent — an unreadable
  setting is unknown, not clean
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

- `internal/scanner/settings.go`
- [Get fork PR contributor approval permissions for a repository](https://docs.github.com/en/rest/actions/permissions#get-fork-pr-contributor-approval-permissions-for-a-repository)
