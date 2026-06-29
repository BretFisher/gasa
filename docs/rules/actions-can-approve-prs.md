---
name: actions/permissions/workflow/actions-can-approve-prs
order: 6
title: Actions Can Approve PRs
category: Settings
severity: medium
aliases: [actions-can-approve-prs, approve-prs]
description: workflows can create and approve pull request reviews
messages:
  can-approve:
    title: GitHub Actions can approve pull requests
    description: >-
      GitHub Actions workflows are allowed to create and approve pull request
      reviews. This could be exploited to bypass required reviews.
    fix: >-
      Disable 'Allow GitHub Actions to create and approve pull requests' in
      Settings > Actions > General > Workflow permissions unless specifically
      needed.
  pass-disabled:
    title: GitHub Actions cannot approve pull requests here
    description: >-
      GitHub Actions are disabled for this repository, so workflows cannot create
      or approve pull request reviews.
  pass-cannot-approve:
    title: GitHub Actions cannot approve pull requests
    description: >-
      The repository does not allow workflows to create and approve pull request
      reviews, which helps preserve human review controls.
---

# Actions Can Approve Pull Requests

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

- `internal/scanner/settings.go`
- [Get default workflow permissions for a repository](https://docs.github.com/en/rest/actions/permissions#get-default-workflow-permissions-for-a-repository)
