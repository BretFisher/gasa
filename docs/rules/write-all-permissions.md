---
name: workflows/write-all-permissions
order: 11
title: Write-All Workflow Permissions
category: Workflows
severity: high
aliases: [write-all-permissions, write-all]
description: workflows grant `write-all` permissions, the broadest possible GITHUB_TOKEN grant
messages:
  write-all:
    title: "Workflow grants write-all permissions {{.Where}}"
    description: >-
      This workflow declares `permissions: write-all` {{.Where}}, which grants the
      GITHUB_TOKEN write access to every scope — contents, packages, pull
      requests, issues, deployments, and more. A compromised step or action in
      this workflow can use all of it.
    fix: >-
      Replace `write-all` with the minimal scopes the jobs actually need. Start
      from `permissions: {}` and add individual scopes such as `contents: read`
      or `issues: write` one at a time.
  pass:
    title: No workflow grants write-all permissions
    description: >-
      No parsed workflow declares `write-all` permissions at the workflow or job
      level.
---

# Write-All Workflow Permissions

| | |
|---|---|
| **Severity** | High |
| **Rule name** | `workflows/write-all-permissions` |
| **Aliases** | `write-all-permissions`, `write-all` |

## What it checks

Whether any workflow declares `permissions: write-all` — at the workflow level
or on any individual job.

## How this differs from `workflow-permissions`

The [`workflow-permissions`](workflow-permissions.md) rule is deliberately a
**presence** check: it verifies that permissions are explicit, not that they are
minimal, and its documentation says so. That leaves a gap this rule closes: a
workflow with `permissions: write-all` passes the presence check while granting
the single broadest token possible — the exact thing the GitHub Actions
hardening guidance warns against.

The two rules are separate on purpose. Passing `workflow-permissions` while
failing this rule is a coherent, common state: the permissions are explicit but
far too broad.

## How the scanner evaluates it

For every workflow that parses and defines at least one job, the scanner
inspects:

- the top-level `permissions` value
- each `jobs.<job_id>.permissions` value

Any of them equal to the string `write-all` produces one high finding naming
the workflow (and the job, for job-level grants).

Deliberate v1 scope: only the literal `write-all` is flagged. An explicit map
that happens to grant many scopes (`contents: write`, `issues: write`, …) is
not, because individual write scopes are routinely legitimate — deciding which
combinations count as over-broad needs a false-positive boundary that
`write-all` does not. `read-all` is not flagged: it grants no write access.

## Why this matters

`write-all` gives the workflow's GITHUB_TOKEN write access to every permission
scope GitHub offers. If any step, action, or transitively-included script in
the workflow is compromised, the attacker holds all of it — push access,
package publishing, release editing, PR approval. Minimal scopes exist to make
that blast radius small.

## Bad examples

```yaml
on: push

permissions: write-all

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
```

```yaml
on: push

permissions: {}

jobs:
  release:
    permissions: write-all
    runs-on: ubuntu-latest
    steps:
      - run: make release
```

## Good example

```yaml
on: push

permissions: {}

jobs:
  release:
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - run: make release
```

## References

- `internal/scanner/workflow.go`
- [Controlling permissions for GITHUB_TOKEN](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token)
- [Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
