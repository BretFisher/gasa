---
name: actions/permissions/sha-pinning-required
order: 12
title: SHA Pinning Required
category: Settings
severity: medium
aliases: [sha-pinning-required, sha-pinning]
description: repository does not require actions to be pinned to a full-length commit SHA
messages:
  not-required:
    title: Actions are not required to be pinned to a commit SHA
    description: >-
      The repository does not enforce full-length commit SHA pinning for
      actions, so a workflow change that references a mutable tag or branch can
      be merged and will run. Even a repository whose workflows are all pinned
      today has nothing stopping an unpinned reference landing tomorrow.
    fix: >-
      Enable 'Require actions to be pinned to a full-length commit SHA' in
      Settings > Actions > General. Pin every existing workflow reference first
      — enforcement blocks unpinned workflows from running.
  pass-disabled:
    title: SHA pinning enforcement is moot — Actions are disabled
    description: >-
      GitHub Actions are disabled for this repository, so no workflow can run
      regardless of how its actions are referenced.
  pass:
    title: Actions are required to be pinned to a commit SHA
    description: >-
      The repository enforces full-length commit SHA pinning, so an unpinned
      action reference cannot run even if one is merged.
---

# SHA Pinning Required

| | |
|---|---|
| **Severity** | Medium |
| **Rule name** | `actions/permissions/sha-pinning-required` |
| **Aliases** | `sha-pinning-required`, `sha-pinning` |
| **Auth required** | Yes |
| **Minimum fine-grained permission** | `Administration: Read` |
| **Classic PAT** | `repo` |

## What it checks

Whether the repository setting **Require actions to be pinned to a full-length
commit SHA** is enabled.

## How this differs from `action-version-pinning`

[`action-version-pinning`](action-version-pinning.md) (high) proves the
workflow files are pinned **today**. This rule checks the setting that stops an
unpinned reference from ever running **tomorrow** — GitHub refuses to run a
workflow referencing a mutable tag or branch while enforcement is on. The two
are complementary: pinned files without enforcement drift; enforcement without
pinned files blocks the existing workflows, which is why the remediation says
to pin first.

## How the scanner evaluates it

The setting arrives in the same `GET /repos/{owner}/{repo}/actions/permissions`
response the [allowed-actions policy](allowed-actions-policy.md) rule already
reads, so this rule costs no additional API call.

- if `sha_pinning_required == false`, it creates a medium finding
- if `sha_pinning_required == true`, the rule passes
- if Actions is disabled (`enabled == false`), the rule passes — nothing can
  run, pinned or otherwise. This requires GitHub to have actually reported
  `enabled: false`; a settings read that failed is undetermined, not disabled
- if GitHub reports no `sha_pinning_required` value at all (for example an
  older GitHub Enterprise Server), the rule reports an informational
  `undetermined-*` finding rather than staying silent — an unreadable setting
  is unknown, not clean

This rule uses the repository Actions settings API, so full scans need
fine-grained `Administration: Read` repository permission, or classic PAT
`repo`.

## Why this matters

Pinning to a full-length commit SHA is the only immutable action reference, but
file-level pinning is a convention until this setting makes it a rule. With
enforcement on, a pull request that introduces `uses: some/action@v3` produces
a workflow GitHub will not run — the drift is caught at the platform, not in
review.

## Bad example

```text
Settings > Actions > General
  Require actions to be pinned to a full-length commit SHA: disabled
```

## Good example

```text
Settings > Actions > General
  Require actions to be pinned to a full-length commit SHA: enabled
```

## References

- `internal/scanner/settings.go`
- [Get GitHub Actions permissions for a repository](https://docs.github.com/rest/actions/permissions#get-github-actions-permissions-for-a-repository)
- [Security hardening for GitHub Actions: Using third-party actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)
