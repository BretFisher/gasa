---
name: workflows/action-version-pinning
order: 2
title: Action Version Pinning
category: Workflows
severity: high
aliases: [action-version-pinning, action-pinning, pinning]
description: actions referenced by tag or branch instead of a full commit SHA
messages:
  unpinned:
    title: "Unpinned Action: {{.Action}}"
    description: >-
      This action uses a mutable reference `{{.Ref}}`. Tags and branches can be
      moved, potentially introducing malicious code.
    fix: Pin to a specific commit SHA instead of `{{.Ref}}`.
  pass:
    title: Action versions are pinned safely
    description: >-
      All detected third-party actions are pinned to immutable commit SHAs
      instead of mutable tags or branches.
---

# Action Version Pinning

## What it checks

Whether workflow `uses:` references are pinned to a full 40-character commit SHA.

## How the scanner evaluates it

The scanner:

- lists workflow files from `.github/workflows`
- fetches each file with `GET /repos/{owner}/{repo}/contents/{path}`
- scans raw workflow text with this regex: `^\s*-?\s*uses:\s*['"]?([^'"@\s]+)@([^'"@\s]+)['"]?`
- extracts the action name and version from every `uses:` line
- skips:
  - local actions starting with `./`
  - Docker-based actions starting with `docker://`
- flags any reference whose version is not a 40-character hex SHA

Optional config behavior:

- if `.gasa.yml` sets:

```yaml
rule_options:
  workflows/action-version-pinning:
    ignore_same_owner: true
```

- then the rule ignores mutable refs for actions whose owner matches the repository owner being scanned
- local actions referenced with `./...` are also treated as owner-controlled and are ignored

This means tags like `@v4`, branches like `@main`, and reusable workflows referenced by tag or branch are all treated as unpinned.

## Why this matters

Tags and branches are mutable. If an upstream action is compromised, a moved tag can make your workflow run attacker-controlled code on the next trigger. A full commit SHA is the only immutable reference GitHub recommends for third-party actions.

## Bad example

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: docker/login-action@master
```

## Good example

```yaml
steps:
  - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29 # v4.1.1
  - uses: docker/login-action@9780b0c442fbb1117ed29e0efdff1e18412f7567 # v3.3.0
```

## Remediation tools

Pinning by hand is tedious. These tools rewrite `uses:` references to full
commit SHAs (and keep a version comment so the file stays readable). Once the
file is SHA-pinned, Dependabot and Renovate preserve that style on update PRs.

| Tool | License | What it does |
|---|---|---|
| [pinact](https://github.com/suzuki-shunsuke/pinact) | MIT | CLI that pins `uses:` references in workflow and composite action files to commit SHAs. Also supports version updates, version-comment verification, offline checks, and SARIF output. Best fit if you only target GitHub Actions. |
| [ratchet](https://github.com/sethvargo/ratchet) | Apache-2.0 | CLI that pins (and unpins) versions across CI/CD systems: GitHub Actions, GitLab CI, Circle CI, Google Cloud Build, Drone, Tekton. Best fit if you also need to pin non-GitHub pipelines. |
| [step-security/secure-repo](https://github.com/step-security/secure-repo) | AGPL-3.0 | Opens hardening PRs against your repo. Pins actions to SHAs and also applies other fixes: minimum `GITHUB_TOKEN` permissions, Harden-Runner, Docker digest pinning, Dependabot config, SAST workflows. Hosted instance at [app.stepsecurity.io/securerepo](https://app.stepsecurity.io/securerepo). |

A practical workflow: run `pinact` or `ratchet` once locally, commit the pinned
workflows, and let Dependabot/Renovate maintain the SHAs going forward. See
also the [`update-tool-actions-pinning`](update-tool-actions-pinning.md) rule
for the Renovate-side configuration check.

## References

- `internal/scanner/workflow.go`
- [Security hardening for GitHub Actions: Using third-party actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)
