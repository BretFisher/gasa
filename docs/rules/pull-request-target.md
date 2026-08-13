---
name: workflows/pull-request-target
order: 1
title: Pull Request Target
category: Workflows
severity: critical
aliases: [pull-request-target]
description: pull_request_target should not be used in public repos and is highly discouraged in private repos
messages:
  used:
    title: pull_request_target event is used
    description: >-
      This workflow uses `pull_request_target`. That event should never be used
      in a public repository and is highly discouraged in a private repository
      because it runs in the context of the base branch with access to a more
      trusted token and potentially secrets.
    fix: >-
      Use the `pull_request` event instead. If you cannot avoid
      `pull_request_target`, keep the workflow limited to trusted base-branch
      code only and never check out or execute untrusted pull request code.
  public-restricted:
    title: pull_request_target event is used (external PRs are blocked)
    description: >-
      This workflow uses `pull_request_target`, which runs in the context of the
      base branch with access to a more trusted token and potentially secrets.
      This repository's pull request creation policy is limited to
      collaborators, so there is no untrusted pull request for the workflow to
      act on today — but that mitigation is a repository setting, one click away
      from disappearing, which is why this is low rather than resolved.
    fix: >-
      Use the `pull_request` event instead. If you cannot avoid
      `pull_request_target`, keep the workflow limited to trusted base-branch
      code only and never check out or execute untrusted pull request code.
  private:
    title: pull_request_target event is used (private repo, external PRs allowed)
    description: >-
      This workflow uses `pull_request_target`, which runs in the context of the
      base branch with access to a more trusted token and potentially secrets.
      This repository is private, which limits who can reach it, but its pull
      request creation policy still allows pull requests from users without
      write access — anyone with read access can fork and open one, so the
      untrusted-PR path is open.
    fix: >-
      Use the `pull_request` event instead, or set the repository's pull
      request creation policy to collaborators only. If you cannot avoid
      `pull_request_target`, keep the workflow limited to trusted base-branch
      code only and never check out or execute untrusted pull request code.
  private-fork-workflows:
    title: pull_request_target event is used (private repo runs fork PR workflows)
    description: >-
      This workflow uses `pull_request_target`, which runs in the context of the
      base branch with access to a more trusted token and potentially secrets.
      External pull request creation is blocked on this private repository, but
      its Actions settings enable "Run workflows from fork pull requests" —
      which is not the default — so pull requests from forks do trigger
      workflow runs when they occur.
    fix: >-
      Use the `pull_request` event instead, or disable "Run workflows from fork
      pull requests" under Settings → Actions → General if fork contributions
      do not need CI. If you cannot avoid `pull_request_target`, keep the
      workflow limited to trusted base-branch code only and never check out or
      execute untrusted pull request code.
  private-restricted:
    title: pull_request_target event is used (private repo, fork PR workflows off)
    description: >-
      This workflow uses `pull_request_target`, which runs in the context of the
      base branch with access to a more trusted token and potentially secrets.
      External pull request creation is blocked on this private repository and
      fork pull requests do not run workflows, so the untrusted-PR path is
      closed today — but both protections are repository settings, one click
      away from disappearing, which is why this is low rather than resolved.
    fix: >-
      Use the `pull_request` event instead. If you cannot avoid
      `pull_request_target`, keep the workflow limited to trusted base-branch
      code only and never check out or execute untrusted pull request code.
  private-fork-unknown:
    title: pull_request_target event is used (fork PR workflow policy unverified)
    description: >-
      This workflow uses `pull_request_target`, which runs in the context of the
      base branch with access to a more trusted token and potentially secrets.
      External pull request creation is blocked on this private repository, but
      the scanner could not read whether fork pull requests run workflows, so
      this is graded as if they do.
    fix: >-
      Re-run with a token that has repository admin access so the fork PR
      workflow policy can be verified, or use the `pull_request` event instead.
      If you cannot avoid `pull_request_target`, keep the workflow limited to
      trusted base-branch code only and never check out or execute untrusted
      pull request code.
  old-checkout:
    title: actions/checkout predates the v7 fork-checkout protection
    description: >-
      Severity was raised one level because this workflow uses
      `actions/checkout@{{.Ref}}`: starting with v7 (June 2026), checkout
      refuses to fetch fork pull request code in `pull_request_target`
      workflows unless explicitly overridden, and this reference predates that
      protection.
    fix: Update actions/checkout to v7 or later.
  pass:
    title: pull_request_target event is not used
    description: >-
      No workflow uses `pull_request_target`, which avoids an event that should
      never be used in public repositories and is highly discouraged in private
      repositories.
---

# Pull Request Target

| | |
|---|---|
| **Severity** | Critical |
| **Rule name** | `workflows/pull-request-target` |
| **Aliases** | `pull-request-target` |

## What it checks

Whether any workflow in `.github/workflows/*.yml` or `.github/workflows/*.yaml` uses the `pull_request_target` event.

## How the scanner evaluates it

The scanner:

- lists `.github/workflows` with `GET /repos/{owner}/{repo}/contents/.github/workflows`
- fetches each workflow file with `GET /repos/{owner}/{repo}/contents/{path}`
- base64-decodes the file content
- parses the workflow YAML and inspects the top-level `on` field
- flags the workflow if `on` is:
  - the string `pull_request_target`
  - an array containing `pull_request_target`
  - a mapping with a `pull_request_target` key

This rule does not try to prove whether the workflow later checks out untrusted code. It flags any use of `pull_request_target` because that event should never be used in a public repository and is highly discouraged in a private repository.

### Severity

The trigger is the same in every case; what changes the severity is who can actually reach it with
an untrusted pull request:

| Repository | External PR creation | Fork PR workflows (private-only setting) | Severity |
|---|---|---|---|
| public | allowed | — | **critical** |
| public | collaborators only | — | **low** |
| private | allowed | any | **high** |
| private | collaborators only | "Run workflows from fork pull requests" enabled | **medium** |
| private | collaborators only | disabled (the default) | **low** |
| private | collaborators only | could not be read | **medium** |

Two deliberate biases keep the rule from under-reporting:

- Only the one known-restricted `pull_request_creation_policy` value (`collaborators_only`)
  downgrades; an unknown or absent value keeps the severe reading, so a new GitHub policy value can
  only over-report, never under-report.
- When the private-repo fork PR workflow policy cannot be read (token lacks admin access, transient
  error), the rule grades as if fork PR workflows were enabled.

The policy is read from the same `GET /repos/{owner}/{repo}` response the scan always made. For
private repositories the scanner additionally reads
`GET /repos/{owner}/{repo}/actions/permissions/fork-pr-workflows-private-repos`, the setting under
Settings → Actions → General that decides whether fork pull requests trigger workflow runs at all
(public repositories answer that endpoint with 422 — the fork-PR contributor approval policy
governs them instead).

The finding never resolves entirely while `pull_request_target` is present: every mitigation above
is a repository setting, one click away from disappearing, rather than a property of the workflow.

### actions/checkout v7 escalation

Whatever the table says is raised **one level** (low → medium → high → critical) when the flagged
workflow contains an `actions/checkout` step pinned to a version tag older than **v7**.

Since [checkout v7 (June 2026)](https://github.blog/changelog/2026-06-18-safer-pull_request_target-defaults-for-github-actions-checkout/),
the action refuses to fetch fork pull request code in `pull_request_target` and `workflow_run`
workflows by default — the classic "pwn request" pattern — unless the step explicitly opts out
with the `allow-unsafe-pr-checkout` input. GitHub also backported the protection to the other
supported version tags in July 2026, but a workflow pinned to an old tag or SHA may still resolve
to pre-protection code, so the scanner treats any version tag below v7 as unprotected.

Only refs that look like version tags (`v4`, `4`, `v4.1.1`) are judged. A full commit SHA or a
branch ref carries no version information, so it neither escalates nor clears — treating "unknown"
as "old" would punish the SHA pinning every other rule asks for. The scanner also does not lower
the severity when checkout v7+ is present: the protection can be switched off per step with
`allow-unsafe-pr-checkout`, so its presence is never proof of safety.

## Why this matters

`pull_request_target` runs in the context of the base branch, not the pull request branch. That
means it can access repository secrets and a more trusted token context. If the workflow then
checks out or executes code from the pull request, an attacker can exfiltrate secrets or abuse
repository access. For that reason, it should never be used in public repositories and is highly
discouraged in private repositories.

## Bad example

```yaml
on: pull_request_target

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
```

## Good example

```yaml
on: pull_request

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: npm test
```

If you truly need `pull_request_target`, keep the workflow limited to trusted base-branch code only and do not check out or execute pull request code.

## References

- `internal/scanner/workflow.go`
- [Events that trigger workflows: pull_request_target](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target)
- [Secure use reference for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Keeping your GitHub Actions and workflows secure: Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
