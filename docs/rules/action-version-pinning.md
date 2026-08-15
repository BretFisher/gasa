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
      This action uses a mutable reference '{{.Ref}}'. Tags and branches can be
      moved, potentially introducing malicious code.
    fix: Pin to a specific commit SHA instead of '{{.Ref}}'.
  unpinned-same-owner-version:
    title: "Same-owner {{.Kind}} pinned to a version tag: {{.Action}}"
    description: >-
      This {{.Kind}} uses the mutable version tag '{{.Ref}}', but it is owned
      by the same user or org as this repository, and a version tag moves only
      when its owner publishes — so this is graded low rather than high. The
      risk is not zero: same owner is not same repo, and a compromise of that
      repository pivots here on its next tag move.
    fix: >-
      Pin to a specific commit SHA, or keep the tag and enable immutable
      releases on the {{.Action}} repository so published tags cannot be moved.
      To silence same-owner refs entirely, set the rule's
      `ignore_same_owner_actions` / `ignore_same_owner_reusable_workflows`
      config options.
  unpinned-same-owner-branch:
    title: "Same-owner {{.Kind}} pinned to a branch: {{.Action}}"
    description: >-
      This {{.Kind}} is owned by the same user or org as this repository, but
      it is referenced by '{{.Ref}}', which does not look like a version tag —
      a branch moves on every push. Same owner is not same repo: a compromise
      of that repository runs attacker code in this one on the very next
      commit, with no release step in between.
    fix: >-
      Pin to a specific commit SHA, or at least to a version tag on a
      repository with immutable releases enabled. To silence same-owner refs
      entirely, set the rule's `ignore_same_owner_actions` /
      `ignore_same_owner_reusable_workflows` config options.
  pass:
    title: Action versions are pinned safely
    description: >-
      All detected third-party actions are pinned to immutable commit SHAs
      instead of mutable tags or branches.
---

# Action Version Pinning

| | |
|---|---|
| **Severity** | High |
| **Rule name** | `workflows/action-version-pinning` |
| **Aliases** | `action-version-pinning`, `action-pinning`, `pinning` |

## What it checks

Whether workflow `uses:` references are pinned to a full 40-character commit SHA.

## How the scanner evaluates it

The scanner:

- lists workflow files from `.github/workflows`
- fetches each file with `GET /repos/{owner}/{repo}/contents/{path}`
- extracts every action reference, then flags any whose version is not a full commit SHA

There are two extraction paths:

1. **Parsed workflow (the normal path).** When the YAML parses, the scanner walks the
   parsed structure and inspects every `jobs.<job_id>.steps[].uses` plus each
   `jobs.<job_id>.uses` (reusable workflow calls). Because it reads structure rather than
   text, a `uses:` string appearing in a comment or inside a `run:` block is not mistaken
   for a real reference.
2. **Regex fallback.** When the YAML fails to parse, the scanner scans the raw text with
   `^\s*-?\s*uses:\s*['"]?([^'"@\s]+)@([^'"@\s]+)['"]?` so an unparsable workflow still
   gets pinning coverage instead of being skipped entirely.

Both paths skip:

- local actions starting with `./`
- Docker-based actions starting with `docker://`

A reference counts as pinned when its version is a hex SHA of 40 characters (SHA-1) or 64
characters (SHA-256, accepted for forward compatibility). Anything else — a tag, a branch,
a short SHA — is treated as unpinned.

### Severity tiers

Tags like `@v4`, branches like `@main`, and reusable workflows referenced by tag or branch are all
treated as unpinned, but they are not all graded the same:

| Reference | Ref shape | Severity |
|---|---|---|
| owned by anyone else | any mutable ref | **high** |
| same user/org as the scanned repo | version tag (`v4`, `4`, `v4.1.1`) | **low** |
| same user/org as the scanned repo | branch or anything else (`main`) | **medium** |

A ref counts as a version tag when it looks like one (`v?<digits>` optionally followed by `.`/`-`
and more); everything else is treated as a branch. The distinction matters because a version tag
moves only when its owner publishes, while a branch moves on every push.

### Optional config

```yaml
rule_options:
  workflows/action-version-pinning:
    ignore_same_owner_actions: true
    ignore_same_owner_reusable_workflows: true
```

- `ignore_same_owner_actions` — ignore mutable refs to *actions* whose owner matches the repository
  owner being scanned
- `ignore_same_owner_reusable_workflows` — the same, for *reusable workflow calls*
  (`jobs.<job_id>.uses`)
- `ignore_same_owner: true` — legacy switch, equivalent to enabling both of the above

Local actions referenced with `./...` never produce findings — both extraction paths skip them.

## Why this matters

Tags and branches are mutable. If an upstream action is compromised, a moved tag can make your
workflow run attacker-controlled code on the next trigger. A full commit SHA is the only immutable
reference GitHub recommends for third-party actions.

### Same owner is not same repo

A ref like `youruser/some-workflow@main` feels internal, but the trust boundary is the
*repository*, not the account: a leaked PAT or a compromised collaborator with write access to just
that one repository pivots into every caller on the next push to `main` — no release, no review in
the calling repo, nothing to notice. That cross-repo pivot is why same-owner refs still produce
findings by default. Two mitigations shrink the window:

- pin to a **version tag** instead of a branch, so the ref only moves on a deliberate publish
  (this is the low-severity tier above), and
- enable **[immutable releases](https://docs.github.com/en/repositories/releasing-projects-on-github/immutable-releases)**
  on the action or reusable-workflow repository, so published tags cannot be moved at all —
  making a tag pin behave like a SHA pin

### Relation to GitHub's SHA-pinning enforcement setting

GitHub's repository setting **"Require actions to be pinned to a full-length commit SHA"** (see the
[`sha-pinning-required`](sha-pinning-required.md) rule) enforces SHA pinning at runtime, with one
documented exemption: "Reusable workflows can still be referenced by tag." Note the exemption is
for **tags only** — a reusable workflow referenced by *branch* is still refused when enforcement is
on. So a same-owner reusable workflow pinned to a version tag survives enforcement, but one pinned
to `@main` will stop running the moment that setting is enabled — one more reason the branch tier
grades higher than the version-tag tier.

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
