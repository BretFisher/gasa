---
name: updates/update-tool-actions-pinning
order: 10
title: Update Tool GitHub Actions Pinning
category: Updates
severity: medium
aliases: [update-tool-actions-pinning, actions-pinning]
description: no update tool will keep GitHub Action commit SHAs current — Renovate covers actions without digest pinning, and Dependabot has no github-actions entry
messages:
  not-pinning:
    title: Update tool will not keep GitHub Action commit SHAs current
    description: >-
      An update tool covers the github-actions ecosystem, but nothing will
      maintain immutable commit SHA pins. Renovate covers actions without digest
      pinning enabled, and Dependabot has no github-actions entry to preserve
      existing SHA pins. Pinning to a SHA prevents a compromised or re-tagged
      action version from introducing malicious code into your workflows.
    fix: |-
      Enable digest pinning in Renovate (renovate.json / .github/renovate.json).

      Top level:
        { "pinDigests": true }

      Or via preset:
        { "extends": ["helpers:pinGitHubActionDigests"] }
        { "extends": ["config:best-practices"] }

      Or add a github-actions entry to .github/dependabot.yml — Dependabot
      preserves whatever reference style your workflows already use, so it keeps
      SHAs current on an already-pinned repository.
  pass-not-applicable:
    title: No GitHub Action SHAs for an update tool to maintain
    description: >-
      No configured update tool covers the github-actions ecosystem, so there
      are no action references for one to keep pinned.
  pass:
    title: Update tool will keep GitHub Action commit SHAs current
    description: >-
      An update tool is configured to maintain GitHub Action commit SHAs, which
      prevents compromised or re-tagged versions from introducing malicious code.
---

# Update Tool GitHub Actions Pinning

| | |
|---|---|
| **Severity** | Medium |
| **Rule name** | `updates/update-tool-actions-pinning` |
| **Aliases** | `update-tool-actions-pinning`, `actions-pinning` |

## What it checks

Whether the repository's dependency update tooling will keep GitHub Action
references pinned to immutable commit SHAs.

This is a different question from
[`update-tool-configuration`](update-tool-configuration.md), which only asks
whether an update tool covers the `github-actions` ecosystem at all and does not
care about pinning.

## How the scanner evaluates it

The rule is **not applicable** — and stays silent — when no validly configured
tool covers the `github-actions` ecosystem. That absence is
`update-tool-configuration`'s finding to report, not this rule's.

When a tool does cover actions, the rule **passes** if either of the following
holds:

- **Dependabot** has a `github-actions` entry, or
- **Renovate** has digest pinning enabled

If a tool covers actions and neither holds → `update-tool-actions-not-pinning`
(medium).

### Why a Dependabot `github-actions` entry is enough

Dependabot has no configuration option that pins GitHub Actions to commit SHAs.
It preserves whatever reference style is already present in workflow files: if a
workflow pins to `actions/checkout@<sha>`, Dependabot's update PRs continue to
use SHAs; if it pins to `@v4`, Dependabot continues to use tags. A long-standing
feature request for a Dependabot-side option is tracked in
[dependabot/dependabot-core#7913](https://github.com/dependabot/dependabot-core/issues/7913).

So a `github-actions` entry is what keeps SHA pins current on a repository whose
workflows are already pinned. Whether the workflows are pinned in the first
place is checked by
[`action-version-pinning`](action-version-pinning.md) (severity **High**). This
rule does not depend on that rule's outcome — each rule stands alone.

### How Renovate pinning is detected

Pinning is detected when **any** of the following is true:

- `pinDigests: true` at the top level of the Renovate config
- any `packageRules` entry has `pinDigests: true`
- `extends` includes a preset that enables GitHub Action digest pinning:
  - `helpers:pinGitHubActionDigests`
  - `helpers:pinGitHubActionDigestsToSemver`
  - `config:best-practices` — Renovate's recommended configuration, which itself
    extends `helpers:pinGitHubActionDigests`

**Known limitation.** Renovate presets inherit, and the scanner does not fetch
and expand preset definitions at scan time. Only the built-in presets listed
above are recognized. A repository that enables pinning solely inside a custom or
remote preset (`github>org/renovate-config`, `local>org/preset`) is still
reported as not pinning. Treating unresolvable presets as "probably pinning"
would convert a false positive into a false negative, which is the worse failure
for a security scanner, so the conservative direction is deliberate.

## Why this matters

Pinning to an immutable commit SHA means a re-tagged or replaced action version
cannot silently introduce new code into your workflows. Even a trusted action's
tag (e.g. `v4`) can be moved to point to a different (potentially malicious)
commit. Committing to a SHA ensures you get exactly the code that was reviewed.

## Bad examples

**Renovate — covers actions, no pinning anywhere:**

```json
{
  "extends": ["config:recommended"]
}
```

`config:recommended` is the base preset. Unlike `config:best-practices` it does
**not** extend `helpers:pinGitHubActionDigests`, so nothing enables digest
pinning.

**Dependabot — covers other ecosystems but not actions, with no Renovate:**

```yaml
version: 2
updates:
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
```

## Good examples

**Renovate — top-level flag:**

```json
{
  "pinDigests": true
}
```

**Renovate — recommended preset (pins action digests transitively):**

```json
{
  "extends": ["config:best-practices"]
}
```

**Renovate — explicit helper preset:**

```json
{
  "extends": ["config:recommended", "helpers:pinGitHubActionDigests"]
}
```

**Dependabot — a `github-actions` entry preserves existing SHA pins:**

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

**Renovate — packageRule scoped to `github-actions`:**

```json
{
  "packageRules": [
    {
      "matchManagers": ["github-actions"],
      "pinDigests": true
    }
  ]
}
```

**Renovate — real-world `.github/renovate.json5` example:**

```json5
{
  // Pin all digests to immutable SHAs
  "pinDigests": true,
  "extends": ["config:best-practices"]
}
```

## References

- `internal/scanner/updates.go`
- [Security hardening: using third-party actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)
- [Renovate pinDigests option](https://docs.renovatebot.com/configuration-options/#pindigests)
- [Renovate helpers:pinGitHubActionDigests preset](https://docs.renovatebot.com/presets-helpers/#helperspingithubactiondigests)
- [dependabot-core#7913 — feature request to add Dependabot SHA pinning](https://github.com/dependabot/dependabot-core/issues/7913)
