# Renovate GitHub Actions Pinning

| | |
|---|---|
| **Severity** | Medium |
| **Rule name** | `updates/update-tool-actions-pinning` |
| **Aliases** | `update-tool-actions-pinning`, `actions-pinning` |

## What it checks

Whether Renovate's config is configured to pin GitHub Action references to
immutable commit SHAs.

## How the scanner evaluates it

This rule only runs when Renovate is validly configured **and** covers the
`github-actions` ecosystem (via `enabledManagers` or default coverage).

Renovate pinning is detected when **any** of the following is true:

- `pinDigests: true` at the top level of the Renovate config
- `extends` includes `"helpers:pinGitHubActionDigests"` or `"helpers:pinGitHubActionDigestsToSemver"`
- any `packageRules` entry has `pinDigests: true`

If Renovate covers actions but none of the above is true → `update-tool-actions-not-pinning` (medium).

## Why no Dependabot check?

Dependabot has no configuration option that pins GitHub Actions to commit SHAs.
It preserves whatever pin style is already present in workflow files: if a
workflow pins to `actions/checkout@<sha>`, Dependabot's update PRs continue to
use SHAs; if it pins to `@v4`, Dependabot continues to use tags. A long-standing
feature request to add a Dependabot-side option is tracked in
[dependabot/dependabot-core#7913](https://github.com/dependabot/dependabot-core/issues/7913).

For Dependabot-only repos, the
[`action_pinning`](action-version-pinning.md) rule (severity **High**) checks
the workflows directly and is the source of truth for whether actions are
SHA-pinned. This rule (`update-tool-actions-pinning`) is intentionally silent
when only Dependabot is configured — neither pass nor fail is emitted.

## Why this matters

Pinning to an immutable commit SHA means a re-tagged or replaced action version
cannot silently introduce new code into your workflows. Even a trusted action's
tag (e.g. `v4`) can be moved to point to a different (potentially malicious)
commit. Committing to a SHA ensures you get exactly the code that was reviewed.

## Bad example

**Renovate — no pinDigests:**

```json
{
  "extends": ["config:best-practices"]
}
```

## Good examples

**Renovate — top-level flag:**

```json
{
  "pinDigests": true
}
```

**Renovate — preset:**

```json
{
  "extends": ["config:best-practices", "helpers:pinGitHubActionDigests"]
}
```

**Renovate — packageRule scoped to github-actions:**

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
