# Update Tool GitHub Actions Cooldown

| | |
|---|---|
| **Severity** | Low |
| **Rule name** | `updates/update-tool-actions-cooldown` |
| **Aliases** | `update-tool-actions-cooldown`, `actions-cooldown` |

## What it checks

- whether Dependabot's `github-actions` entry defines a `cooldown` block, **or**
- whether Renovate's config sets `minimumReleaseAge` at the top level or in any `packageRules` entry

The rule **passes** if either tool has a cooldown/minimum-release-age configured.

## How the scanner evaluates it

This rule only runs when at least one update tool is validly configured (the main
`updates/update-tool-configuration` rule handles the missing/invalid case).

- if the Dependabot `github-actions` entry has a `cooldown` block → passes
- if Renovate has `minimumReleaseAge` set anywhere in the config → passes
- if neither tool has a cooldown configured and at least one tool covers `github-actions` → `update-tool-actions-missing-cooldown` (low)

The scanner checks for the **presence** of a cooldown setting but does not validate the specific
duration value.

## Why this matters

A cooldown/minimum-release-age delay prevents immediate adoption of a new action version, giving
the community time to detect supply-chain attacks (compromised tags, malicious releases) before they
land in your workflows automatically.

## Bad examples

**Dependabot — no cooldown:**

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "daily"
```

**Renovate — no minimumReleaseAge:**

```json
{
  "extends": ["config:best-practices"]
}
```

## Good examples

**Dependabot:**

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "daily"
    cooldown:
      default-days: 7
```

**Renovate — top-level:**

```json
{
  "minimumReleaseAge": "7 days"
}
```

**Renovate — scoped to github-actions via packageRules:**

```json
{
  "packageRules": [
    {
      "matchManagers": ["github-actions"],
      "minimumReleaseAge": "7 days"
    }
  ]
}
```

## References

- `internal/scanner/updates.go`
- [Dependabot cooldown option](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#cooldown)
- [Renovate minimumReleaseAge](https://docs.renovatebot.com/configuration-options/#minimumreleaseage)
