---
name: updates/update-tool-configuration
order: 8
title: Update Tool Configuration
category: Updates
severity: medium
aliases: [update-tool-configuration, update-tool]
description: no dependency update tool configured (Dependabot or Renovate), invalid config, or missing github-actions coverage
messages:
  no-tool:
    title: No dependency update tool configured
    description: >-
      This repository has neither a Dependabot configuration file nor a Renovate
      configuration file. Automated dependency update tooling keeps action
      versions and package dependencies current and helps catch vulnerable or
      malicious releases.
    fix: >-
      Add a `.github/dependabot.yml` (Dependabot) or a `renovate.json` /
      `.github/renovate.json` (Renovate) to enable automated dependency updates.
  invalid-dependabot:
    title: Invalid Dependabot configuration
    description: "The dependabot configuration file could not be parsed: {{.Err}}"
    fix: Fix the YAML syntax in your dependabot.yml file.
  invalid-renovate:
    title: Invalid Renovate configuration
    description: "The Renovate configuration file could not be parsed: {{.Err}}"
    fix: Fix the JSON syntax in your Renovate configuration file.
  missing-actions:
    title: Update tool not configured for GitHub Actions
    description: >-
      This repository has GitHub Actions workflows but {{.Tool}} is not
      configured to update them. Action versions will not be automatically kept
      up to date.
    fix: |-
      Configure your update tool to track the github-actions ecosystem.

      Dependabot (.github/dependabot.yml):
        - package-ecosystem: "github-actions"
          directory: "/"
          schedule:
            interval: "weekly"

      Renovate (renovate.json / .github/renovate.json):
        { "enabledManagers": ["github-actions"] }
        (or omit enabledManagers entirely — Renovate auto-detects github-actions)
  pass:
    title: Dependency update tool is configured correctly
    description: >-
      {{.Tool}} is configured with valid configuration and includes GitHub
      Actions updates when workflows are present.
---

# Update Tool Configuration

| | |
|---|---|
| **Severity** | Medium |
| **Rule name** | `updates/update-tool-configuration` |
| **Aliases** | `update-tool-configuration`, `update-tool` |

## What it checks

- whether `.github/dependabot.yml` / `.github/dependabot.yaml` (Dependabot) or any supported Renovate config file exists
- whether the found config file parses successfully
- whether at least one tool covers the `github-actions` ecosystem when workflow files exist

The rule **passes** if either Dependabot or Renovate satisfies all of the above conditions. Teams can use one or both tools.

## Supported Renovate config paths (checked in order)

```text
renovate.json
renovate.json5
.github/renovate.json
.github/renovate.json5
.gitlab/renovate.json
.gitlab/renovate.json5
.renovaterc
.renovaterc.json
.renovaterc.json5
```

## How the scanner evaluates it

API calls made:

- `GET /repos/{owner}/{repo}/contents/` — root directory listing
- `GET /repos/{owner}/{repo}/contents/.github` (and `.gitlab`, only when the root listing shows it
  exists) — directory listings
- `GET /repos/{owner}/{repo}/contents/<path>` — one fetch per config file the listings proved to
  exist, in Renovate's own precedence order
- `GET /repos/{owner}/{repo}/contents/.github/workflows`

The listings replace what used to be one probe per candidate path — eleven requests to establish
that no update tool exists. If a listing fails or returns at the contents API's 1,000-entry
truncation cap, the scanner falls back to per-path probing, so a listing problem can only cost
speed, never correctness.

Decision logic:

- if both tools are missing → `no-update-tool` (medium)
- if Dependabot is present but YAML is invalid and Renovate is not valid → `invalid-dependabot` (medium)
- if Renovate is present but JSON is invalid and Dependabot is not valid → `invalid-renovate` (medium)
- if at least one tool is valid and workflows exist but neither covers `github-actions` → `update-tool-missing-actions` (medium)

The scanner strips `//` and `/* */` comments from Renovate `.json5` files before parsing so that
common real-world configs with inline comments are handled correctly.

For Renovate's `github-actions` coverage: if `enabledManagers` is absent or empty, Renovate
auto-detects all package managers (including `github-actions`), so the rule passes. Only when
`enabledManagers` is explicitly set must `"github-actions"` appear in the list.

Optional config behavior:

```yaml
rule_options:
  updates/update-tool-configuration:
    require_workflows: true
```

When `require_workflows: true` is set in `.gasa.yml`, the rule is skipped entirely when the
repository has no workflow YAML files under `.github/workflows`.

## Why this matters

Automated dependency update tools keep action versions and package dependencies current and help
catch vulnerable or malicious releases before they persist indefinitely in the codebase.

## Bad examples

```text
# Neither .github/dependabot.yml nor any renovate.json* file present
```

```yaml
# dependabot.yml — covers only npm, not github-actions
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
```

## Good examples

**Dependabot:**

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

**Renovate (explicit):**

```json
{
  "enabledManagers": ["github-actions", "npm"]
}
```

**Renovate (implicit — auto-detects all managers including `github-actions`):**

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:best-practices"]
}
```

## References

- `internal/scanner/updates.go`
- [Get repository content](https://docs.github.com/en/rest/repos/contents#get-repository-content)
- [Configuring Dependabot version updates](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuring-dependabot-version-updates)
- [Renovate configuration options](https://docs.renovatebot.com/configuration-options/)
