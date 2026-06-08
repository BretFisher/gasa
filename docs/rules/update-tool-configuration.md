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

- `GET /repos/{owner}/{repo}/contents/.github/dependabot.yml`
- fallback: `GET /repos/{owner}/{repo}/contents/.github/dependabot.yaml`
- `GET /repos/{owner}/{repo}/contents/<each renovate path>` — stops at first found
- `GET /repos/{owner}/{repo}/contents/.github/workflows`

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

**Renovate (implicit — auto-detects all managers including github-actions):**

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
