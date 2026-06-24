# GitHub Actions Security Assessment

A CLI tool that scans GitHub repositories for Actions security-related misconfigurations. It checks your workflows, repo settings, and dependency tooling against recommended security practices and tells you exactly what to fix.

You can scan single repos or entire users and orgs. You can control which rules it runs and the type of output (table, json, or html). Rules have docs and remediation help.

You can use it as a downloadable CLI, a Docker container, or a GitHub Action. It can do a partical check on a 3rd-party public repository, but for a full settings check it'll need at least read-only admin access, which if your local `gh` cli is logged in, it'll use that to check your repository settings.

This tool is only concerned with GitHub Actions security best practices, and goes beyond the workflow yaml to help repo owners, partically open source maintainers, validate that their workflows, settings, and Dependabot/Renovate configs are providing a safe Actions environment.

> [!WARNING]
> Don't run `gasa` as a GitHub Actions workflow on a public repo — the findings report would be public, which is likely the last thing you want for a security report. A future feature will report findings to the GitHub Security tab to keep them private.

## Quick Start

```bash
# scan a single repository
# gasa run [flags] [owner/repo]
gasa run bretfisher/gasa

# scan all your personal/org repositories in batch mode
# gasa batch [flags] <owner-or-user | owner/repo,owner/repo,... | --input file>
gasa batch mostlydevops

# hey agents, you can get json output with
gasa batch mostlydevops --format json
```

## Install

Pick whichever fits your environment. All methods install the same `gasa` binary.

### Homebrew (macOS / Linux)

```bash
brew install bretfisher/tap/gasa
```

### Docker

The image is published to [GitHub Container Registry](https://github.com/bretfisher/gasa/pkgs/container/gasa) for `linux/amd64` and `linux/arm64`. The entrypoint is `gasa`, so append the same args you'd pass the CLI:

```bash
# public repo, no token needed
docker run --rm ghcr.io/bretfisher/gasa:latest run bretfisher/gasa

# pass a token for full settings checks
docker run --rm -e GITHUB_TOKEN ghcr.io/bretfisher/gasa:latest run myorg/myrepo
```

Pin a version with a tag like `ghcr.io/bretfisher/gasa:v0.3.0` instead of `latest`.

### Pre-built binary download

Download a release archive for your OS/arch from the [Releases page](https://github.com/bretfisher/gasa/releases/latest), extract it, and move `gasa` onto your `PATH`.

### Build from source

Requires [Go](https://go.dev/dl/) 1.26+.

```bash
# install the latest tagged release straight from the module
go install github.com/bretfisher/gasa@latest

# or clone and build locally
git clone https://github.com/bretfisher/gasa.git
cd gasa
make build          # outputs ./bin/gasa
./bin/gasa --help
```

See [Build](#build) below for development commands.

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `gasa run` | Scan a single repository for Actions security issues |
| `gasa batch` | Scan many repositories at once (a whole user/org, a list, or a file) and produce one combined report |
| `gasa rules` | List available rule names and aliases |

### Flags

| Flag | Scope | Description |
|------|-------|-------------|
| `--token-stdin` | global | Read GitHub token from stdin |
| `--config`, `-c` | global | Path to a `gasa` YAML config file |
| `--format` | global | Output format: `table`, `json`, or `html` |
| `--timeout` | global | Maximum time for each repo scan or repo-listing call (default `1m`, e.g. `30s`, `2m`) |
| `--debug` | global | Print single-line diagnostic debug output to stderr while scanning |
| `--rule`, `-r` | `run`, `batch` | Run only the specified rule name or alias (repeat or comma-separate) |
| `--category` | `run`, `batch` | Run only rules in the specified category (repeat or comma-separate; mutually exclusive with `--rule`) |
| `--severity` | `run`, `batch` | Run only rules with the specified severity: `critical`, `high`, `medium`, `low`, or `info` (repeat or comma-separate; mutually exclusive with `--rule`) |
| `--success` | `run`, `batch` | Include successful rule results in the output alongside findings |
| `--output` | `batch` | Write the report to this file path (required for `--format html`; optional for `--format json`, which defaults to stdout) |
| `--concurrency` | `batch` | Number of repos to scan in parallel (default `5`) |
| `--include-archived` | `batch` | Include archived repos when scanning a whole user or org (skipped by default) |
| `--input` | `batch` | Path to a file with one `owner/repo` per line (`#` comments and blank lines ignored) |

### Authentication

The tool looks for a GitHub token in this order:

1. `--token-stdin`
2. `GITHUB_TOKEN` environment variable
3. `GH_TOKEN` environment variable
4. `gh auth token` (if the [GitHub CLI](https://cli.github.com/) is installed and authenticated)

Without authentication, the tool can still scan public repos but is limited to 60 API requests/hour and cannot check repository-level Actions settings. With a token, the limit is 5,000 requests/hour and all checks are available.

### Minimal Token Permissions

For a full scan, `gasa` uses these repository GET endpoints:

- `GET /repos/{owner}/{repo}`
- `GET /repos/{owner}/{repo}/contents/{path}`
- `GET /repos/{owner}/{repo}/actions/permissions`
- `GET /repos/{owner}/{repo}/actions/permissions/workflow`
- `GET /repos/{owner}/{repo}/actions/permissions/fork-pr-contributor-approval`

Minimal fine-grained PAT permissions:

| Repo type | Minimum fine-grained repository permissions |
|----------|----------------------------------------------|
| Public repo | `Metadata: Read`, `Contents: Read`, `Administration: Read` |
| Private repo | `Metadata: Read`, `Contents: Read`, `Administration: Read` |

Notes:

- For public repos, you can run without a token, but repository-level Actions settings checks are unavailable.
- For private repos, a token is required.
- For classic PATs, the practical minimum for a full scan is `repo`, because the Actions settings endpoints require it.
- If you only want workflow file and dependency update tool checks on a public repo, no token is required.

### Examples

```bash
# Scan the current cloned repository by inferring owner/repo from git origin
gasa run

# Scan a public repo (uses gh CLI token if available)
gasa run bretfisher/udemy-docker-mastery

# Scan with an explicit token from stdin
printf '%s' "$GITHUB_TOKEN" | gasa run --token-stdin myorg/myrepo

# List rule names and aliases for targeted scans
gasa rules

# Run a single rule by short alias
gasa run --rule fork-pr-approval myorg/myrepo

# Run multiple rules by alias
gasa run --rule action-pinning,permissions myorg/myrepo

# Run all rules in a category
gasa run --category workflows myorg/myrepo

# Run only critical and high severity rules
gasa run --severity critical,high myorg/myrepo

# Include successful rule results too
gasa run --success myorg/myrepo

# Use an explicit config file
gasa run --config ./security/gasa.yml myorg/myrepo

# Print live scanner diagnostics to stderr while keeping results on stdout
gasa run --debug myorg/myrepo

# JSON output (pipe to jq, save to file, etc.)
gasa run --format json myorg/myrepo > results.json

# HTML report output
gasa run --format html myorg/myrepo > report.html
```

## Batch Scanning

Batch mode is the fastest way to assess many repositories at once and roll the results into a single report. For most maintainers and security teams this is the primary way to run `gasa`: point it at a user or org and get one report covering every repo.

`gasa batch` takes exactly **one** input source:

| Input | Example | Behavior |
|-------|---------|----------|
| User or org name | `gasa batch bretfisher` | Fetches all of that account's repos (auto-detects user vs org), most-recently-pushed first |
| Explicit list | `gasa batch owner/repo1,owner/repo2` | Scans only the comma-separated repos |
| File (`--input`) | `gasa batch --input repos.txt` | Reads one `owner/repo` per line; `#` comments and blank lines are ignored |

Output depends on `--format`:

- `--format table` (default) **streams** each repo's results to stdout as that repo finishes — good for a quick terminal pass, no `--output` needed.
- `--format html --output report.html` writes one combined, styled HTML report — best for sharing with a team.
- `--format json` prints a JSON array of every repo's result to stdout (add `--output results.json` to write a file instead) — best for automation, piping to `jq`, and diffing over time.

Repos are scanned in parallel (`--concurrency`, default `5`). Progress lines like `[3/40] owner/repo — 5 finding(s)` always go to **stderr**, so they never pollute piped table/JSON/HTML output on stdout.

```bash
# Scan every repo in a user account or org into one HTML report (the common case)
gasa batch bretfisher --format html --output bretfisher-security-report.html

# Scan an org with more parallelism and a shared config file
gasa batch my-org --config .gasa.yaml --concurrency 10 --format html --output my-org-report.html

# Scan a hand-picked, comma-separated list of repos
gasa batch owner/repo1,owner/repo2,owner/repo3 --format html --output report.html

# Scan a curated list of repos kept in a file (one owner/repo per line)
gasa batch --input repos.txt --format html --output report.html

# Quick streaming terminal pass over an org, no output file needed
gasa batch my-org --format table

# Focus a fleet-wide scan on a single high-severity concern
gasa batch my-org --rule action-pinning --severity high,critical --format html --output pinning-audit.html

# Include archived repos (they are skipped by default)
gasa batch my-org --include-archived --format html --output report.html

# Machine-readable results for every repo, piped straight to jq (stdout)
gasa batch my-org --format json | jq '.[] | select(.findings | length > 0)'

# Same, but saved to a file instead of stdout
gasa batch my-org --format json --output results.json

# Cap per-repo scan time when crawling a large or slow org
gasa batch my-org --timeout 30s --format html --output report.html
```

All of `run`'s rule filters (`--rule`, `--category`, `--severity`, `--success`), the global `--config`, and the same [authentication](#authentication) resolution work identically in batch mode. Scanning a whole user/org calls the GitHub API to list repos first, so an authenticated token is strongly recommended — unauthenticated runs are capped at 60 requests/hour and the repo listing may be incomplete.

## Config File

`gasa` will automatically load `.gasa.yml` or `.gasa.yaml` from the current working directory if present. You can also pass a file explicitly with `--config`.

A sample config is available at `.gasa.sample.yaml`. It is not auto-loaded.

Current config support includes:

- rule include and exclude lists
- rule-specific options
- severity overrides by rule ID
- finding suppressions by rule, finding ID, or file path

Rule precedence:

1. `--rule` flags override config-based include and exclude selection
2. `--severity` filters the selected rules by their effective severity after config overrides
3. config overrides and suppressions still apply to the selected rules
4. if neither CLI rules nor config rule filters are set, all built-in rules run

Example `.gasa.yml`:

```yaml
rules:
  include:
    - workflows/action-version-pinning
    - workflows/pull-request-target
  exclude:
    - updates/update-tool-actions-cooldown

rule_options:
  workflows/action-version-pinning:
    ignore_same_owner: true
  updates/update-tool-configuration:
    require_workflows: true

overrides:
  - rule: workflows/action-version-pinning
    severity: critical

suppressions:
  - rule: workflows/workflow-permissions
    path: .github/workflows/legacy.yml
    reason: reviewed exception
```

## Output

- `--format table` writes the default terminal table output to stdout
- `--format json` writes machine-readable results to stdout
- `--format html` writes a styled HTML report to stdout
- scan status and auth hints go to stderr
- `--debug` writes diagnostic lines to stderr in the format `[DEBUG] owner/repo | message`
- debug output is single-line and repo-prefixed so batch scan output can be filtered or sorted safely
- findings include remediation text plus a repo-specific `fix_url` when the tool can determine the right GitHub page or file to fix
- `--success` adds passing rule results with `SUCCESS ...` titles in green and explains why the rule passed

Example human output details:

- workflow findings link directly to the workflow file and line when available
  - update tool findings link to the relevant config file or the new-file page if the config is missing
  - repository settings findings link to `Settings > Actions`

Example JSON shape:

```json
{
  "repo_full_name": "owner/repo",
  "repo_url": "https://github.com/owner/repo",
  "findings": [
    {
      "id": "settings-all-actions-allowed",
      "rule": "actions/permissions/allowed-actions-policy",
      "success": false,
      "severity": "medium",
      "title": "All GitHub Actions are allowed",
      "description": "This repository allows all GitHub Actions to run without restriction.",
      "remediation": "Restrict allowed actions to selected and specify trusted action sources.",
      "fix_url": "https://github.com/owner/repo/settings/actions",
      "doc_url": "https://docs.github.com/..."
    }
  ],
  "scanned_at": "2026-04-04T00:00:00Z"
}
```

In `batch --format json` mode, the output is a JSON **array** of these per-repo objects, in the same order as the input. In `batch --format html` mode, every repo is combined into a single report file.

## Rule Selection

Use `gasa rules` to print the canonical rule names and short aliases.

Canonical rule names currently supported:

| Canonical rule | Aliases |
|----------------|---------|
| `workflows/pull-request-target` | `pull-request-target` |
| `workflows/action-version-pinning` | `action-version-pinning`, `action-pinning`, `pinning` |
| `workflows/workflow-permissions` | `workflow-permissions`, `permissions` |
| `actions/permissions/allowed-actions-policy` | `allowed-actions-policy`, `allowed-actions` |
| `actions/permissions/workflow/default-workflow-permissions` | `default-workflow-permissions`, `default-permissions` |
| `actions/permissions/workflow/actions-can-approve-prs` | `actions-can-approve-prs`, `approve-prs` |
| `actions/permissions/fork-pr-contributor-approval` | `fork-pr-contributor-approval`, `fork-pr-approval` |
| `updates/update-tool-configuration` | `update-tool-configuration`, `update-tool` |
| `updates/update-tool-actions-cooldown` | `update-tool-actions-cooldown`, `actions-cooldown` |
| `updates/update-tool-actions-pinning` | `update-tool-actions-pinning`, `actions-pinning` |

Notes:

- `--rule` can be repeated or comma-separated
- `--category` can be repeated or comma-separated (e.g. `--category workflows,settings`)
- `--severity` can be repeated or comma-separated (e.g. `--severity critical,high`)
- `--success` includes passing rule results for the selected rules
- `--rule` and `--category` are mutually exclusive
- `--rule` and `--severity` are mutually exclusive
- aliases resolve to canonical rule names internally
- if no `--rule`, `--category`, or `--severity` flags are given, all rules run

## Security Checks

The scanner runs the following checks against each repository. Findings are rated by severity: **critical**, **high**, **medium**, **low**, or **info**. See the linked rule docs for detailed explanations, examples, and remediation steps.

| Check | Category | Severity | What it fixes |
|-------|----------|----------|-----------------|
| [Pull Request Target](docs/rules/pull-request-target.md) | Workflows | Critical | `pull_request_target`, which should never be used in a public repo and is highly discouraged in a private repo |
| [Action Version Pinning](docs/rules/action-version-pinning.md) | Workflows | High | Actions referenced by tag (`@v4`) or branch (`@main`) instead of commit SHA |
| [Workflow Permissions](docs/rules/workflow-permissions.md) | Workflows | High | Workflows without an explicit `permissions` block, inheriting overly broad defaults |
| [Default Workflow Permissions](docs/rules/default-workflow-permissions.md) | Settings | High | Repository default `GITHUB_TOKEN` set to read-write instead of read-only |
| [Allowed Actions Policy](docs/rules/allowed-actions-policy.md) | Settings | Medium | Repository allows all actions to run instead of restricting to trusted sources |
| [Actions Can Approve PRs](docs/rules/actions-can-approve-prs.md) | Settings | Medium | Workflows can create and approve pull request reviews, bypassing required reviews |
| [Fork PR Workflow Approval](docs/rules/fork-pr-workflow-approval.md) | Settings | High | External contributors can trigger fork PR workflows without maintainer approval |
| [Update Tool Configuration](docs/rules/update-tool-configuration.md) | Updates | Medium | No Dependabot or Renovate config, invalid config, or missing `github-actions` coverage |
| [Update Tool GitHub Actions Cooldown](docs/rules/update-tool-actions-cooldown.md) | Updates | Low | Neither Dependabot nor Renovate sets a cooldown delay for `github-actions` updates |
| [Renovate GitHub Actions Pinning](docs/rules/update-tool-actions-pinning.md) | Updates | Medium | Renovate is not configured to pin actions to immutable commit SHAs (Dependabot has no equivalent option) |

## Build

From the repo root:

```bash
make build
./bin/gasa --help
```

Useful development commands:

```bash
make test
make fmt
make deps
```
