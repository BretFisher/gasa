# AGENTS.md - GitHub Actions Security Assessment

> This file provides context for AI coding assistants working on this project.
> It documents the current reality of the repo: a CLI-only security scanner for GitHub Actions and related repository settings.

---

Prefer retrieval-led reasoning over pre-trained training-led reasoning

Before writing code, first explore the project structure

## Docs pages

@PLAN.md - Project plan

## What This Is

A Go CLI that scans a GitHub repository, user, or org for GitHub Actions security issues and related maintenance gaps.

It focuses on:

- insecure workflow triggers
- unpinned third-party actions
- missing or overly broad workflow permissions
- risky repository-level Actions settings
- missing or incomplete Dependabot configuration

## Product Naming

- Human-readable name: **GitHub Actions Security Assessment**
- CLI command: **`gasa`**

Use those names consistently in docs, help text, examples, and future code changes.

## Scope

The scanner is intentionally focused on GitHub Actions security and closely related repo hygiene.
Avoid expanding into unrelated tooling or broad platform scanning unless explicitly requested.

## Current Architecture

### Tech Stack

- **Go 1.26+**
- **google/go-github/v84**
- **yaml.v3**
- **spf13/cobra** (CLI framework)
- **charm.land/lipgloss/v2** (terminal styling and tables)
- **CLI-first design**

### Project Structure

```text
.
├── main.go                 # CLI entrypoint: loads embedded rule docs, calls cmd.Execute
├── rulesdata.go            # //go:embed docs/rules/*.md (must live in root package)
├── cmd/                     # Cobra command tree (package cmd)
│   ├── root.go             # rootCmd, Execute(), persistent flags, Version
│   ├── run.go              # `gasa run` + scan request/auth helpers
│   ├── rules.go            # `gasa rules`
│   ├── version.go          # `gasa version`
│   ├── batch.go            # `gasa batch`
│   ├── output.go           # Table and JSON output formatting (lipgloss v2)
│   ├── output_html.go      # Single-repo HTML output
│   └── output_html_batch.go # Batch HTML report
├── internal/
│   └── scanner/
│       ├── scanner.go      # Scan orchestration
│       ├── workflow.go     # Workflow file checks
│       ├── settings.go     # Repo Actions settings checks
│       ├── updates.go      # Dependabot/Renovate config checks
│       ├── rules.go        # runFuncs (firing logic) + registry-backed rule selection
│       ├── ruledocs.go     # Loads docs/rules/*.md front-matter; renders report copy
│       └── findings.go     # Finding types, severities
├── docs/rules/*.md          # SINGLE SOURCE OF TRUTH: rule metadata + report copy
│                            #   (YAML front-matter) plus human prose body
├── go.mod
├── go.sum
└── Makefile
```

### Important Commands

From the repo root:

```bash
go run . --help
go run . rules
go run . run owner/repo
go run . run --debug owner/repo
go run . run --rule fork-pr-approval owner/repo
go run . run --category workflows owner/repo

make build
./bin/gasa --help
```

---

## Security Checks Implemented

The CLI currently checks these areas:

### Workflows

1. **Pull Request Target**
   - Detects `pull_request_target`
2. **Action Version Pinning**
   - Detects `uses:` references pinned to tags or branches instead of full commit SHAs
3. **Workflow Permissions**
   - Detects workflows without explicit `permissions`

### Repository Settings

1. **Allowed Actions Policy**
   - Detects repositories that allow all actions
2. **Default Workflow Permissions**
   - Detects repo default `GITHUB_TOKEN` set to write
3. **Actions Can Approve PRs**
   - Detects Actions being allowed to approve pull requests
4. **Fork PR Workflow Approval**
   - Detects less restrictive approval policies than `all_external_contributors`

### Updates

1. **Dependabot Configuration**
   - Detects missing config, invalid config, and missing `github-actions` coverage
2. **Dependabot GitHub Actions Cooldown**
   - Detects `github-actions` Dependabot update entries that do not set `cooldown`

Detailed rule documentation lives in `docs/rules/`.
Each rule doc should describe:

- what the rule checks
- how the scanner evaluates it
- exact API calls or workflow fields used
- bad and good examples
- links to relevant official GitHub docs

---

## CLI Behavior

### Authentication Order

The CLI resolves credentials in this order:

1. `--token-stdin`
2. `GITHUB_TOKEN`
3. `GH_TOKEN`
4. `gh auth token` with a short timeout

### Output Modes

- `--format table` by default with severity-colored terminal tables (lipgloss v2)
- `--format json` for machine-readable output
- `--format html` for browser-friendly reports
- status and progress go to stderr
- `--debug` is a global flag that writes diagnostic single-line output to stderr only
- debug lines use the format `[DEBUG] owner/repo | message`
- debug output must stay repo-prefixed and single-line so interleaved batch scans remain readable
- results go to stdout
- terminal width is auto-detected for table formatting

### Subcommands

- `gasa run <owner/repo>` — scan a repository
- `gasa batch <owner-or-user | owner/repo,...>` — scan multiple repositories and combine results
- `gasa rules` — list available rules and aliases

### Rule Selection

The `run` subcommand supports:

- `--rule <name-or-alias>` — filter by individual rule names or aliases
- `--category <name>` — filter by rule category (e.g. `workflows`, `settings`, `updates`)
- repeated or comma-separated values for both flags
- `--rule` and `--category` are mutually exclusive

Canonical rule names are endpoint-style where helpful, and short aliases are supported for day-to-day use.

---

## Current Build Targets

`Makefile`:

- `make run` - show CLI help
- `make build` - build `bin/gasa`
- `make test` - run Go tests (`-race -shuffle=on`)
- `make lint` - golangci-lint
- `make lint-md` - markdownlint (all `*.md`)
- `make deps` - tidy modules
- `make fmt` - format Go code
- `make clean` - remove built artifacts

---

## Linting

CI runs these via super-linter. After editing files of a given type, run the
matching linter locally and fix all findings before finishing. Linter configs
live in `.github/linters/` so local runs and CI share one source of truth.

- **Go** (`*.go`): `make lint` (golangci-lint), plus `go vet ./...` and `gofmt`
- **Markdown** (`*.md`): `make lint-md` (markdownlint)
- **GitHub Actions workflows** (`.github/workflows/*.yml`): `actionlint`, `zizmor`, and `poutine`
- **Dockerfiles**: `hadolint` (config `.github/linters/.hadolint.yaml`)
- **IaC / misconfiguration**: `checkov` (config `.github/linters/.checkov.yaml`)

---

## Known Issues / Technical Debt

- scanner checks still run sequentially in `internal/scanner/scanner.go`
- unauthenticated scans are limited by GitHub's 60 requests/hour API limit
- token permission guidance should also be added to the relevant rule docs that use repository settings APIs
- CLI help/auth troubleshooting should be expanded so users can quickly identify the minimal token permissions needed for full scans

---

## Guidance For Future Changes

- Always run `make build`, the relevant test command, and the linters for the
  file types you touched (see [Linting](#linting)) at the end of each task.

- Rule metadata (title, severity, category, aliases, order, description) and ALL
  human-facing report copy (finding titles, descriptions, fix advice, success
  messages) live in the YAML front-matter of `docs/rules/<slug>.md` — not in Go.
  To reword a finding or its "fix", edit the front-matter `messages:` map; no Go
  change or recompile of copy is needed. Dynamic values are `{{.Placeholders}}`
  filled by the rule's evaluator. The prose below the front-matter is the deep
  human doc and is also where external GitHub/Renovate docs are referenced.

- If adding a rule, update these together:
  - `docs/rules/<slug>.md` — front-matter (name, order, title, category,
    severity, aliases, description, messages) + prose body
  - `internal/scanner/scanner.go` — add the `ruleName…` constant
  - `internal/scanner/rules.go` — register the name → evaluator in `runFuncs`
  - `internal/scanner/` — implement the evaluator; render copy via
    `ruleMessage(ruleName, key, data)` and success via `successMessage(...)`
  - `README.md` if appropriate
  - `TestRuleDocsCoverage` enforces the rule↔doc binding; run `make test`
