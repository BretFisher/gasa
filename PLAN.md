# PLAN.md

## Purpose

This file is the working project plan for **GitHub Actions Security Assessment** (`gasa`).

It tracks:

- what has already been completed
- what is currently in progress or partially complete
- what still needs to be done before this tool is ready for broader team adoption

This file should be updated as work lands so it remains the current operational plan, not just a list of future ideas.

## Project State

Current state:

- the project is now a CLI-only Go tool
- the primary binary name is `gasa`
- the CLI framework is Cobra with lipgloss v2 for terminal-styled output
- the scanner covers workflow files, repository Actions settings, and Dependabot configuration
- the CLI supports subcommands (`gasa run`, `gasa rules`), human output with severity-colored tables, JSON output, rule/category filtering, and YAML config
- the repo has meaningful automated tests, but does not yet have CI workflows

## Phase 1: Product And Architecture Reset

Status: Completed

Goal:

- turn the project into a focused CLI-only GitHub Actions security scanner

Completed work:

- standardized product naming to **GitHub Actions Security Assessment** and CLI name `gasa`
- updated `AGENTS.md` to reflect the real project scope and constraints
- kept the project focused on GitHub Actions security and closely related repo hygiene
- cleaned repo housekeeping:
  - added `.gitignore`
  - removed the stale old binary name from `app/bin/`
  - ran `go mod tidy` to remove stale dependencies

Result:

- the codebase now matches the intended product direction and is much easier to evolve safely

## Phase 2: Core Scanner Rules And CLI Foundation

Status: Completed

Goal:

- implement a usable scanner with clear rule selection and consistent output

Completed work:

- implemented workflow checks for:
  - dangerous workflow patterns (`pull_request_target`)
  - action version pinning
  - explicit workflow permissions
- implemented repository Actions settings checks for:
  - allowed actions policy
  - default workflow permissions
  - Actions approving pull requests
  - fork PR contributor approval policy
- implemented Dependabot checks for:
- missing config
- invalid config
- missing `github-actions` coverage
- missing `cooldown` on `github-actions` updates
- added rule registry and aliases in `internal/scanner/rules.go`
- added selective execution through `--rule`
- added rule listing via `gasa rules` subcommand
- kept default output as terminal tables and added structured output formats
- preserved auth resolution order:
  - `--token-stdin`
  - `GITHUB_TOKEN`
  - `GH_TOKEN`
  - `gh auth token`

Result:

- the CLI can perform focused or full repository scans with a clear rule model

## Phase 3: Documentation Baseline

Status: Completed

Goal:

- make the tool understandable and operable without reading the source

Completed work:

- created and expanded `README.md`
- documented build, run, output, authentication, and rule selection behavior
- documented the minimal PAT permissions required for full scans
- created rule documentation in `docs/rules/` for all current checks
- updated the rule docs so they match current code behavior
- added token permission notes to the settings rule docs
- corrected Dependabot documentation to reflect the actual evaluation logic

Result:

- the repo docs now match the current CLI and scanner behavior closely

## Phase 4: Human Remediation Output

Status: Partially completed

Goal:

- improve scan output so humans can jump directly to the right GitHub page or file to fix each issue

Completed work:

- added repo-specific `fix_url` output for findings
- linked workflow findings to workflow files and line numbers when available
- linked Dependabot findings to `.github/dependabot.yml` or the new-file creation page when config is missing
- linked repository settings findings to `Settings > Actions`
- included `fix_url` in JSON output
- updated human-readable output to print the remediation URL

Remaining work:

- improve settings links further if stable GitHub section anchors are available
- make missing-permission findings more explicit in human output so operators know which rules were skipped or degraded
- document the JSON output contract more formally before broader automation use
- decide whether to version the JSON schema/output contract

Result so far:

- findings are now much more actionable for humans and downstream tooling than they were originally

## Phase 4b: CLI Framework And Output Improvements

Status: Completed

Goal:

- modernize the CLI framework and improve terminal output for human readability

Completed work:

- migrated CLI from stdlib `flag` to Cobra with `spf13/cobra`
- restructured CLI around subcommands: `gasa run` (scan) and `gasa rules` (list rules)
- `gasa` with no subcommand now shows help
- moved `--rule` to a `run`-only flag
- added `--category` flag for filtering rules by category, mutually exclusive with `--rule`
- added `--severity` flag for filtering runs to selected effective severities
- migrated terminal output to lipgloss v2 (`charm.land/lipgloss/v2`)
- added severity-colored tables for findings and rules output using `lipgloss/table`
- terminal width auto-detection via `charmbracelet/x/term`
- removed scoring from code, output, and documentation (findings are listed by severity only)
- added `output.go` to separate all formatting logic from CLI wiring

Result:

- the CLI has a clean subcommand structure, modern terminal output, and category-based rule filtering

## Phase 5: Testing And Safety Hardening

Status: In progress

Goal:

- make the scanner safer to change and safer for teams to trust

Completed work:

- added unit and mocked-API tests across the scanner package
- added tests for:
  - severity ordering
  - rule registry, alias resolution, and category filtering
  - repo parsing and finding deduplication
  - fix URL generation
  - workflow analysis logic
  - settings checks with mocked GitHub API responses
  - Dependabot checks with mocked GitHub API responses
  - read-only request behavior using mocked endpoints
  - graceful error handling for repository access failures
- added CLI output tests for:
  - `printTable`
  - `printJSON`
  - `printRulesTable`
  - `printRulesJSON`
- added end-to-end mocked scan coverage for mixed findings in one repository scan
- verified the app builds and tests pass locally

Remaining work:

- add coverage reporting and make it part of the regular workflow
- add more API edge-case tests for:
  - rate limits
  - timeouts
  - partial access to settings APIs
  - malformed API responses
- add regression tests whenever new scanner rules are introduced
- consider more direct assertions around deterministic output ordering
- consider concurrency in the scanner only after preserving deterministic results and test stability

Result so far:

- the project has moved from effectively no tests to a solid baseline test suite, but it still needs CI enforcement and broader edge-case coverage

## Phase 6: Authentication, Permissions, And Operator Guidance

Status: Partially completed

Goal:

- make it easy for users to know how to authenticate and what permissions are required

Completed work:

- analyzed the exact repository GET endpoints used by the scanner
- documented minimal fine-grained token permissions for full scans
- documented the practical classic PAT requirement for full settings checks
- updated the settings error message to reflect the correct permission guidance
- added permission notes to the settings rule docs

Remaining work:

- improve CLI help output for insufficient permissions and troubleshooting
- make rate-limit behavior and degraded scans more explicit in docs and output
- document clearly which checks require which level of access
- consider whether the CLI should summarize skipped or unavailable checks at the end of a scan

Result so far:

- token permissions are now documented, but operator guidance can still be clearer and more actionable

## Phase 7: Rule Engine And Configurable Policy Architecture

Status: Partially completed

Goal:

- evolve the scanner from a fixed built-in rule registry into a rule system that supports user configuration cleanly

Why this phase comes next:

- the current rule model is static and code-driven
- user-facing rule configuration is becoming a product requirement
- this work should happen before broader team adoption so rule IDs, configuration shape, and extensibility points stabilize early

Current architecture constraints to address:

- rules are registered statically in `internal/scanner/rules.go`
- rule execution currently mixes rule selection with direct scanner method calls
- workflow, settings, and Dependabot checks fetch and analyze data inside rule-specific code paths
- this makes it harder to support reusable rule configuration or future extensibility without duplicating API calls

Required architectural direction:

- keep built-in rule execution in Go for now
- add YAML configuration for scanner behavior and rule selection first
- refactor scanner internals around:
  - data collection
  - normalized facts
  - rule evaluation
- defer arbitrary user-authored rule logic unless there is a concrete product need later

Milestone scope:

- define a scanner config file format, likely `.gasa.yml`
- support user configuration for:
  - including rules
  - excluding rules
  - severity overrides
  - rule-specific options
  - suppressions or exceptions with reasons
  - reusable profiles if helpful
- refactor the scanner so GitHub API reads and file parsing happen once per scan and produce normalized facts
- make rules consume normalized facts instead of each rule triggering its own fetch path
- define stable rule identifiers and metadata expectations
- document how built-in rules and future contributed rules should be added, tested, and documented

Recommended design principles:

- do not use raw YAML as a full rule language in v1
- do not introduce a complex policy engine unless simpler configuration proves insufficient
- keep the scanner CLI-first and focused on GitHub Actions security
- keep rule behavior deterministic and testable
- avoid adding plugin loading or dynamic code execution in early versions
- prefer a small number of well-defined configuration points over a broad but weak DSL

Proposed architecture:

1. Collectors
   - fetch repository metadata
   - fetch workflow files and parse them once
   - fetch Actions settings once
   - fetch Dependabot config once
   - record access limitations and degraded-check conditions explicitly

2. Normalized facts
   - define internal fact models such as:
     - repository facts
     - workflow facts
     - Actions settings facts
     - Dependabot facts
     - authentication and access facts
   - make these facts the input contract for all rule evaluation

3. Rule evaluation
   - keep built-in rules in Go
   - have each rule evaluate facts and emit findings
   - remove direct API fetch behavior from individual rule execution paths where practical

4. User configuration
   - add `.gasa.yml` support
   - allow:
     - `include`
     - `exclude`
     - overrides
     - suppressions
     - rule options
   - decide CLI precedence over config file and document it clearly

5. Future extensibility
   - evaluate CEL or Rego only after templates and facts prove insufficient
   - only consider external rule packs after the config format, fact model, and test strategy are stable

Expected YAML configuration scope:

- scanner configuration, not arbitrary rule logic
- example capabilities:
  - enable or disable rules
  - tune severities
  - set org-specific allowed action owners
  - suppress findings for known reviewed exceptions

Open source patterns to follow:

- ESLint and golangci-lint:
  - code-defined built-in rules or linters
  - config files for selection and tuning
  - stable rule IDs and documented rule metadata
- Semgrep:
  - strong rule metadata
  - per-rule docs and tests
  - clear schema for rule definitions
- Trivy and OPA-style tools:
  - policy-as-code for advanced users
  - useful reference, but likely too heavy for the first configurable-rules milestone

Implementation requirements:

- preserve existing CLI rule selection behavior during the transition
- keep built-in rules working while internals are refactored
- make degraded checks and permission limitations explicit in the fact model
- ensure output ordering remains deterministic
- add tests for config parsing, precedence, fact generation, and deterministic rule evaluation
- update `README.md`, `AGENTS.md`, and `docs/rules/` to match the new architecture
- define contribution expectations for new rules:
  - stable ID
  - metadata
  - docs
  - tests
  - examples
  - remediation guidance

Recommended task breakdown:

- inventory the current rule execution flow and identify shared data-fetch boundaries
- design normalized fact types and scanner collection flow
- refactor built-in rules to evaluate facts instead of calling fetch logic directly
- design `.gasa.yml` schema and precedence rules
- implement config loading and validation
- implement include/exclude, severity overrides, and suppressions
- add tests for config parsing, rule evaluation, and deterministic output
- document user configuration, rule contribution workflow, and future extensibility boundaries

Result needed:

- the scanner should support practical user configuration immediately
- the rule architecture should be ready for safe addition of new built-in rules and future configuration needs
- the project should avoid locking itself into a static registry that becomes harder to evolve after CI, packaging, and broader adoption land

## Phase 8: CI, Docker, GHCR, And Releases

Status: Not started

Goal:

- automate validation, packaging, publishing, and releases using GitHub Actions

Required workflows:

- Go build/test workflow for pull requests and default branch changes
- Docker build workflow that produces a minimal runtime image containing only the compiled `gasa` binary
- GHCR publishing workflow for tagged releases and optionally the default branch
- full release workflow to generate release artifacts and publish a GitHub release

Expected scope:

- run `go test ./...`
- run `make build`
- build a small production image
- push images to `ghcr.io`
- generate release binaries for common target platforms
- attach release artifacts to GitHub Releases
- include version metadata in binaries and images where useful

Implementation requirements:

- all third-party actions must be pinned to full SHAs
- workflow permissions must be minimal and explicit
- the workflows should model the same security standards this tool expects from other repos
- the container image should include only what is needed to run the binary
- the container image should not include source code, build tooling, or unnecessary packages

Recommended task breakdown:

- add CI workflow for test/build on pull requests and default branch
- add Dockerfile if needed for a minimal runtime image
- add GHCR publishing workflow
- add release workflow for multi-platform artifacts
- document release process and installation methods in `README.md`

## Phase 9: Release Readiness For Team Adoption

Status: Not started

Goal:

- make the project safe and predictable enough for internal teams to rely on it

Needed work:

- define supported operating systems and architectures
- document installation paths for the CLI and container image
- define versioning and release cadence expectations
- document how teams should interpret findings and scores
- document what the scanner does not check so the scope boundaries are clear
- add a short security model section explaining that the scanner reads repository data/settings but does not modify them
- expand README examples for:
  - public repo scans
  - private repo scans
  - rule-specific scans
  - JSON output usage in automation
- decide on the stability expectations for machine-readable JSON output

Result needed:

- teams should be able to understand what the tool does, what it does not do, how to authenticate it safely, and how to act on its output

## Phase 10: Future Extensions

Status: Deferred

Potential work later:

- organization-level scanning, if explicitly scoped and kept aligned with the product focus
- additional GitHub Actions security rules, only if they remain tightly aligned with Actions security and repository hygiene
- research whether `workflow_run`, `issue_comment`, or other workflow triggers should become new dangerous-trigger checks; do not add them to the existing `pull_request_target` rule until the exact risky conditions, false-positive boundaries, severities, docs, and examples are understood
- S8 from `SECURITY-REVIEW.md` is not approved for implementation: batch HTML reports are intended for GitHub admins, and retaining detailed scan errors is currently preferred over sanitizing report diagnostics

Deferred tooling decisions:

- `release-please` (googleapis/release-please-action): evaluated and deferred. It automates version
  bumping and CHANGELOG generation from Conventional Commits, then cuts the tag/release; GoReleaser
  would still build and publish artifacts on that tag (they are complementary, not redundant). Not
  adopted now because the project has a single committer, does not yet enforce Conventional Commits,
  and the current `workflow_dispatch` release with an explicit version input is simpler. Revisit when
  either a second regular contributor lands or Conventional Commits are enforced and hands-off
  versioning is wanted. Prerequisite before adoption is commit-message discipline, not the action
  itself. Coordinate release ownership so release-please and GoReleaser do not both try to create the
  GitHub Release.

Guardrails:

- do not turn the project into a hosted service, dashboard, or broader platform product without an explicit direction change
- keep the product CLI-first and security-focused

## Phase 11: Homebrew Distribution

Status: Not started

Goal:

- let users install the CLI with `brew install` in addition to GHCR images and raw release binaries

Why this phase:

- Homebrew is the most common install path for macOS/Linux CLI users
- GoReleaser already produces the binaries, so generating a formula/cask is an incremental addition rather than a new tool

Approach:

- use GoReleaser's native Homebrew support to generate and publish the formula/cask on each tagged release
- note: GoReleaser v2 is migrating the `brews:` stanza toward `homebrew_casks:`; confirm the current syntax against GoReleaser docs at implementation time

Prerequisites:

- create a dedicated tap repository, conventionally `bretfisher/homebrew-tap`, which enables `brew install bretfisher/tap/gasa`
- provision a cross-repo write token: `GITHUB_TOKEN` is scoped to this repo only and cannot push to the tap repo, so a PAT or GitHub App token with `contents:write` on the tap repo is required, stored as a release secret
- decide whether the formula installs the prebuilt release binary (preferred) versus building from source

Implementation requirements:

- pin and least-privilege any new token usage; do not widen the existing release job's permissions beyond what the tap push needs
- keep the formula install path consuming the already-built, checksummed release archives so Homebrew installs match the published artifacts
- verify a real `brew install` end to end on macOS (amd64 and arm64) before announcing the install path
- document the Homebrew install method in `README.md` alongside the GHCR and binary install paths

Recommended task breakdown:

- create the `homebrew-tap` repository
- create and store the tap write token as a secret
- add the Homebrew stanza to `.goreleaser.yml`
- run a test release to confirm the formula is generated and pushed
- validate `brew install` on macOS and Linux
- document the install path in `README.md`

## Phase 12: Cross-Repo Rule Validation (E2E) With `gasa-pass` And `gasa-fail`

Status: Not started

Goal:

- prove every shipped rule actually fires (and actually passes) against real GitHub repositories and real GitHub API responses, not just mocked HTTP
- make that proof runnable locally with an admin PAT and in Actions with a read-only PAT

Why this phase:

- the existing suite is unit + mocked-API only. It validates the scanner's reaction to a *recorded* API shape, not the shape GitHub actually returns today
- GitHub changes settings API payloads and adds new settings endpoints. A mocked suite cannot detect that drift
- rules that read repository *settings* (allowed-actions policy, default workflow permissions, Actions-can-approve-PRs, fork-PR contributor approval) are the ones most likely to silently degrade, and are exactly the ones mocks cover worst
- these are integration tests, not unit tests: they cross a process boundary, a network boundary, and an auth boundary. They must be separated from `make test` so the default gate stays hermetic, fast, and offline

### Companion repository roles

- `bretfisher/gasa-pass` (public) — every rule should report success. It is the "known good repository" reference implementation, and doubles as a documentation artifact operators can copy from
- `bretfisher/gasa-fail` (public) — the primary "known bad repository". It should fail every rule it structurally can, and is the real regression net: a rule that silently stops firing is the failure mode that matters most in a security scanner
- `bretfisher/gasa-fail-private` (private, **not yet created**) — the second fail fixture, required
  because rules 8 and 9 cannot both fail in one repo (see R18). Carries Dependabot scoped to a
  non-actions ecosystem plus a Renovate config that covers `github-actions` with neither
  `minimumReleaseAge` nor pinning, so rules 9 and 10 fail there while rule 8 passes. Being private is
  deliberate: it also gives the project a fixture for private-repo Actions settings behavior, which
  differs from public and may warrant its own rules later

Because no single repository can fail every rule, the coverage invariant is: **each rule must have a fail case in at least one fail fixture and a pass case in `gasa-pass`** — not "gasa-fail fails everything".

### Current baseline (measured 2026-08-08, with `--no-config`)

A scan of both repos with today's `main` produces:

- `gasa-pass` — passes for 9 of 10 rules: `pull-request-target`, `action-version-pinning`, `workflow-permissions`, `allowed-actions-policy`, `default-workflow-permissions`, `actions-can-approve-prs`, `fork-pr-contributor-approval`, `update-tool-configuration`, `update-tool-actions-cooldown`
- `gasa-fail` — findings for `pull-request-target`, `action-version-pinning` (6), `workflow-permissions` (2), `allowed-actions-policy`, `update-tool-configuration`. Passes for `default-workflow-permissions`, `actions-can-approve-prs`, `fork-pr-contributor-approval`

Re-baselined 2026-08-09 after the `gasa-fail` settings flip described below. `gasa-fail` now fails 7 of 10 rules: `pull-request-target`, `action-version-pinning` (6), `workflow-permissions` (2), `allowed-actions-policy`, `default-workflow-permissions`, `fork-pr-contributor-approval`, `update-tool-configuration`.

Gaps the baseline exposes, all of which this phase must close:

1. ~~`gasa-fail` passes three settings rules~~ — **partially closed 2026-08-09.** `default_workflow_permissions` flipped `read` → `write` and `fork_pr_contributor_approval` flipped `all_external_contributors` → `first_time_contributors`, so rules 5 and 7 now fail correctly. Still open: `can_approve_pull_request_reviews` remains `false`, so rule 6 still passes on the fail fixture
2. `update-tool-actions-pinning` evaluates on both repos and emits neither a finding nor a success. It is the only rule with no observed state at all. Fixtures must be designed to force it into both
3. `update-tool-actions-cooldown` is silent on `gasa-fail` — neither a finding nor a success

Resolved during planning:

- an earlier baseline run showed `allowed-actions-policy` and `actions-can-approve-prs` never
  executing. Proven cause: this repo's own `.gasa.yaml` excludes both rules and the CLI auto-discovers
  it from the working directory. Both rules are fine and both emit success findings; the config was
  masking them. This is exactly the failure mode the phase exists to catch — a scan that looks clean
  because the rule never ran — and it was reproducible on `main` before any e2e code existed. Fixed by
  the `--no-config` flag below

### Architecture

Four layers, deliberately separated so the write path and the read path never share code or credentials.

**0. `--no-config` CLI flag — completed**

Added a persistent `--no-config` flag that ignores all config files, including an auto-discovered `.gasa.yml` / `.gasa.yaml`. Mutually exclusive with `--config`. Precedence is `--no-config` > `--config PATH` > auto-discovery.

- `cmd/config.go` holds `resolveScanConfig`, the single resolver now shared by `run` and `batch`. Both commands previously duplicated the same load-or-discover block; divergence there would mean the same repo scanned two ways silently applies two different rule sets
- the scan header prints `Config: disabled (--no-config)` rather than omitting the line, so "no config existed" is distinguishable from "a config existed and was ignored on purpose"
- `cmd/config_test.go` covers all five precedence paths plus the mutually-exclusive rejection

This is what makes the e2e harness trustworthy: it always scans the full registered rule set regardless of what config sits in the working directory.

**1. Fixture source of truth lives in this repo**

```text
testdata/e2e/
  gasa-e2e.yaml                 # explicit scanner config used by e2e ONLY
  fixtures/
    gasa-pass/
      repo.yaml                 # declarative repo settings manifest
      files/                    # verbatim tree pushed to the repo
        .github/dependabot.yml
        .github/workflows/*.yaml
        README.md
    gasa-fail/
      repo.yaml
      files/...
  expected/
    gasa-pass.golden.json
    gasa-fail.golden.json
```

Why in-repo rather than editing the companion repos by hand: the fixture repos are *inputs to a test*. If they drift, the test lies while still going green. Keeping content and settings in this repo means a PR that adds a rule also shows its pass fixture, its fail fixture, and its expected output in one reviewable diff. It also makes the fixture repos rebuildable from scratch if one is deleted.

`repo.yaml` covers the settings the scanner reads:

```yaml
visibility: public
actions:
  enabled: true
  allowed_actions: all              # gasa-fail
  default_workflow_permissions: write
  can_approve_pull_request_reviews: true
  fork_pr_contributor_approval: first_time_contributors
```

**2. Sync (write path) — local only**

- `make fixtures-apply` pushes `files/` and applies `repo.yaml` via `gh api`
- requires the existing admin PAT via `gh auth token`
- never runs in CI, and the CI token cannot perform these calls even if it did
- prompts for confirmation before writing, since it force-syncs the fixture repos' default branch

**3. Verify (read path) — local and CI**

- `make fixtures-verify` reads both repos and compares live state against `repo.yaml` + `files/`
- fails with an explicit "run `make fixtures-apply` from a machine with the admin PAT" message
- CI runs this *before* the assertions, so drift is reported as drift rather than as a bogus rule regression. This distinction matters: without it, someone flipping a setting in the GitHub UI produces a failure that looks like a scanner bug

**4. Assertions — Go tests behind a build tag**

- runs with `--no-config` / a nil `*scanner.Config`, so the full registered rule set is always exercised
- new package `test/e2e`, files carrying `//go:build e2e`
- run via `go test -tags=e2e -timeout=5m ./test/e2e/...`
- build tag rather than `t.Skip`, so the default `make test` cannot make a network call even by accident, and so `go vet ./...` on a laptop with no token stays clean
- the test calls the `internal/scanner` API directly (not the CLI binary) so failures point at scanner behavior, with one thin CLI smoke test for the `--config` + `--token-stdin` path

### Golden file contract

Assert on rule *outcomes*, not on prose.

Each golden entry records only:

```json
{"rule": "workflows/workflow-permissions", "id": "no-permissions-.github/workflows/bad.yaml", "severity": "high", "success": false}
```

Deliberately excluded from the golden:

- `Title`, `Description`, `Remediation` — these are rendered from `docs/rules/*.md` front-matter templates and change with copy edits. Asserting them turns every wording fix into an e2e failure
- `FixURL`, `DocURL` — already covered by dedicated unit tests
- `Line` — stable today, but couples the golden to fixture file formatting

Entries are sorted deterministically (rule, then id) before comparison. `make e2e-update` regenerates goldens; regenerating must be an explicit act, never automatic.

### Coverage matrix test

A separate test in the same package walks `scanner.AvailableRules()` and fails if any rule lacks **either** a `success: false` entry in *at least one* fail fixture golden (`gasa-fail.golden.json` or `gasa-fail-private.golden.json`) **or** a `success: true` entry in `gasa-pass.golden.json`. The "at least one" wording is load-bearing — see R18 for why a single fail repo cannot cover every rule.

This is what makes the phase durable: adding a rule without fixtures becomes a build failure instead of an untested rule. It also directly encodes the Phase 5 remaining-work item "add regression tests whenever new scanner rules are introduced".

### Token and permission model

Local:

- reuse the existing `gh` admin PAT via `gh auth token`
- needed for both read and write; this is the only credential that can run `fixtures-apply`

CI — **created, pending verification**:

- a **fine-grained PAT** with read-only Contents and Administration on `gasa-pass` and `gasa-fail`
- `Administration: Read-only` is what unlocks `/actions/permissions*` and `/actions/permissions/fork-pr-contributor-approval`
- stored as an **environment** secret in the repository environment `e2e-fixtures`. Confirmed present: environment `e2e-fixtures`, secret name **`E2E_REPO_PAT`**. Note GitHub normalizes/rejects hyphens in secret names, so the workflow must reference `secrets.E2E_REPO_PAT` with underscores
- an environment secret is reachable only by a job that declares `environment: e2e-fixtures`, which keeps it out of reach of every other workflow in this repo
- exposed via `env:` on the single step that needs it, never at job or workflow level
- do **not** use a classic PAT here: the classic scope that grants settings read is `repo`, which is read *and write* across every repo the account owns. That is the opposite of the goal

Verification task before relying on this: the README currently states that a classic PAT is required
for full settings checks. Confirm empirically whether `Administration: Read-only` on a fine-grained
PAT actually returns all four settings endpoints. Until a run with `E2E_REPO_PAT` proves it, this
stays an **untested hypothesis** — the local baseline above was collected with the admin PAT, which
is strictly more privileged. If a settings rule reports "skipped" under the CI token, the token is
the cause, not the scanner. Update the README either way; the answer matters to every operator, not
just to CI.

Operational note: fine-grained PATs expire (1 year maximum). Add the expiry date to the phase notes and make the e2e job's auth failure message explicit enough that an expired token is diagnosed in seconds rather than mistaken for a scanner bug.

### Workflow design

New file `.github/workflows/e2e.yml`, kept separate from `ci.yml` because it has a different trust model, a different credential, and a different failure meaning.

- workflow-level `permissions: {}`; the single job gets `contents: read` only. `GITHUB_TOKEN` is not the credential doing the scanning
- job declares `environment: e2e-fixtures`
- `timeout-minutes: 10`
- concurrency group on workflow + ref with `cancel-in-progress: true`
- steps: checkout (`persist-credentials: false`) → `setup-go` with `go-version-file: go.mod` → `make fixtures-verify` → `make test-e2e`

Trigger recommendation — this is the important security decision:

- **do not run this on `pull_request`.** The job needs a real cross-repo PAT, and a PR in a Go repo runs attacker-controlled code (`go test` executes whatever the PR added). Any PR-triggered job holding a PAT is an exfiltration path, and it does not require a fork to exploit
- run on `push` to `main`, filtered to paths that can change scanner behavior (`**/*.go`, `go.mod`, `go.sum`, `docs/rules/**`, `testdata/e2e/**`)
- run on a daily `schedule` — this is the trigger that catches GitHub-side API drift, which is a primary reason for the phase
- `workflow_dispatch` for on-demand pre-merge validation — **approved**. It is safe here because dispatch runs the workflow file from the selected ref under an environment gate, and only accounts with write access can trigger it. The `e2e-fixtures` environment can additionally carry required reviewers if a per-run gate is wanted later

Consequence to accept explicitly: rule regressions are caught on `main`, not in the PR that introduces them. That is the correct trade for a public repo. Local `make test-e2e` is the pre-merge check, and it is cheap.

### Fixture repo safety

`gasa-fail` is a public repo that, by design, contains a `pull_request_target` workflow and (after `fixtures-apply`) deliberately weak fork-PR approval settings. That combination on a public repo would normally be a live abuse surface, not just a fixture.

**Resolved:** the repo-level setting that blocks pull requests from external non-write contributors is enabled on `gasa-fail`. External PRs cannot be opened, so the `pull_request_target` fixture has no untrusted input to act on. Both repos stay public — which is a bonus, since `gasa-pass` doubles as a public reference for a well-configured repo.

One consequence to encode in the fixtures: this setting is *not* the same as the
`fork-pr-contributor-approval` policy the scanner reads, so `gasa-fail` can still be set to the weak
approval policy the rule is supposed to flag while remaining unexploitable. Confirm this holds after
`fixtures-apply` flips that setting — if enabling the external-PR block also forces the approval
policy, the two requirements conflict and `gasa-fail` needs the settings-rule fixtures moved to a
third repo or asserted via mocked tests instead.

Remaining hygiene:

- fixture workflow job bodies must be inert (`run: echo fixture`) so a trigger firing costs nothing and does nothing
- fixture repos must hold no secrets and no environments
- Dependabot must not open PRs that mutate fixture content out from under the goldens. Either set `open-pull-requests-limit: 0` in the fixture repos or accept that `fixtures-verify` will catch the drift and `fixtures-apply` will revert it — the second is simpler and self-healing, and is the recommended default

### Make targets

Per repo convention, all of these go in the `Makefile` and get documented in `README.md`:

- `make test` — unchanged; hermetic, offline, the CI gate
- `make test-e2e` — `go test -tags=e2e -timeout=5m ./test/e2e/...`
- `make fixtures-verify` — read-only drift check against both repos
- `make fixtures-apply` — write path, local + admin PAT only, confirmation prompt
- `make e2e-update` — regenerate golden files

### Recommended task breakdown

Done:

- ~~add a CLI option that ignores config files~~ — `--no-config`, see layer 0
- ~~create the read-only fine-grained PAT and the `e2e-fixtures` environment~~ — secret `E2E_REPO_PAT`
- ~~decide `gasa-fail` visibility~~ — stays public, external PRs blocked at the repo setting

Remaining:

1. Capture the current fixture repo trees and settings into `testdata/e2e/fixtures/` so the checked-in state matches reality before anything changes
2. Design the coverage matrix: for each of the 10 rules, decide its `gasa-pass` construction and its `gasa-fail` construction. Close both gaps listed in the baseline section
3. Implement `fixtures-verify` and `fixtures-apply`, verify first
4. Flip `gasa-fail` settings to their insecure states via `fixtures-apply`; re-baseline
5. Add the `test/e2e` package, golden comparison, and the coverage matrix test
6. Run the e2e suite once with `E2E_REPO_PAT` locally to prove `Administration: Read-only` is sufficient before wiring CI; update README token guidance
7. Add `.github/workflows/e2e.yml` referencing `secrets.E2E_REPO_PAT`; lint with `actionlint`, `zizmor`, and `poutine`
8. Document the whole loop in `README.md` and the fixture contract in `AGENTS.md`

### Per-rule fixture audit

A rule-by-rule review of docs, evaluation code, and the *actual* state of both fixture repos as read directly with `gh api` — deliberately not trusting scanner output, since the scanner is the thing under test. Recommendations accumulate here and are actioned only after all 10 rules are reviewed.

Verdict key: **OK** = fixtures already produce the correct pass/fail split, no change needed. **FIX-FIXTURE** = repos need changing. **FIX-CODE** = scanner or docs need changing.

#### Rule 1 — `workflows/pull-request-target` — verdict: OK

Docs and code agree: flags any workflow whose top-level `on` contains `pull_request_target` as a bare string, an array member, or a mapping key. Deliberately does not attempt to prove that untrusted checkout follows. Files are filtered to `.yml`/`.yaml`. The success finding is synthesized generically when the rule returns zero findings.

Verified directly against both repos:

| Repo | Workflow | `on:` | PRT |
|---|---|---|---|
| gasa-pass | `daily-repo-status.lock.yml` (101 KB, gh-aw generated) | `schedule`, `workflow_dispatch` | no |
| gasa-pass | `pr-target-replace-1.yaml` | `pull_request` | no |
| gasa-pass | `pr-target-replace-2.yaml` | `workflow_run` | no |
| gasa-pass | `sha-pins-and-permissions.yaml` | `push`, `pull_request` | no |
| gasa-pass | `daily-repo-status.md` | — | correctly filtered out |
| gasa-fail | `bad-no-sha-pins.yaml` | `push`, `pull_request` | no |
| gasa-fail | `bad-pull-request-target.yaml` | `pull_request_target:` (mapping) | **yes** |

Derived expectation — gasa-pass passes, gasa-fail emits exactly one finding on `bad-pull-request-target.yaml` — matches scanner output exactly. `--debug` also confirms all four gasa-pass workflows `parsed OK`, so the pass is genuine rather than the vacuous "nothing parsed, therefore clean" result.

Decided, no action:

- do **not** add bare-string or array trigger shapes to `gasa-fail`. `hasDangerousTrigger` already has unit coverage for all three shapes in `workflow_test.go`. E2E should exercise the integration path (contents listing, base64 decode, suffix filter), not re-test pure-function branches. Keeping e2e lean is what keeps it fast and non-flaky

#### Rule 2 — `workflows/action-version-pinning` — verdict: OK

Two evaluation paths, not one. When a workflow parses, the rule walks the parsed structure — every `jobs.<id>.steps[].uses` plus `jobs.<id>.uses` (reusable workflow calls). Only when parsing fails does it fall back to the line regex `^\s*-?\s*uses:\s*['"]?([^'"@\s]+)@([^'"@\s]+)['"]?`. Local (`./`) and `docker://` refs are skipped in both paths. `isSHA` accepts 40 **or** 64 hex characters.

Verified directly by extracting and classifying every `uses:` in both repos independently of the scanner:

| Repo | Workflow | `uses:` refs | unpinned |
|---|---|---|---|
| gasa-pass | `daily-repo-status.lock.yml` | 48 | 0 |
| gasa-pass | `pr-target-replace-1.yaml` | 2 | 0 |
| gasa-pass | `pr-target-replace-2.yaml` | 2 | 0 |
| gasa-pass | `sha-pins-and-permissions.yaml` | 4 | 0 |
| gasa-fail | `bad-no-sha-pins.yaml` | 4 | **4** (`@v4` ×4, lines 17/22/30/33) |
| gasa-fail | `bad-pull-request-target.yaml` | 2 | **2** (`@v7` ×2, lines 19/28) |

Derived expectation — gasa-pass passes across 56 pinned refs, gasa-fail emits 6 findings — matches scanner output exactly, including all six line numbers.

Decided, no action:

- do **not** add a branch ref (`@main`) or an unpinned reusable-workflow `job.Uses` to `gasa-fail`.
  `workflow_test.go` already covers branch refs, reusable-workflow refs, local actions, `docker://`,
  both 40- and 64-hex SHAs, comment-only `uses:` lines, the regex fallback for unparsable YAML, and
  `ignore_same_owner` in both directions. This rule is the best unit-covered of the workflow rules;
  e2e should add integration coverage, not duplicate it

#### Rule 3 — `workflows/workflow-permissions` — verdict: OK

Structural check only, and the docs say so explicitly. A workflow is compliant if top-level
`permissions` exists **or** every job carries its own `permissions`. `hasExplicitPermissions` tests
`Permissions != nil` on the `interface{}` field, so YAML `permissions: {}` unmarshals to an
empty-but-non-nil map and counts as explicit — confirmed empirically, since two `gasa-pass`
workflows use exactly that form and pass.

Verified directly against both repos:

| Repo | Workflow | permissions | compliant |
|---|---|---|---|
| gasa-pass | `daily-repo-status.lock.yml` | top-level `permissions: {}` (line 70) + 5 job-level blocks | yes |
| gasa-pass | `pr-target-replace-1.yaml` | top-level `permissions: {}` | yes |
| gasa-pass | `pr-target-replace-2.yaml` | top-level `permissions: pull-requests: write` | yes |
| gasa-pass | `sha-pins-and-permissions.yaml` | top-level `permissions: {}` + job-level | yes |
| gasa-fail | `bad-no-sha-pins.yaml` | none at any level | **no** |
| gasa-fail | `bad-pull-request-target.yaml` | none at any level | **no** |

Derived expectation — gasa-pass passes, gasa-fail emits exactly two findings — matches scanner output exactly.

Decided, no action:

- unit coverage in `workflow_test.go` already spans workflow-level, all-jobs, partial-jobs (correctly non-compliant), and the empty workflow. No fixture additions needed

#### Rule 4 — `actions/permissions/allowed-actions-policy` — verdict: OK

Reads `GET /repos/{owner}/{repo}/actions/permissions` and branches on `allowed_actions`: `all` → medium finding; `selected` → `pass-selected`; `local_only` → `pass-local-only`; Actions disabled → `pass-disabled`.

Verified directly:

| Repo | `enabled` | `allowed_actions` | allowlist | expected |
|---|---|---|---|---|
| gasa-pass | `true` | `selected` | `github_owned_allowed: true`, `verified_allowed: true`, patterns `chainguard-actions/*` | pass (`pass-selected`) |
| gasa-fail | `true` | `all` | endpoint 409s ("All actions and workflows are allowed") | **finding** (`settings-all-actions-allowed`) |

Both match scanner output exactly. This is the first settings rule and its fixtures are already correct — no change needed.

Also observed on this endpoint: both repos return `"sha_pinning_required": false`, a GitHub setting the scanner does not currently read. See R8.

#### Rule 5 — `actions/permissions/workflow/default-workflow-permissions` — verdict: FIX-FIXTURE

Reads `GET /repos/{owner}/{repo}/actions/permissions/workflow` and flags `default_workflow_permissions == write` as high. `read` passes.

Verified directly:

| Repo | `default_workflow_permissions` | expected | correct for its role? |
|---|---|---|---|
| gasa-pass | `read` | pass | yes |
| gasa-fail | `read` | **pass** | **no — must fail** |

Scanner output matches the live settings on both, so the rule is behaving correctly. The defect is in the fixture: `gasa-fail` is configured securely for this rule and therefore proves nothing.

Required fix: set `gasa-fail` to `default_workflow_permissions: write` via `PUT /repos/bretfisher/gasa-fail/actions/permissions/workflow`. That endpoint carries `can_approve_pull_request_reviews` in the same body, which is rule 6's input, so both settings should be flipped in a single call rather than two.

Risk of that flip, assessed rather than assumed: `gasa-fail`'s workflows genuinely execute — its run
history shows a `CI | push | failure` run. Flipping the default to `write` means those runs receive
a read-write `GITHUB_TOKEN`. Blast radius is small (external PRs are blocked, only trusted pushes
trigger, the repo holds nothing of value, and the job dies immediately on `npm ci` with no
`package.json`), but it is not zero. Mitigation is the fixture-inertness item already in the hygiene
list: rewriting `run: npm ci && npm test` to `run: echo fixture` changes no rule outcome, since
rules 2 and 3 read `uses:` and `permissions:`, never `run:`.

#### Rule 6 — `actions/permissions/workflow/actions-can-approve-prs` — verdict: FIX-FIXTURE

Reads `can_approve_pull_request_reviews` from the same `GET /repos/{owner}/{repo}/actions/permissions/workflow` response as rule 5. `true` → medium finding; `false` → `pass-cannot-approve`. Code and docs agree exactly.

Verified directly:

| Repo | `can_approve_pull_request_reviews` | expected | correct for its role? |
|---|---|---|---|
| gasa-pass | `false` | pass | yes |
| gasa-fail | `false` | **pass** | **no — must fail** |

The rule behaves correctly against both repos; the fixture is the defect. This is the last remaining settings rule that `gasa-fail` does not fail.

Required fix: set `can_approve_pull_request_reviews: true` on `gasa-fail`. Now known safe to do independently — the repo already holds `default_workflow_permissions: write` with `can_approve: false`, proving the two fields are not coupled, and `write` + `true` is the standard insecure pairing GitHub permits.

Unit coverage for the finding path already exists (`settings_test.go:185`, `scanner_test.go:449` both assert `can_approve_pull_request_reviews: true`), so this is purely an e2e fixture gap, not a code gap.

#### Rule 7 — `actions/permissions/fork-pr-contributor-approval` — verdict: OK

Reads `approval_policy` from `GET /repos/{owner}/{repo}/actions/permissions/fork-pr-contributor-approval`. Anything other than `all_external_contributors` is a high finding; `all_external_contributors` passes. GitHub's three documented values are `first_time_contributors_new_to_github`, `first_time_contributors`, and `all_external_contributors`.

Verified directly:

| Repo | `approval_policy` | expected |
|---|---|---|
| gasa-pass | `all_external_contributors` | pass |
| gasa-fail | `first_time_contributors` | **finding** |

Both match scanner output. Fixtures correct as of the 2026-08-09 settings flip.

Fixture-safety claim confirmed empirically rather than assumed. Weakening `gasa-fail` to
`first_time_contributors` does **not** reopen the `pull_request_target` abuse surface, because the
repo object reports `pull_request_creation_policy: collaborators_only` — external contributors
cannot open a pull request at all, so there is no untrusted fork PR for the weakened approval policy
to admit. `gasa-pass` reports `pull_request_creation_policy: all` for contrast. This is the setting
referenced in the "Fixture repo safety" section above, and it is visible on `GET
/repos/{owner}/{repo}`.

Noted behavioral asymmetry, not a defect in this rule: rule 7 fails **closed** — a payload with an empty or unexpected `approval_policy` produces a finding — whereas rules 4, 5, and 6 fail **open**, emitting nothing at all. For a security scanner, rule 7's direction is the correct one. See R10.

#### Rule 8 — `updates/update-tool-configuration` — verdict: OK

Four failure branches: both tools missing (`no-tool`), invalid Dependabot YAML, invalid Renovate JSON, and a valid tool that does not cover the `github-actions` ecosystem while workflows exist. Passes if *either* tool satisfies all conditions.

Verified directly by fetching both configs and probing all nine Renovate paths:

| Repo | Dependabot config | Renovate | workflows | expected |
|---|---|---|---|---|
| gasa-pass | valid, `package-ecosystem: github-actions` (daily, cooldown 7) | none (all 9 paths 404) | yes | pass |
| gasa-fail | valid, **`package-ecosystem: docker` only** | none (all 9 paths 404) | yes | **finding** (`update-tool-missing-actions`) |

Both match scanner output.

Branch coverage note, decided as no-action: `gasa-fail` exercises only the `missing-actions` branch
of four. `no-tool`, `invalid-dependabot`, and `invalid-renovate` are unexercised at e2e level, as is
every Renovate code path on both repos. All of them are already unit-tested in `updates_test.go` —
`_NoConfig`, `_BothMissingReportsNoTool`, `_InvalidYAML`, `_MissingActionsEcosystem`,
`_IgnoresOtherEcosystems`, `_RequireWorkflows` both ways, the indeterminate/unknown handling,
`RenovateCoversActions` in three variants, and HuJSON comment stripping. Consistent with the
position taken on rules 1–3: e2e proves the integration, unit tests prove the branches.

#### Rule 9 — `updates/update-tool-actions-cooldown` — verdict: FIX-FIXTURE, blocked by a structural conflict

Passes when Dependabot's `github-actions` entry has a `cooldown` block, or Renovate sets `minimumReleaseAge` at the top level or in any `packageRules` entry. Emits a low finding only when a valid tool **covers `github-actions`** and no cooldown is set.

Verified directly:

| Repo | Dependabot | cooldown | covers actions | result |
|---|---|---|---|---|
| gasa-pass | valid, `github-actions` | `default-days: 7` | yes | pass — correct |
| gasa-fail | valid, `docker` only | none | **no** | **silent** |

Root cause of the silence, proven by code path and confirmed with `--debug`:
`evaluateUpdateToolActionsCooldownFacts` returns nil at `updates.go:413` because neither tool covers
`github-actions`, and `updateToolActionsCooldownSuccessFinding` returns nil at `rules.go:421`
because no cooldown is configured. Debug output reports `rule:pass
updates/update-tool-actions-cooldown (no findings)` while nothing at all reaches the report — the
rule is internally treated as passing but declines to say so.

**Structural conflict: rules 8 and 9 cannot both fail in the same repository.** This is a design constraint, not a fixture mistake, and it was not visible before this audit:

- rule 8's `missing-actions` branch fires only when **no** valid tool covers `github-actions`
- rule 9 fires only when a valid tool **does** cover `github-actions` but sets no cooldown

The conditions are exact complements. Rule 8's other three branches (`no-tool`,
`invalid-dependabot`, `invalid-renovate`) conflict too, since rule 9 requires at least one *valid*
config. Combining tools does not escape it either: adding a Renovate config to `gasa-fail` that
covers actions makes rule 8 pass (coverage by *either* tool satisfies it), and one that does not
cover actions leaves rule 9 silent exactly as now.

This breaks the coverage-matrix invariant as currently written ("every rule has a `success: false` entry in `gasa-fail.golden.json`"). Rule 10 is expected to hit the same wall — see the rule 10 entry. Options are captured in R18.

#### Rule 10 — `updates/update-tool-actions-pinning` — verdict: FIX-CODE (confirmed false positive) + FIX-FIXTURE

Renovate-only by design. Dependabot has no SHA-pinning option, so the rule short-circuits when Renovate is absent. Pinning is detected via top-level `pinDigests: true`, a literal `helpers:pinGitHubActionDigests` / `helpers:pinGitHubActionDigestsToSemver` entry in `extends`, or `pinDigests: true` in any `packageRules` entry.

Verified directly:

| Repo | Renovate config | result |
|---|---|---|
| gasa-pass | none (all 9 paths 404) | silent |
| gasa-fail | none (all 9 paths 404) | silent |

**The silence here is documented, intended behavior**, unlike rule 9's. `docs/rules/update-tool-actions-pinning.md` states it explicitly: "This rule is intentionally silent when only Dependabot is configured — neither pass nor fail is emitted." Both fixtures are Dependabot-only, so both are correctly silent. The rule is not broken in the way rule 9 appeared to be.

Consequence for the fixture set: **rule 10 currently has no pass case and no fail case anywhere.**
The fail case comes from `gasa-fail-private`'s bad Renovate config under R18. The pass case requires
a Renovate config *with* pinning on a pass fixture — which makes the "good Renovate config on
`gasa-pass`" item a **hard requirement, not a consideration**. Without it, rule 10 cannot satisfy
the coverage matrix.

Correction to R18 as originally written: adding Renovate to `gasa-pass` does **not** cost the all-nine-paths-404 fixture. `gasa-fail` is Dependabot-only and stays that way, so it continues to exercise the all-404 path. The trade-off flagged in R18 does not exist.

#### Accumulated recommendations (action after all 10 rules reviewed)

- ~~**R1**~~ **Done** (PR #38), FIX-CODE, affects rules 1/2/3: unparsable workflow YAML is silently
  reported as clean. `WorkflowFact.Valid` is only set when `yaml.Unmarshal` succeeds
  (`workflow.go:157`). The dangerous-trigger rule `continue`s past invalid files and the parse error
  surfaces only under `--debug`. A repo whose workflows all fail to parse reports "pull_request_target
  event is not used" — a clean bill of health for files nobody actually checked.
  `ScanResult.Incomplete[]` already exists for precisely this situation and is already wired into
  output; unparsable workflows should be added to it. Practical risk is low because GitHub will not
  run a workflow it cannot parse either; the real hazard is a divergence between GitHub's parser and
  `gopkg.in/yaml.v3`, which is an **untested hypothesis** with no evidence behind it yet. Scope
  confirmed after reviewing rules 1–3: all three share the identical `if !wf.Valid { continue }`
  guard, so one fix in the collection layer covers every workflow rule
- **R2 — fixture stability, not a rule bug: `daily-repo-status.lock.yml` in `gasa-pass`.** A 101 KB
  machine-generated gh-aw file that upstream tooling rewrites, living in a repo whose entire purpose
  is byte-stability. It will generate recurring `fixtures-verify` drift alarms. Options: leave it and
  let `fixtures-apply` revert the churn (self-healing, some noise), or move the gh-aw workflow out of
  `gasa-pass`. Undecided
- ~~**R3**~~ **Done** (PR #39), FIX-CODE, rule 2: finding IDs can collide and silently drop a real
  finding. The ID is `unpinned-<path>-<sanitized action name>` (`rules.go:541`) and includes neither
  the ref nor the line. `dedupeFindings` keys purely on ID (`scanner.go:308`), so two unpinned uses of
  the *same* action in the *same* file collapse into one finding — e.g. `actions/checkout@v4` in one
  job and `actions/checkout@v3` in another. Proven by code inspection; not yet reproduced at runtime,
  and `gasa-fail` does not trigger it because its two `actions/checkout` refs live in different files
  (different paths → different IDs). Fix by including the line number or the ref in the ID. Note this
  changes golden-file entries, so it should land before goldens are generated, not after
- ~~**R4**~~ **Done** (PR #41), FIX-DOCS, rule 2: the rule doc describes only the regex path.
  `docs/rules/action-version-pinning.md` presents the line regex as *the* mechanism, but that path
  only runs when a workflow fails to parse; the primary path is a structural walk over parsed jobs and
  steps. The doc also says "not a 40-character hex SHA" while `isSHA` accepts 40 or 64 (SHA-256
  forward-compatibility). Update the doc to describe both paths and both SHA lengths
- **R6 — moved to Phase 13.** Product gap, rule 3: `permissions: write-all` passes this rule. The
  check is presence-only, which the doc states plainly, but the rule is severity **high** and named
  "Workflow Permissions", so a passing result reads to an operator as "this repo's workflow
  permissions are safe". A workflow with top-level `permissions: write-all` — the single broadest
  possible grant, and the exact thing the GitHub Actions hardening guidance warns against — produces a
  clean pass. `gasa-pass` already demonstrates the milder version of this: `pr-target-replace-2.yaml`
  passes with `pull-requests: write`. Options: (a) leave as documented; (b) extend this rule to also
  flag `write-all` and other blanket grants; (c) add a separate rule for over-broad explicit
  permissions. Option (b) or (c) sits squarely inside the Phase 10 guardrail of "tightly aligned with
  Actions security", and detecting `write-all` is cheap and unambiguous. Undecided — needs a severity
  and false-positive boundary before implementing
- ~~**R7**~~ **Done** (PR #40), FIX-CODE, rule 3: a valid-YAML non-workflow file in
  `.github/workflows` yields a high-severity false positive. `hasExplicitPermissions` returns false
  when a file has no `permissions` and zero jobs, so a stray `config.yml` parked in the workflows
  directory is reported as "No explicit permissions defined" at high severity. The behavior is
  deliberately asserted today (`none := &WorkflowFile{}` in `workflow_test.go`). GitHub would also
  reject such a file as an invalid workflow, so flagging it is not wrong — but the message
  misdiagnoses the problem. Consider a distinct "not a valid workflow" finding instead. Interacts with
  R1: both concern how the scanner reports files it could not meaningfully evaluate
- **R8 — moved to Phase 13.** New rule candidate: `sha_pinning_required` is a real repo setting the
  scanner ignores. `GET /repos/{owner}/{repo}/actions/permissions` — the response rule 4 already
  fetches — carries `sha_pinning_required`, GitHub's repo-level enforcement of "require actions to be
  pinned to a full-length commit SHA". Both fixture repos currently report `false`. This complements
  rule 2 exactly: rule 2 proves the workflow files are pinned *today*, while this setting is what
  stops an unpinned ref from ever landing *tomorrow*. Costs zero additional API calls since the field
  is already in a response the scanner parses. Strongly aligned with the Phase 10 guardrail. Fixture
  consequence: `gasa-pass` has it `false`, so adopting this rule requires flipping that setting on
  before `gasa-pass` can pass a full sweep
- ~~**R9**~~ **Done** (PR #37), FIX-CODE, affects all four settings rules (4, 5, 6, 7): a transient
  settings fetch error is reported as "GitHub Actions are disabled". When `GET /actions/permissions`
  fails for a non-auth reason (5xx, timeout), `settings.go` takes the `default:` branch — it records
  an incomplete-scan warning but leaves `AccessFinding` nil and `facts.Permissions` nil. Every
  settings rule then finds no findings, and every settings success helper begins with `if
  !actionsSettingsEnabled(facts)` (`rules.go:328/345/356/367`), which is true when `Permissions` is
  nil. The result is four success findings asserting "GitHub Actions are disabled for this repository"
  — a fact the scanner never observed and which may be flatly false. The `Incomplete[]` warning does
  fire alongside it, so the scan is at least marked partial, but the findings themselves state
  something untrue. Proven by code inspection, not yet reproduced at runtime. Fix by distinguishing
  "observed disabled" from "never observed" in the fact model rather than inferring one from a nil
  pointer
- ~~**R10**~~ **Done** (PR #35), FIX-CODE, systemic across the settings rules: a missing field makes a
  rule emit absolutely nothing — and for rules 5 and 6 this is proven, not hypothetical. Every
  settings rule pairs an early return on a nil field with a success helper that also returns nil for
  the same case, so the rule produces neither a finding nor a success. Confirmed instances: rule 4
  when `allowed_actions` is absent (`rules.go:603` + `rules.go:331`); rules 5 and 6 when
  `DefaultWorkflowPermissions` is nil (`rules.go:626`/`rules.go:649` + `rules.go:349`/`rules.go:360`).

  For rules 5 and 6 the trigger is documented *and* already unit-tested:
  `TestFetchAuthenticatedSettings_DeniedSkipsQuietly` asserts that a **403 on `GET
  /actions/permissions/workflow` leaves the value unset with no warning and no access finding**,
  because the top-level `/actions/permissions` call succeeded and therefore no `AccessFinding` was
  recorded. The rule docs describe this as "silently skips this sub-check".

  This is a direct risk to the Phase 12 CI plan, not an abstract one. If the read-only fine-grained
  PAT can read `/actions/permissions` but is refused on `/actions/permissions/workflow`, rules 5 and 6
  will vanish from the CI run with no error, no warning, and no incomplete marker — while passing
  locally under the admin PAT. A scan that silently drops two high/medium settings rules is exactly
  the failure this phase exists to catch. Two consequences: (a) the token verification task is now a
  hard prerequisite, not a nicety; (b) the fix is to emit an explicit "could not determine" finding,
  or record an `Incomplete[]` entry, whenever a settings sub-call is refused. For rule 4, the case
  where GitHub omits `allowed_actions` while `enabled: true` remains an **untested hypothesis**
  (likely an org/enterprise policy), not reproducible on these personal repos
- ~~**R11**~~ **Done** (PR #41), FIX-DOCS, rule 4: the doc contradicted the code on disabled Actions. `docs/rules/allowed-actions-policy.md` says "if Actions is disabled (`enabled == false`), the rule returns no finding". The code returns a success finding (`pass-disabled`, "GitHub Actions are disabled for this repository")
- ~~**R12 — FIX-FIXTURE, rule 5: flip `gasa-fail` to `default_workflow_permissions: write`.**~~ **Done
  2026-08-09** (applied manually in the GitHub UI, verified by `gh api`). Rule 5 now fails on
  `gasa-fail`. The paired hygiene item still stands: make the fixture workflow `run:` steps inert
  (`run: echo fixture`), since `gasa-fail`'s workflows genuinely execute and now receive a read-write
  `GITHUB_TOKEN`. Rules 2 and 3 read `uses:` and `permissions:`, never `run:`, so that edit changes no
  rule outcome
- ~~**R13 — can `can_approve_pull_request_reviews: true` coexist with `default_workflow_permissions:
  read`?**~~ **Resolved 2026-08-09, no longer a blocker.** `gasa-fail` now holds `write` +
  `can_approve: false`, proving the two fields are independently settable. `write` + `true` is the
  standard insecure pairing GitHub permits, so rules 5 and 6 can fail independently and no fixture
  redesign is needed. The narrow original question (`read` + `true`) is moot for this fixture and was
  never required
- **R18 — DESIGN DECISION, resolved 2026-08-09: add a third fixture repo,
  `bretfisher/gasa-fail-private`.** Rules 8 and 9 have exactly complementary trigger conditions (see
  the rule 9 entry), so no single repository can fail both, and the coverage-matrix test as originally
  specified — "every rule has a `success: false` entry in `gasa-fail.golden.json`" — is unsatisfiable.
  Rejected alternatives: exempting rules 9 and 10 from the matrix and leaning on unit tests (silently
  drops two rules from the very net this phase exists to build), and rotating `gasa-fail`'s config
  between runs (non-deterministic fixtures defeat golden files).

  Decided design:

  - create **`bretfisher/gasa-fail-private`**, a **private** repo whose update-tool configs are
    deliberately bad. Shape revised by R22 — it must carry **Dependabot with a non-actions ecosystem
    only** (e.g. `docker`, no cooldown) **plus Renovate `{"extends": ["config:recommended"]}`**.
    Renovate then covers `github-actions` by auto-detection with neither `minimumReleaseAge` nor
    pinning, so rules 9 and 10 both fail while rule 8 passes on Renovate's coverage. It must **not**
    have a Dependabot `github-actions` entry: under R22 that would make rule 10 pass and destroy the
    fail case this repo exists to provide
  - relax the matrix invariant to: **every rule has a fail case in at least one fail fixture, and a pass case in `gasa-pass`**
  - private is deliberate, not incidental — private repos expose a different Actions settings surface, which makes this repo a ready-made fixture if settings rules specific to private repos are added later

  Two consequences that must be handled, neither optional:

  1. **The CI token must be re-scoped.** `E2E_REPO_PAT` is currently limited to `gasa-pass` and `gasa-fail`. It needs `gasa-fail-private` added, and on a private repo `Contents: Read` genuinely matters rather than being a formality. Without this the e2e job fails with a 404 that reads like a missing repo, not a permissions problem
  2. **Private-repo Actions settings behave differently, and how differently is an untested hypothesis.**
     `fork-pr-contributor-approval` is meaningless where forks cannot happen and the endpoint may 404 or
     return a different shape; `allowed_actions: selected` has historically been gated by plan tier for
     private repos. Probe all four settings endpoints on the new repo with `gh api` *before* writing its
     `repo.yaml` manifest, and expect rules 4–7 to need explicit "not applicable here" handling rather
     than the values used for `gasa-fail`

  **Valuable but no longer required (downgraded again by R22): add a good Renovate config to
  `gasa-pass`.** After R22, `gasa-pass` passes rule 10 through its existing Dependabot
  `github-actions` entry, so a Renovate config is not needed to satisfy the coverage matrix. It
  remains the only way to exercise Renovate code paths end to end — config-path probing, JSON/JSON5
  parsing, HuJSON comment stripping, `enabledManagers` detection, `minimumReleaseAge`, and
  pinning-preset resolution — all of which currently rest entirely on mocks. Adding `{"extends":
  ["config:best-practices"]}` would additionally serve as the live regression test for R20's
  transitive preset resolution, since that config must resolve to "pinning enabled". The earlier
  concern that this costs the all-nine-paths-404 fixture was wrong — `gasa-fail` stays Dependabot-only
  and continues to exercise that path
- ~~**R20**~~ **Done** (PR #34), FIX-CODE, confirmed false positive, highest-value finding of this
  audit: rule 10 does not resolve Renovate preset inheritance. `renovatePinningConfigured`
  (`updates.go:490`) matches only the literal strings `helpers:pinGitHubActionDigests` and
  `helpers:pinGitHubActionDigestsToSemver` in `extends`. It does not expand presets transitively.
  Verified against Renovate's own documentation: **`config:best-practices` extends
  `helpers:pinGitHubActionDigests`**, alongside `config:recommended`, `docker:pinDigests`,
  `:configMigration`, `:pinDevDependencies`, `abandonments:recommended`,
  `security:minimumReleaseAgeNpm`, and `:maintainLockFilesWeekly`.

  So a repository using `{"extends": ["config:best-practices"]}` — Renovate's own recommended starting
  configuration and one of the most common real-world configs — **is genuinely pinning GitHub Action
  digests, and gasa reports a medium `update-tool-actions-not-pinning` finding against it.** Worse,
  `docs/rules/update-tool-actions-pinning.md` uses that exact config as its **"Bad example"**, so the
  documentation actively teaches the wrong thing.

  Rule 9 escapes the same trap only by luck: `config:best-practices` includes
  `security:minimumReleaseAgeNpm`, which scopes `minimumReleaseAge` to npm and therefore genuinely
  leaves `github-actions` without a cooldown. Rule 9's bad example is correct by coincidence, not by
  design — `renovateCooldownConfigured` has the identical no-preset-resolution limitation and will
  misreport any config that inherits a cooldown transitively.

  Fix options: resolve the small set of known built-in presets that imply pinning (cheap, covers the common cases, needs maintenance as Renovate evolves); or stop asserting a negative and downgrade the finding to informational when `extends` contains any preset the scanner cannot resolve. Also fix the doc's bad example either way

- **R21 — FIX-FIXTURE, depends on R20: `gasa-fail-private`'s Renovate config must not be
  `config:best-practices`.** The obvious "bad Renovate" config is `{"extends":
  ["config:best-practices"]}`, and it *would* produce the rule 10 failure the fixture needs — but only
  because of the R20 false positive. Encoding that in a golden file would bake a confirmed bug in as
  expected behavior, which is precisely the failure mode this audit exists to prevent. Use
  `{"extends": ["config:recommended"]}` instead: `config:recommended` is the base preset that
  `config:best-practices` builds on and does **not** include `helpers:pinGitHubActionDigests`, so it
  is a genuine not-pinning config. It also carries no `minimumReleaseAge`, so it fails rule 9 at the
  same time — exactly the pairing `gasa-fail-private` exists to provide

- ~~**R22**~~ **Done** (PR #34), RULE CHANGE: extend rule 10 (`update-tool-actions-pinning`) to
  recognise Dependabot. Today the rule is Renovate-only and stays silent for Dependabot-only repos.
  The intent of the check is narrower than its current implementation suggests: *if either updater is
  configured for `github-actions`, will it keep SHA pins current?* That is a different question from
  `update-tool-configuration`, which only asks whether an updater covers actions at all and does not
  care about pinning.

  New evaluation logic:

  - if neither tool covers `github-actions` → not applicable, stay silent (rule 8 already reports the absence)
  - **pass** if Dependabot has a `github-actions` entry — Dependabot preserves whatever pin style already exists, so it will keep SHAs current on an already-pinned repo
  - **pass** if Renovate has pinning configured — `pinDigests: true`, a pinning helper preset, a `packageRules` entry, **or** a preset that transitively implies pinning such as `config:best-practices`
  - **fail** when a tool covers `github-actions` but neither of the above holds

  This depends on R20. The "or `config:best-practices`" clause is exactly the transitive preset resolution R20 identifies as missing, so R20 is now a prerequisite for R22 rather than an independent fix.

  Accepted trade-off, stated by the requester: the rule gets more complex and partly redundant with `update-tool-configuration`. That is fine — the two rules answer different questions.

  **Sub-decision resolved 2026-08-09: Option A, no caveat wording.** A Dependabot `github-actions`
  entry passes on its own. Rules stand alone and must not depend on another rule's outcome —
  `action-version-pinning` (severity high) independently covers the case where the workflows were
  never pinned to begin with. The alternative (pass only when rule 2 is clean) was rejected because
  cross-rule dependencies are a rule-engine structural change Phase 7 has not designed for. No hedging
  language added to the finding text for now.

  **Fixture consequences — these cut against the `gasa-fail-private` design as sketched in R18 and must be resolved together:**

  - `gasa-pass` will now pass rule 10 through its existing Dependabot `github-actions` entry. The good Renovate config therefore drops back from *required* to *valuable* — it is no longer needed for rule 10's pass case, but it remains the only way to exercise Renovate code paths end to end
  - `gasa-fail-private` **must not carry a Dependabot `github-actions` entry.** Under R22 such an entry would make rule 10 pass, destroying the fail case that repo exists to provide. Rules 9 and 10 become partially conflicting on the Dependabot path for the same reason rules 8 and 9 conflict
  - Revised `gasa-fail-private` shape that fails both rule 9 and rule 10: **Dependabot with a
    non-actions ecosystem only** (e.g. `docker`, no cooldown) **plus Renovate `{"extends":
    ["config:recommended"]}`**. Renovate then covers `github-actions` by auto-detection with neither
    `minimumReleaseAge` nor pinning, so rule 9 fails and rule 10 fails, while rule 8 passes because
    Renovate provides coverage. This also exercises the both-tools-present path, which no other fixture
    does

- ~~**R19**~~ **Done** (PR #35), FIX-CODE: a rule that emitted nothing still logged `rule:pass`. With
  `--debug`, rule 9 on `gasa-fail` prints `rule:pass updates/update-tool-actions-cooldown (no
  findings)` while emitting neither a finding nor a success record. An operator reading debug output
  concludes the rule evaluated and passed; the report shows the rule never happened. Whatever fix
  lands for R10's silent-emission problem should also make the debug line distinguish "passed and said
  so" from "produced nothing"
- ~~**R17**~~ **Done 2026-08-12** — efficiency, rule 8 and batch mode: nine 404 probes per scan just to look for Renovate. A
  full scan of `gasa-pass` issues 19 GitHub API calls, and **9 of them** are contents requests for
  Renovate config paths that do not exist (`renovate.json`, `renovate.json5`,
  `.github/renovate.json*`, `.gitlab/renovate.json*`, `.renovaterc*`). The scanner short-circuits at
  the first hit, so a repo *without* Renovate — the common case — always pays the full nine. At
  roughly 19 calls per repo, an authenticated 5,000/hour budget caps a batch run near 260 repos/hour,
  and nearly half of that budget is spent proving a file is absent. Cheaper approach: list
  `/contents/`, `/contents/.github`, and `/contents/.gitlab` (3 calls, and `.github` is arguably
  already needed) and fetch only the config that actually appears. Not a correctness issue, and not
  urgent for two fixture repos, but it matters for the org-scanning direction in Phase 10 and connects
  to the rate-limit work already listed in Phase 5
- **R16 — moved to Phase 13.** New rule candidate: `pull_request_creation_policy`. Discovered on `GET
  /repos/{owner}/{repo}` while verifying rule 7's fixture safety. `gasa-fail` reports
  `collaborators_only`, `gasa-pass` reports `all`. This is the repo-level control that determines
  whether external contributors can open pull requests at all, which makes it the single setting that
  most directly neutralizes `pull_request_target` risk on a public repo. Two possible uses: a
  standalone rule, or context that modulates rule 1's severity (a public repo running
  `pull_request_target` with `collaborators_only` is materially safer than one with `all`). The
  severity-modulation option is the more interesting one but also the more complex, since it couples
  two rules. Costs no extra API call — the repository object is already fetched. Undecided; evaluate
  alongside R8 as a pair of "settings gasa already receives but ignores"
- **R15 — FIX-FIXTURE, rule 6: set `can_approve_pull_request_reviews: true` on `gasa-fail`.** The last settings rule the fail fixture does not fail. Safe to set independently — see the rule 6 entry
- **R14 — fixture drift is already live, not theoretical.** `gasa-pass` currently has 5 open
  Dependabot PRs proposing action version bumps (`actions/checkout` 4.3.1→7.0.0, `codecov-action`
  4.6.0→7.0.0, and three more). Merging any of them rewrites the pinned SHAs. Rule 2's *outcome* is
  unaffected — the refs stay SHA-pinned either way — but it confirms R2's concern is real and ongoing.
  `gasa-fail` additionally runs a weekly Dependabot `docker` update that fails every time, because its
  `dependabot.yml` declares a `docker` ecosystem with no Dockerfile in the repo. Decide whether
  fixture repos should have Dependabot updates suppressed (`open-pull-requests-limit: 0`) or left to
  churn with `fixtures-apply` reverting
- ~~**R5**~~ **Done** (PR #41), FIX-DOCS: the "Check ID" table row was stale on seven pages; replaced
  with rule name and aliases. Rule pages advertise values like `action_pinning` and
  `pull_request_target`, but no emitted finding uses those strings — real IDs are of the form
  `unpinned-<path>-<action>` and `dangerous-trigger-<path>`. Either correct the row to the real ID
  pattern or drop it. Confirm against the remaining rule pages before deciding, since the fix should
  be uniform

### Audit outcome and action order

All 10 rules were reviewed against docs, code, and the live state of both fixture repos read directly with `gh api`. Summary of verdicts:

| Rule | Verdict | Note |
|---|---|---|
| 1 pull-request-target | OK | fixtures correct |
| 2 action-version-pinning | OK | fixtures correct; ID collision bug found (R3) |
| 3 workflow-permissions | OK | fixtures correct; `write-all` passes by design (R6) |
| 4 allowed-actions-policy | OK | fixtures correct |
| 5 default-workflow-permissions | FIXED | `gasa-fail` flipped to `write` 2026-08-09 |
| 6 actions-can-approve-prs | FIX-FIXTURE | R15 outstanding |
| 7 fork-pr-contributor-approval | FIXED | `gasa-fail` flipped 2026-08-09 |
| 8 update-tool-configuration | OK | fixtures correct |
| 9 update-tool-actions-cooldown | FIX-FIXTURE | blocked by rule 8/9 conflict → R18 |
| 10 update-tool-actions-pinning | FIX-CODE + RULE CHANGE | confirmed false positive (R20); rule extended (R22) |

The single most important outcome is not a fixture gap but a confirmed user-facing bug: **R20**, a false positive against `config:best-practices`, Renovate's own recommended configuration.

**Sequencing constraint that governs everything below: every code fix must land before golden files
are generated.** R3 changes finding IDs; R20 and R22 change rule 10's outcomes; R1, R9, and R10 add
findings or `Incomplete[]` entries that do not exist today. Generating goldens first would bake
current behavior in as expected and force a full regeneration. Freeze the code, then the fixtures,
then generate goldens.

**Phase A — code correctness. Complete, in stack #36 (PRs #34–#41), awaiting review and merge.** These affect anyone running the tool today, independent of the e2e work. Phase B landed with them as PR #41.

The stack merges bottom-up in this order:

| PR | Branch | Fixes |
|---|---|---|
| #34 | `fix/renovate-preset-and-dependabot-pinning` | R20, R22 |
| #35 | `fix/settings-undetermined-checks` | R10, R19 |
| #37 | `fix/settings-transient-error-not-disabled` | R9 |
| #38 | `fix/unparsable-workflows-incomplete` | R1 |
| #39 | `fix/action-pinning-finding-id-collision` | R3 |
| #40 | `fix/non-workflow-file-message` | R7 |
| #41 | `docs/rule-page-corrections` | R4, R5, R11 |

Phase C cannot begin until this stack is merged: PRs #34 and #39 change rule outcomes and finding IDs, and #35, #37, #38, and #40 add findings and incomplete entries that do not exist today. Generating goldens before they land would bake current behavior in as expected.

1. **R20 + R22 together** — transitive Renovate preset resolution, and the rule 10 extension that depends on it. Highest user impact; R22 cannot be correct without R20
2. **R10 + R19** — settings rules emitting nothing when a field is absent or a sub-call is refused, and the `rule:pass` debug line that misreports it. Security-critical: a refused sub-call silently removes a high and a medium rule from the scan
3. **R9** — a transient settings fetch error currently reports "GitHub Actions are disabled for this repository" as a success across four rules
4. **R1** — unparsable workflow YAML silently reported as clean across rules 1, 2, and 3
5. **R3** — finding ID collision drops a real finding when the same action is unpinned twice in one file
6. **R7** — misleading high-severity message for a valid-YAML non-workflow file (low priority)

**Phase B — documentation sync.** Cheap, and R20's is actively misleading.

7. R20's "Bad example" in `update-tool-actions-pinning.md` (teaches a config that is actually correct), R4 (rule 2 describes only the fallback path), R11 (rule 4 contradicts the code), R5 (stale "Check ID" row, sweep all 10 pages)

**Phase C — fixtures. In progress.**

8. ~~**R15** — set `can_approve_pull_request_reviews: true` on `gasa-fail`~~ **Done 2026-08-11.** `gasa-fail` now fails 8 of 10 rules, which is every rule it structurally can; only rules 9 and 10 remain, and those are what `gasa-fail-private` exists for
9. ~~**R18 + R21** — create `gasa-fail-private`~~ **Done 2026-08-11.** Private repo created with
   Dependabot scoped to `docker` only (plus a real `Dockerfile` so that ecosystem is valid), Renovate
   `{"extends": ["config:recommended"]}`, one deliberately correct SHA-pinned workflow, and hardened
   Actions settings. Verified live: 10 of 10 rules report, and exactly rules 9 and 10 fail. Two code
   defects were found in the process — see P1 and P2 below. **Still outstanding: re-scope
   `E2E_REPO_PAT` to include this repository** (see below)
10. ~~Optional: good Renovate config on `gasa-pass`~~ **Done 2026-08-12.** `renovate.json` extending
    `config:best-practices` added to the fixture. This exercises the Renovate fetch/parse path and
    rule 8's both-tools branch end to end. One honest caveat discovered while landing it: it is
    **not** a live R20 regression test for the must-pass direction, because `actionsPinningState`
    short-circuits on gasa-pass's Dependabot `github-actions` entry before preset resolution runs.
    The preset table's must-NOT-pass direction (`config:recommended`) is what `gasa-fail-private`
    covers live; the must-pass direction rests on unit tests
11. ~~Hygiene: make fixture workflow `run:` steps inert~~ **Done 2026-08-12.** Both `gasa-fail`
    workflows now only echo, and the github-script step logs instead of posting a PR comment — which
    it genuinely would have done, since the repository's default token permission is deliberately
    `write`. Every rule-relevant byte (triggers, `uses:` refs, absence of `permissions:`) is
    unchanged, so finding IDs and goldens are untouched

Decided 2026-08-11: **Dependabot is not suppressed on the fixture repositories.** Churn is accepted and `fixtures-apply` reverts it, which needs no extra setup and self-heals. This closes R2 and R14.

**Blocking Phase D — `E2E_REPO_PAT` must be re-scoped.** The token currently grants access to
`gasa-pass` and `gasa-fail` only. Add `gasa-fail-private`, keeping `Contents: Read` and
`Administration: Read`. On a private repository `Contents: Read` is load-bearing rather than a
formality. Without it the e2e job fails with a 404 that reads like a missing repository rather than
a permissions problem. This is a manual step in the GitHub UI; fine-grained PAT scopes are not
editable through the API.

#### Defects found while building the private fixture

Both were discovered only by pointing the scanner at a real private repository, which is precisely the class of bug mocked tests cannot reach.

- **P1 — FIX-CODE: fork-PR approval reported as unverified on every private repository.** `GET
  /actions/permissions/fork-pr-contributor-approval` answers **422** on private repos with "Fork PR
  approval is not allowed for private repositories". 422 is neither an access denial nor a transient
  failure, so it fell to the catch-all branch and produced both an undetermined finding and an
  incomplete-scan warning — flagging a control that cannot be misconfigured because it does not exist
  there. Now recognised as a distinct not-applicable state that passes with its own message and raises
  no warning
- **P2 — FIX-CODE: `applyRuleConfig` discarded every finding's own severity.** It stamped the rule's
  severity onto all findings unconditionally, so the deliberate `info` on the access and "could not
  determine" findings was overwritten with the rule's — a gap in coverage rendered as a high-severity
  vulnerability, inflating the counts operators triage on. Now only an explicit user override replaces
  a finding's chosen severity; a finding that sets none still inherits the rule default. This bug
  predates the audit and affected the existing `settings-check-failed` and
  `settings-check-unavailable` findings too

**Phase D — harness. Complete 2026-08-11**, in three pull requests: fixture tooling, the test suite, and
the workflow.

- `tools/fixtures` declares each fixture repository's content and Actions settings under
  `testdata/e2e/fixtures/`, with `verify` (read-only, the only mode CI runs), `apply` (additive, never
  deletes) and `capture` modes, wired to `make fixtures-verify` / `fixtures-apply` / `fixtures-capture`
- `test/e2e` scans all three repositories behind an `e2e` build tag, asserting the scanner API against
  golden files and separately driving the real binary for the CLI wiring the API path skips
- `TestEveryRuleHasPassAndFailCoverage` enforces that every registered rule passes in `gasa-pass` and
  fails in at least one fail fixture, so adding a rule without fixtures becomes a build failure
- `.github/workflows/e2e.yml` runs on pushes to `main` (path-filtered), a daily schedule, and manual
  dispatch — never on `pull_request`, since the job holds a cross-repository PAT and a PR runs
  attacker-controlled code. Linted clean with actionlint, zizmor and poutine

Two further defects were found while building it, both fixed in the same pull requests:

- **P3 — the cooldown and pinning rules went silent when no update tool covered `github-actions`.**
  Neither a finding nor a success, so the check vanished from the report — indistinguishable from a
  clean pass. True of `gasa-fail` for both rules. They now report not-applicable explicitly, matching
  the treatment private-repo fork-PR approval received in P1. All three fixtures now report all ten
  rules
- **P4 — the first version of the e2e suite passed while comparing empty results against empty
  goldens.** The rule registry is built from `docs/rules` front matter and populated by the binary at
  startup, so a package importing the scanner directly registers no rules and every scan returns
  nothing. `TestMain` now refuses to run on an empty registry, and a scan reporting fewer findings
  than there are registered rules is a hard failure

**Phase E.** ~~R17 (nine Renovate 404 probes per scan)~~ **Done 2026-08-12** — a file-inventory
collector lists the root and dot-directories (one or two requests) and the update-tool collectors
skip paths the listings proved absent, dropping the common no-Renovate case from eleven requests to
two or three. Any listing failure or truncation falls back to per-path probing, so it can only cost
speed, never correctness. The three new-rule candidates (R6, R8, R16) moved to Phase 13.

### Open decisions

- ~~should the e2e job assert the scanner API or the CLI binary?~~ **Resolved 2026-08-11: both.** The
  scanner API carries the 10-rule coverage matrix because its failures point straight at scanner
  behavior, and a smaller set of assertions drives the real `gasa` binary to cover the CLI wiring the
  API path skips — flag parsing, `--no-config`, token resolution, output format, and exit code
- ~~whether to suppress Dependabot on the fixture repos~~ **Resolved 2026-08-11: not suppressed.**
  Churn is accepted and `fixtures-apply` reverts it, which needs no extra setup and self-heals
- R6, R8, R16 have moved to Phase 13 and are decided there, not here

Result needed:

- every shipped rule is proven to fire and to pass against real GitHub repositories on every push to `main` and every day
- the fixture repos are reproducible from this repo rather than hand-maintained
- CI holds the narrowest credential that can do the job, in an environment secret, on triggers that never expose it to untrusted code

## Phase 13: New Rule Candidates From The Fixture Audit

Status: Not started

Goal:

- decide and implement the new rules surfaced by the Phase 12 per-rule audit

Why these are grouped and deferred:

- none of them blocks the e2e harness, and each one changes what `gasa-pass` and `gasa-fail` are expected to report. Adding rules mid-audit would have invalidated the fixture work in progress
- all three read data the scanner **already fetches**, so none costs an additional API call
- each needs a severity and a false-positive boundary agreed before implementation, per the Phase 7 contribution expectations (stable ID, metadata, docs, tests, examples, remediation)

Candidates, in rough order of value:

1. **Over-broad explicit workflow permissions (from R6).** `workflows/workflow-permissions` is
   presence-only by design, so `permissions: write-all` — the broadest possible grant — produces a
   clean pass at severity high. Either extend that rule to flag blanket grants, or add a separate rule.
   Needs a decision on which scopes count as over-broad beyond `write-all`, since `contents: write` is
   legitimate in plenty of workflows. `gasa-pass` already contains a milder instance:
   `pr-target-replace-2.yaml` passes with `pull-requests: write`

2. **`sha_pinning_required` repository setting (from R8).** Present in the `GET
   /repos/{owner}/{repo}/actions/permissions` response that `allowed-actions-policy` already parses. It
   is GitHub's enforcement of "require actions pinned to a full-length commit SHA". Complements
   `action-version-pinning` precisely: that rule proves the files are pinned today, this setting
   prevents an unpinned ref landing tomorrow. Fixture consequence: both repos currently report `false`,
   so `gasa-pass` needs the setting enabled before it could pass

3. **`pull_request_creation_policy` (from R16).** Present on the repository object the scanner already
   fetches. `gasa-fail` reports `collaborators_only`, `gasa-pass` reports `all`. It is the control that
   determines whether external contributors can open pull requests at all, making it the single setting
   that most directly neutralizes `pull_request_target` risk on a public repo. Two designs: a
   standalone rule, or context that modulates the `pull-request-target` rule's severity. The second is
   more useful but couples two rules, which the rule engine does not currently support and Phase 7 has
   not designed for

Implementation requirements for any of these:

- stable rule ID, front-matter metadata, a `docs/rules/` page, unit tests, and pass/fail fixture coverage in the Phase 12 repos
- update the coverage matrix and regenerate goldens, since a new rule adds an expected entry to every fixture
- respect the Phase 10 guardrail: only rules tightly aligned with GitHub Actions security and repository hygiene

## Immediate Next Tasks

Recommended next implementation order:

1. design and implement the rule engine and configurable policy architecture milestone
2. refactor scanner execution around shared data collection and normalized facts
3. add `.gasa.yml` support for rule selection, overrides, and suppressions
4. add coverage reporting and wire it into CI
5. add GitHub Actions workflows for CI build/test
6. add Docker build and GHCR publishing workflow
7. add release workflow for tagged releases and release artifacts
8. improve CLI auth troubleshooting and degraded-scan messaging
9. document install paths, supported platforms, release expectations, and config usage
10. build the Phase 12 cross-repo e2e harness against `gasa-pass` / `gasa-fail`

## Recently Completed Highlights

Recent high-value work already landed:

- migrated CLI framework from stdlib `flag` to Cobra
- restructured CLI into `gasa run` and `gasa rules` subcommands
- migrated terminal output to lipgloss v2 with severity-colored tables
- added `--category` flag for category-based rule filtering
- removed scoring from code and docs (severity-only model)
- added terminal width auto-detection for table formatting
- remediation `fix_url` support in human and JSON output
- documented token permission requirements
- added broad scanner and CLI test coverage

## Maintenance Notes

When this file is updated:

- move completed work into the relevant phase history
- keep remaining work specific and actionable
- prefer updating phase status over creating duplicate ad hoc notes elsewhere
- keep this file aligned with `README.md`, `AGENTS.md`, and the current codebase
