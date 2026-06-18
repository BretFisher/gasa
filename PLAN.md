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

- `release-please` (googleapis/release-please-action): evaluated and deferred. It automates version bumping and CHANGELOG generation from Conventional Commits, then cuts the tag/release; GoReleaser would still build and publish artifacts on that tag (they are complementary, not redundant). Not adopted now because the project has a single committer, does not yet enforce Conventional Commits, and the current `workflow_dispatch` release with an explicit version input is simpler. Revisit when either a second regular contributor lands or Conventional Commits are enforced and hands-off versioning is wanted. Prerequisite before adoption is commit-message discipline, not the action itself. Coordinate release ownership so release-please and GoReleaser do not both try to create the GitHub Release.

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
