# gasa-fail-private

Test fixture for [`gasa`](https://github.com/bretfisher/gasa). **Do not use as a template.**

This repository is deliberately misconfigured for the two `updates` rules that
cannot fail anywhere else, and is kept correct for everything else so its
failures stay unambiguous.

## Why this repository exists

`gasa-fail` cannot fail every rule, because some rules have mutually exclusive
trigger conditions:

- `updates/update-tool-configuration` fires only when **no** tool covers the
  `github-actions` ecosystem.
- `updates/update-tool-actions-cooldown` fires only when a tool **does** cover
  it but sets no cooldown.

Those are exact complements, so no single repository can fail both. This
repository covers the second case (and `update-tool-actions-pinning` with it)
while `gasa-fail` covers the first.

## What is deliberately wrong

| Rule | Why it fires here |
|---|---|
| `updates/update-tool-actions-cooldown` | Renovate covers `github-actions` but sets no `minimumReleaseAge`, and Dependabot has no `github-actions` entry with a `cooldown` |
| `updates/update-tool-actions-pinning` | Renovate covers `github-actions` without digest pinning, and Dependabot has no `github-actions` entry to preserve existing SHA pins |

`renovate.json` extends `config:recommended` rather than `config:best-practices`
on purpose. `config:best-practices` transitively extends
`helpers:pinGitHubActionDigests`, so it genuinely *does* pin action digests and
would make the pinning rule pass.

## What is deliberately correct

Everything else: the workflow is SHA-pinned with explicit permissions and no
`pull_request_target`, and repository Actions settings are hardened. Dependabot
covers `docker` so a valid update tool is configured.

This repository is private so it also serves as a fixture for private-repo
Actions settings behavior, which differs from public.

## Managed by the gasa repo

Contents and settings are declared in `gasa` under `testdata/e2e/fixtures/` and
applied with `make fixtures-apply`. Edits made here directly will be reverted.
