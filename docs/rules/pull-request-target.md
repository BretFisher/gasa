# Pull Request Target

| | |
|---|---|
| **Severity** | Critical |
| **Check ID** | `pull_request_target` |

## What it checks

Whether any workflow in `.github/workflows/*.yml` or `.github/workflows/*.yaml` uses the `pull_request_target` event.

## How the scanner evaluates it

The scanner:

- lists `.github/workflows` with `GET /repos/{owner}/{repo}/contents/.github/workflows`
- fetches each workflow file with `GET /repos/{owner}/{repo}/contents/{path}`
- base64-decodes the file content
- parses the workflow YAML and inspects the top-level `on` field
- flags the workflow if `on` is:
  - the string `pull_request_target`
  - an array containing `pull_request_target`
  - a mapping with a `pull_request_target` key

This rule does not try to prove whether the workflow later checks out untrusted code. It flags any use of `pull_request_target` because that event should never be used in a public repository and is highly discouraged in a private repository.

## Why this matters

`pull_request_target` runs in the context of the base branch, not the pull request branch. That means it can access repository secrets and a more trusted token context. If the workflow then checks out or executes code from the pull request, an attacker can exfiltrate secrets or abuse repository access. For that reason, it should never be used in public repositories and is highly discouraged in private repositories.

## Bad example

```yaml
on: pull_request_target

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
```

## Good example

```yaml
on: pull_request

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: npm test
```

If you truly need `pull_request_target`, keep the workflow limited to trusted base-branch code only and do not check out or execute pull request code.

## References

- `internal/scanner/workflow.go`
- [Events that trigger workflows: pull_request_target](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target)
- [Secure use reference for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Keeping your GitHub Actions and workflows secure: Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
