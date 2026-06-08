# Workflow Permissions

| | |
|---|---|
| **Severity** | High |
| **Check ID** | `workflow_permissions` |

## What it checks

Whether each workflow has explicit `permissions` configured either:

- once at the workflow level, or
- on every individual job

## How the scanner evaluates it

The scanner:

- lists workflow files from `.github/workflows`
- fetches each file with `GET /repos/{owner}/{repo}/contents/{path}`
- parses the YAML and inspects:
  - top-level `permissions`
  - each `jobs.<job_id>.permissions`
- considers the workflow compliant if:
  - top-level `permissions` exists, or
  - every job has its own `permissions`
- flags the workflow if neither condition is true

This is a structural check only. It verifies that permissions are explicit, not whether each permission set is perfectly minimal.

## Why this matters

Without explicit permissions, the workflow inherits the repository default `GITHUB_TOKEN` permissions. In many repos that is broader than needed, which increases impact if a workflow or action is compromised.

## Bad example

```yaml
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: npm test
```

## Good example

```yaml
on: push

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: npm test
```

## Good example with per-job permissions

```yaml
on: push

permissions: {}

jobs:
  test:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: npm test
```

## References

- `internal/scanner/workflow.go`
- [Use GITHUB_TOKEN for authentication in workflows](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token)
