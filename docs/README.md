# GASA Command Examples

Quick command reference for future agents working in this repository.

The Go module for the CLI lives at the repo root. Run `go run` from the repo root:

```bash
go run . <command>
```

From the repo root, build or invoke through `make`:

```bash
make build
./bin/gasa <command>
```

## Learn The CLI

```bash
# Top-level help
./bin/gasa --help

# Command-specific help
./bin/gasa run --help
./bin/gasa rules --help
./bin/gasa batch --help
```

## Common Single-Repo Scans

```bash
# Scan a repo with default table output
./bin/gasa run owner/repo

# Scan the repo inferred from git origin
./bin/gasa run

# JSON output for automation
./bin/gasa run --format json owner/repo

# HTML output
./bin/gasa run --format html owner/repo > report.html

# Show debug lines on stderr
./bin/gasa run --debug owner/repo

# Include passing rule checks too
./bin/gasa run --success owner/repo
```

## Targeted Scans

```bash
# List canonical rule names and aliases
./bin/gasa rules

# Run one rule by alias
./bin/gasa run --rule fork-pr-approval owner/repo

# Run multiple rules
./bin/gasa run --rule action-pinning,permissions owner/repo

# Run one category
./bin/gasa run --category workflows owner/repo

# Run only selected severities
./bin/gasa run --severity critical,high owner/repo
```

## Config And Auth

```bash
# Use an explicit token from stdin
printf '%s' "$GITHUB_TOKEN" | ./bin/gasa run --token-stdin owner/repo

# Use an explicit config file
./bin/gasa run --config .gasa.yml owner/repo
```

Authentication resolution order:

1. `--token-stdin`
2. `GITHUB_TOKEN`
3. `GH_TOKEN`
4. `gh auth token`

## Batch Scans

```bash
# Scan all repos for a user or org with streaming table output
./bin/gasa batch BretFisher --format table

# Scan a comma-separated repo list and write HTML
./bin/gasa batch BretFisher/repo1,BretFisher/repo2 --format html --output report.html

# Scan repos listed in a file
./bin/gasa batch --input repos.txt --format html --output report.html

# JSON batch output requires --output
./bin/gasa batch BretFisher --format json --output report.json
```

## Developer Verification

Project instructions require these commands after changes:

```bash
make build
make test
```
