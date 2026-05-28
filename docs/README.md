# GASA Command Examples

Quick command reference for future agents working in this repository.

The Go module for the CLI lives in `app/`. Run `go run` from `app/`:

```bash
go run ./cmd/gasa <command>
```

From the repo root, build or invoke through `make -C app`:

```bash
make -C app build
./app/bin/gasa <command>
```

## Learn The CLI

```bash
# Top-level help
./app/bin/gasa --help

# Command-specific help
./app/bin/gasa run --help
./app/bin/gasa rules --help
./app/bin/gasa batch --help
```

## Common Single-Repo Scans

```bash
# Scan a repo with default table output
./app/bin/gasa run owner/repo

# Scan the repo inferred from git origin
./app/bin/gasa run

# JSON output for automation
./app/bin/gasa run --format json owner/repo

# HTML output
./app/bin/gasa run --format html owner/repo > report.html

# Show debug lines on stderr
./app/bin/gasa run --debug owner/repo

# Include passing rule checks too
./app/bin/gasa run --success owner/repo
```

## Targeted Scans

```bash
# List canonical rule names and aliases
./app/bin/gasa rules

# Run one rule by alias
./app/bin/gasa run --rule fork-pr-approval owner/repo

# Run multiple rules
./app/bin/gasa run --rule action-pinning,permissions owner/repo

# Run one category
./app/bin/gasa run --category workflows owner/repo

# Run only selected severities
./app/bin/gasa run --severity critical,high owner/repo
```

## Config And Auth

```bash
# Use an explicit token from stdin
printf '%s' "$GITHUB_TOKEN" | ./app/bin/gasa run --token-stdin owner/repo

# Use an explicit config file
./app/bin/gasa run --config .gasa.yml owner/repo
```

Authentication resolution order:

1. `--token-stdin`
2. `GITHUB_TOKEN`
3. `GH_TOKEN`
4. `gh auth token`

## Batch Scans

```bash
# Scan all repos for a user or org with streaming table output
./app/bin/gasa batch BretFisher --format table

# Scan a comma-separated repo list and write HTML
./app/bin/gasa batch BretFisher/repo1,BretFisher/repo2 --format html --output report.html

# Scan repos listed in a file
./app/bin/gasa batch --input repos.txt --format html --output report.html

# JSON batch output requires --output
./app/bin/gasa batch BretFisher --format json --output report.json
```

## Developer Verification

Project instructions require these commands after changes:

```bash
make -C app build
make -C app test
```
