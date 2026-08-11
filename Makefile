.PHONY: run build clean test cover deps fmt vet lint fixtures-verify fixtures-apply fixtures-capture

# Run the CLI
run:
	go run . --help

# Build the CLI binary
build:
	mkdir -p bin && go build -o bin/gasa .

# Clean build artifacts
clean:
	rm -rf bin/ gasa coverage.out coverage.html

# Run tests with the race detector and randomized order. This is the gate CI
# runs: the scanner fans out concurrent collectors and a shared in-flight
# semaphore, so -race is the tool that catches that class of bug. -shuffle=on
# surfaces hidden inter-test ordering dependencies.
test:
	go test -race -shuffle=on ./...

# Run tests with coverage; writes coverage.out and coverage.html
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Install / sync dependencies
deps:
	go mod tidy

# Format code
fmt:
	go fmt ./...

# Static analysis via go vet
vet:
	go vet ./...

# Lint via golangci-lint (install: brew install golangci-lint)
lint:
	golangci-lint run -c .github/linters/.golangci.yaml ./...

# --- End-to-end test fixture repositories -----------------------------------
# The e2e suite scans three real repositories (gasa-pass, gasa-fail,
# gasa-fail-private). They are inputs to a test, so drift makes the test lie
# while still going green. Their content and settings are declared under
# testdata/e2e/fixtures/ and reconciled with these targets.

# Read-only drift check: does the live state match the checkout? This is the
# only fixture target CI runs, and the only one its read-only token can perform.
fixtures-verify:
	go run ./tools/fixtures verify

# Push the checkout back over the repositories. Needs an admin token, so it is
# local-only. Additive: it never deletes repository files.
fixtures-apply:
	go run ./tools/fixtures apply

# Record the repositories' current state into the checkout. Use after a
# deliberate change made through the GitHub UI; review the diff before
# committing.
fixtures-capture:
	go run ./tools/fixtures capture
