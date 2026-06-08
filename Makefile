.PHONY: run build clean test cover deps fmt vet lint

# Run the CLI
run:
	go run . --help

# Build the CLI binary
build:
	mkdir -p bin && go build -o bin/gasa .

# Clean build artifacts
clean:
	rm -rf bin/ gasa coverage.out coverage.html

# Run tests
test:
	go test ./...

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
