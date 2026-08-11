// Package e2e holds the end-to-end suite that scans the real fixture
// repositories. Every test file carries the `e2e` build tag so the default
// `go test ./...` stays hermetic and offline.
//
// This file deliberately carries no build tag. Without it the package has no
// Go files when the tag is absent, and golangci-lint fails typechecking outright
// with "build constraints exclude all Go files" rather than simply skipping it.
package e2e
