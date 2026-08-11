//go:build e2e

package e2e

import (
	"os"
	"testing"

	"github.com/bretfisher/gasa/internal/scanner"
)

// TestMain registers the rule documentation before any test runs.
//
// The rule registry is built from docs/rules/*.md front matter, and the binary
// populates it at startup from an embedded FS. Anything that imports the scanner
// package directly — this suite included — must do the same, or the registry is
// empty, no rules resolve, and every scan returns nothing.
//
// That failure is silent and dangerous: the first version of this suite passed
// while comparing an empty result set against an empty golden file. The
// sanity check below exists so it can never happen again.
func TestMain(m *testing.M) {
	if err := scanner.LoadRuleDocs(os.DirFS("../../docs/rules")); err != nil {
		panic("loading rule docs for e2e tests: " + err.Error())
	}
	if len(scanner.AvailableRules()) == 0 {
		panic("no rules registered after loading docs/rules; the suite would pass vacuously")
	}
	os.Exit(m.Run())
}
