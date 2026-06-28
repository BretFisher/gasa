package scanner

import (
	"os"
	"testing"
)

// TestMain loads the rule documentation (front-matter + report copy) from the
// real docs/rules directory before any test runs. Production loads these from an
// embedded FS; tests read them straight off disk via os.DirFS (go:embed can't
// reach ../../docs/rules, but runtime reads have no such restriction).
func TestMain(m *testing.M) {
	if err := LoadRuleDocs(os.DirFS("../../docs/rules")); err != nil {
		panic("loading rule docs for tests: " + err.Error())
	}
	os.Exit(m.Run())
}
