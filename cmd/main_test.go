package cmd

import (
	"os"
	"testing"

	"github.com/bretfisher/gasa/internal/scanner"
)

// TestMain loads rule documentation before cmd tests run. Production loads these
// from an embedded FS in package main; here we read them off disk via os.DirFS
// pointed at the repo's docs/rules directory (one level up from cmd).
func TestMain(m *testing.M) {
	if err := scanner.LoadRuleDocs(os.DirFS("../docs/rules")); err != nil {
		panic("loading rule docs for cmd tests: " + err.Error())
	}
	os.Exit(m.Run())
}
