package main

import (
	"embed"
	"io/fs"
)

// ruleDocsFS embeds the rule documentation pages into the binary at compile
// time. The embed lives here in package main (the repo root) rather than in
// internal/scanner because go:embed cannot reference paths outside its own
// package directory (no ".."), and docs/rules is a sibling of internal/, not a
// child of it. main wires this FS into the scanner at startup.
//
//go:embed docs/rules/*.md
var ruleDocsFS embed.FS

// ruleDocsDir returns the embedded tree rooted at the rule pages, ready to hand
// to scanner.LoadRuleDocs.
func ruleDocsDir() fs.FS {
	sub, err := fs.Sub(ruleDocsFS, "docs/rules")
	if err != nil {
		// The embed path is a compile-time constant, so this can never fail.
		panic(err)
	}
	return sub
}
