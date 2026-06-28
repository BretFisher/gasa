// Command gasa is the GitHub Actions Security Assessment CLI. It scans GitHub
// repositories for Actions security misconfigurations, action-pinning issues,
// and missing dependency update automation.
package main

import (
	"fmt"
	"os"

	"github.com/bretfisher/gasa/cmd"
	"github.com/bretfisher/gasa/internal/scanner"
)

func main() {
	// Load rule metadata + report copy from the embedded docs/rules pages before
	// any command runs; the scanner reads rules from this registry.
	if err := scanner.LoadRuleDocs(ruleDocsDir()); err != nil {
		fmt.Fprintln(os.Stderr, "gasa: failed to load rule documentation:", err)
		os.Exit(1)
	}
	cmd.Execute()
}
