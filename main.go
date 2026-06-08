// Command gasa is the GitHub Actions Security Assessment CLI. It scans GitHub
// repositories for Actions security misconfigurations, action-pinning issues,
// and missing dependency update automation.
package main

import "github.com/bretfisher/github-security-assessment/cmd"

func main() {
	cmd.Execute()
}
