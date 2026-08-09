package cmd

import "github.com/bretfisher/gasa/internal/scanner"

// noConfigLabel is what the scan header prints in place of a config path when
// config loading was explicitly turned off. It is printed rather than silently
// omitted so an operator reading the header can tell "no config file existed"
// apart from "a config file existed and was ignored on purpose".
const noConfigLabel = "disabled (--no-config)"

// resolveScanConfig decides which config, if any, applies to this invocation.
//
// Precedence, highest first:
//  1. --no-config: use no config at all, not even a discovered one
//  2. --config PATH: load exactly that file, and fail if it is missing
//  3. auto-discovery: load .gasa.yml / .gasa.yaml from workDir if present
//
// The returned label is what the scan header shows; it is the config path for
// cases 2 and 3, noConfigLabel for case 1, and "" when discovery found nothing.
//
// This lives in one place because `run` and `batch` must resolve config
// identically. Divergence here would mean the same repo scanned two ways
// silently applies two different rule sets.
func resolveScanConfig(configPath string, noConfig bool, workDir string) (*scanner.Config, string, error) {
	if noConfig {
		return nil, noConfigLabel, nil
	}
	if configPath != "" {
		cfg, err := scanner.LoadConfig(configPath)
		if err != nil {
			return nil, "", err
		}
		return cfg, configPath, nil
	}
	if workDir == "" {
		workDir = "."
	}
	return scanner.LoadConfigFromDir(workDir)
}
