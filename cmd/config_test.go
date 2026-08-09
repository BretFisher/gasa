package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

const sampleConfig = `rules:
  exclude:
    - actions/permissions/allowed-actions-policy
`

// writeConfigDir returns a temp dir containing a .gasa.yaml that excludes a
// rule, so tests can prove whether auto-discovery ran.
func writeConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gasa.yaml"), []byte(sampleConfig), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return dir
}

func TestResolveScanConfigDiscoversFromWorkDir(t *testing.T) {
	dir := writeConfigDir(t)

	cfg, label, err := resolveScanConfig("", false, dir)
	if err != nil {
		t.Fatalf("resolveScanConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected a discovered config, got nil")
	}
	if len(cfg.Rules.Exclude) != 1 {
		t.Fatalf("expected 1 excluded rule, got %d", len(cfg.Rules.Exclude))
	}
	if want := filepath.Join(dir, ".gasa.yaml"); label != want {
		t.Fatalf("label = %q, want %q", label, want)
	}
}

// The point of --no-config: a config file that exists and would be
// auto-discovered must be ignored entirely. This is what keeps an operator's
// local .gasa.yaml from silently shrinking the rule set during e2e runs.
func TestResolveScanConfigNoConfigIgnoresDiscoverableFile(t *testing.T) {
	dir := writeConfigDir(t)

	cfg, label, err := resolveScanConfig("", true, dir)
	if err != nil {
		t.Fatalf("resolveScanConfig: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config with --no-config, got %+v", cfg)
	}
	if label != noConfigLabel {
		t.Fatalf("label = %q, want %q", label, noConfigLabel)
	}
}

func TestResolveScanConfigExplicitPathWins(t *testing.T) {
	dir := writeConfigDir(t)
	explicit := filepath.Join(t.TempDir(), "custom.yaml")
	if err := os.WriteFile(explicit, []byte("rules:\n"), 0o600); err != nil {
		t.Fatalf("write explicit config: %v", err)
	}

	cfg, label, err := resolveScanConfig(explicit, false, dir)
	if err != nil {
		t.Fatalf("resolveScanConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected explicit config, got nil")
	}
	if len(cfg.Rules.Exclude) != 0 {
		t.Fatalf("explicit config should have no exclusions, got %v", cfg.Rules.Exclude)
	}
	if label != explicit {
		t.Fatalf("label = %q, want %q", label, explicit)
	}
}

func TestResolveScanConfigMissingExplicitPathErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.yaml")

	if _, _, err := resolveScanConfig(missing, false, "."); err == nil {
		t.Fatal("expected an error for a missing --config path, got nil")
	}
}

func TestResolveScanConfigNoFileFound(t *testing.T) {
	cfg, label, err := resolveScanConfig("", false, t.TempDir())
	if err != nil {
		t.Fatalf("resolveScanConfig: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config when none exists, got %+v", cfg)
	}
	if label != "" {
		t.Fatalf("label = %q, want empty", label)
	}
}

// --config and --no-config contradict each other; cobra must reject the pair
// rather than letting one silently win.
func TestConfigFlagsAreMutuallyExclusive(t *testing.T) {
	t.Cleanup(resetFlagsForTest)

	rootCmd.SetArgs([]string{"run", "--config", "x.yaml", "--no-config", "owner/repo"})
	rootCmd.SetOut(os.Stderr)
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected mutually-exclusive flag error, got nil")
	}
}

// resetFlagsForTest clears both the flag values and pflag's per-flag Changed
// bit. Cobra's mutually-exclusive check reads Changed, not the bound variable,
// so resetting only the variables would leak "already set" state into whichever
// test runs next — and `make test` runs with -shuffle=on, so that ordering is
// not stable.
func resetFlagsForTest() {
	rootCmd.SetArgs(nil)
	flagConfig = ""
	flagNoConfig = false
	for _, name := range []string{"config", "no-config"} {
		if f := rootCmd.PersistentFlags().Lookup(name); f != nil {
			f.Changed = false
		}
	}
}
