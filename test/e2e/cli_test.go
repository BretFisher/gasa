//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The golden matrix drives the scanner API directly, because a failure there
// points straight at scanner behaviour. That path never exercises the CLI
// wiring an operator actually goes through, so these tests run the real binary:
// flag parsing, config resolution, token resolution, output encoding, and the
// process exit code.

// buildCLI compiles the binary under test once per run. Building rather than
// reusing ./bin/gasa guarantees the tests exercise the current working tree
// instead of whatever was last built by hand.
func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "gasa")
	cmd := exec.Command("go", "build", "-o", bin, "../..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build gasa: %v\n%s", err, out)
	}
	return bin
}

// runGasa runs the binary and returns stdout, stderr and the exit code.
func runGasa(t *testing.T, bin string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), "NO_COLOR=1")

	err := cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run %s: %v\nstderr: %s", bin, err, stderr.String())
	}
	return stdout.String(), stderr.String(), code
}

// TestCLIJSONMatchesGolden proves the binary and the scanner API agree. If the
// CLI ever drops findings on the way to stdout — a filter, an encoding bug, a
// config resolved differently — the API-level matrix would not notice.
func TestCLIJSONMatchesGolden(t *testing.T) {
	bin := buildCLI(t)

	for _, fx := range fixtureRepos {
		t.Run(fx.repo, func(t *testing.T) {
			stdout, stderr, code := runGasa(t, bin,
				"run", fx.owner+"/"+fx.repo, "--no-config", "--success", "--format", "json")
			if code != 0 {
				t.Fatalf("exit code = %d, want 0\nstderr: %s", code, stderr)
			}

			var result struct {
				Findings []struct {
					Rule    string `json:"rule"`
					ID      string `json:"id"`
					Success bool   `json:"success"`
				} `json:"findings"`
			}
			if err := json.Unmarshal([]byte(stdout), &result); err != nil {
				t.Fatalf("stdout is not valid JSON: %v\n%s", err, truncate(stdout))
			}

			var g golden
			raw, err := os.ReadFile(filepath.Join(goldenDir, fx.repo+".golden.json"))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if err := json.Unmarshal(raw, &g); err != nil {
				t.Fatalf("parse golden: %v", err)
			}

			if len(result.Findings) != len(g.Findings) {
				t.Fatalf("CLI reported %d findings, golden has %d", len(result.Findings), len(g.Findings))
			}

			want := make(map[string]bool, len(g.Findings))
			for _, e := range g.Findings {
				want[e.Rule+"\x00"+e.ID] = e.Success
			}
			for _, f := range result.Findings {
				success, ok := want[f.Rule+"\x00"+f.ID]
				if !ok {
					t.Errorf("CLI reported a finding absent from the golden: rule=%s id=%s", f.Rule, f.ID)
					continue
				}
				if success != f.Success {
					t.Errorf("rule=%s id=%s success: CLI=%t golden=%t", f.Rule, f.ID, f.Success, success)
				}
			}
		})
	}
}

// TestCLIHumanOutputNamesFailingRules covers the default table path, which is
// what most operators see and which the JSON tests never touch.
func TestCLIHumanOutputNamesFailingRules(t *testing.T) {
	bin := buildCLI(t)

	stdout, stderr, code := runGasa(t, bin, "run", "bretfisher/gasa-fail", "--no-config")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr: %s", code, stderr)
	}
	for _, want := range []string{"pull_request_target", "Unpinned Action"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("table output missing %q\n%s", want, truncate(stdout))
		}
	}
	// The scan header goes to stderr so stdout stays pipeable.
	if !strings.Contains(stderr, "Config: disabled (--no-config)") {
		t.Errorf("stderr should record that config was disabled, got: %s", truncate(stderr))
	}
}

// TestCLIRejectsConflictingConfigFlags is a cheap guard on the flag wiring the
// whole suite depends on: if --no-config stopped working, every scan above
// would silently pick up the repository's own .gasa.yaml and run a reduced rule
// set while still passing.
func TestCLIRejectsConflictingConfigFlags(t *testing.T) {
	bin := buildCLI(t)

	_, stderr, code := runGasa(t, bin, "run", "bretfisher/gasa-pass", "--no-config", "--config", ".gasa.yaml")
	if code == 0 {
		t.Fatal("expected a non-zero exit for mutually exclusive flags")
	}
	if !strings.Contains(stderr, "no-config") {
		t.Errorf("error should name the conflicting flags, got: %s", truncate(stderr))
	}
}

func truncate(s string) string {
	const max = 2000
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n… truncated"
}
