//go:build e2e

// Package e2e scans real GitHub repositories and asserts what gasa reports.
//
// These are integration tests, not unit tests: they cross a network boundary
// and an auth boundary, and they are the only tests that can catch GitHub
// changing its own behaviour. The build tag keeps them out of `make test` so
// the default gate stays hermetic, fast, and offline — a tag rather than
// t.Skip, so the default suite cannot make a network call even by accident.
//
//	make test-e2e
package e2e

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bretfisher/gasa/internal/scanner"
)

var update = flag.Bool("update", false, "rewrite the golden files from the current scan results")

const (
	goldenDir   = "../../testdata/e2e/expected"
	scanTimeout = 3 * time.Minute
)

// fixtureRepos are the repositories under test and what each exists to prove.
// Kept here rather than derived from the fixture manifests so a manifest bug
// cannot silently shrink the set of repositories the suite scans.
var fixtureRepos = []struct {
	owner string
	repo  string
	role  string
}{
	{"bretfisher", "gasa-pass", "every rule passes"},
	{"bretfisher", "gasa-fail", "fails every rule it structurally can"},
	{"bretfisher", "gasa-fail-private", "fails the two update-tool rules that gasa-fail cannot"},
}

// goldenEntry is what the suite asserts: a rule's outcome, not its prose.
//
// Title, Description and Remediation are deliberately excluded. They are
// rendered from docs/rules/*.md front-matter templates, so asserting them would
// turn every wording fix into an e2e failure. FixURL and DocURL have dedicated
// unit tests, and Line couples the golden to fixture file formatting.
type goldenEntry struct {
	Rule     string `json:"rule"`
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Success  bool   `json:"success"`
}

type golden struct {
	Repo       string        `json:"repo"`
	Incomplete []string      `json:"incomplete"`
	Findings   []goldenEntry `json:"findings"`
}

func newScanner(t *testing.T) *scanner.Scanner {
	t.Helper()
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		token = strings.TrimSpace(runCmd(t, "gh", "auth", "token"))
	}
	if token == "" {
		t.Fatal("no GitHub token: set GITHUB_TOKEN, GH_TOKEN, or sign in with `gh auth login`.\n" +
			"In CI this is E2E_REPO_PAT, which needs Contents: Read and Administration: Read on all three fixture repositories.")
	}
	return scanner.NewWithToken(token)
}

func runCmd(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// scanFixture scans one repository with no config at all, so the full
// registered rule set always runs regardless of what config sits in the working
// directory. A local .gasa.yaml exclusion silently shrinking the rule set is
// the exact failure this suite exists to catch.
func scanFixture(t *testing.T, s *scanner.Scanner, owner, repo string) *scanner.ScanResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	result, err := s.ScanRepoWithOptions(ctx, owner, repo, scanner.ScanOptions{
		IncludeSuccess: true,
		Config:         nil,
	})
	if err != nil {
		t.Fatalf("scan %s/%s: %v", owner, repo, err)
	}
	if result.Error != "" {
		t.Fatalf("scan %s/%s reported: %s", owner, repo, result.Error)
	}

	// A scan that reports nothing is never a legitimate result here: with
	// IncludeSuccess set, every registered rule contributes either a finding or
	// a success. Asserting it explicitly is what stops an empty result set from
	// being compared against an empty golden and passing.
	if want := len(scanner.AvailableRules()); len(result.Findings) < want {
		t.Fatalf("scan %s/%s returned %d findings for %d registered rules; every rule must report",
			owner, repo, len(result.Findings), want)
	}
	return result
}

func toGolden(repo string, result *scanner.ScanResult) golden {
	entries := make([]goldenEntry, 0, len(result.Findings))
	for _, f := range result.Findings {
		entries = append(entries, goldenEntry{Rule: f.Rule, ID: f.ID, Severity: f.Severity, Success: f.Success})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Rule != entries[j].Rule {
			return entries[i].Rule < entries[j].Rule
		}
		return entries[i].ID < entries[j].ID
	})

	incomplete := append([]string(nil), result.Incomplete...)
	sort.Strings(incomplete)
	if incomplete == nil {
		incomplete = []string{}
	}
	return golden{Repo: repo, Incomplete: incomplete, Findings: entries}
}

// TestScanMatchesGolden is the core regression net: a rule that silently stops
// firing, or starts firing where it should not, changes this file.
func TestScanMatchesGolden(t *testing.T) {
	s := newScanner(t)

	for _, fx := range fixtureRepos {
		t.Run(fx.repo, func(t *testing.T) {
			got := toGolden(fx.repo, scanFixture(t, s, fx.owner, fx.repo))
			path := filepath.Join(goldenDir, fx.repo+".golden.json")

			if *update {
				writeGolden(t, path, got)
				t.Logf("updated %s", path)
				return
			}

			wantRaw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden: %v\nrun `make e2e-update` to create it", err)
			}
			var want golden
			if err := json.Unmarshal(wantRaw, &want); err != nil {
				t.Fatalf("parse golden %s: %v", path, err)
			}

			diffGolden(t, fx.repo, want, got)
		})
	}
}

func writeGolden(t *testing.T, path string, g golden) {
	t.Helper()
	raw, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		t.Fatalf("marshal golden: %v", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write golden: %v", err)
	}
}

// diffGolden reports differences per entry rather than dumping two blobs, so a
// failure names the rule that changed.
func diffGolden(t *testing.T, repo string, want, got golden) {
	t.Helper()

	index := func(g golden) map[string]goldenEntry {
		m := make(map[string]goldenEntry, len(g.Findings))
		for _, e := range g.Findings {
			m[e.Rule+"\x00"+e.ID] = e
		}
		return m
	}
	wantIdx, gotIdx := index(want), index(got)

	for key, w := range wantIdx {
		g, ok := gotIdx[key]
		if !ok {
			t.Errorf("%s: expected finding no longer reported: rule=%s id=%s (success=%t)", repo, w.Rule, w.ID, w.Success)
			continue
		}
		if g.Success != w.Success {
			t.Errorf("%s: rule=%s id=%s success changed %t -> %t", repo, w.Rule, w.ID, w.Success, g.Success)
		}
		if g.Severity != w.Severity {
			t.Errorf("%s: rule=%s id=%s severity changed %q -> %q", repo, w.Rule, w.ID, w.Severity, g.Severity)
		}
	}
	for key, g := range gotIdx {
		if _, ok := wantIdx[key]; !ok {
			t.Errorf("%s: unexpected new finding: rule=%s id=%s success=%t severity=%s", repo, g.Rule, g.ID, g.Success, g.Severity)
		}
	}

	if strings.Join(want.Incomplete, "|") != strings.Join(got.Incomplete, "|") {
		t.Errorf("%s: incomplete checks changed\n  want: %v\n  got:  %v", repo, want.Incomplete, got.Incomplete)
	}
}

// TestEveryRuleHasPassAndFailCoverage is what makes this suite durable. Adding a
// rule without fixture coverage becomes a test failure instead of an untested
// rule quietly shipping.
//
// The invariant is "a fail case in at least one fail fixture", not "gasa-fail
// fails everything": update-tool-configuration fires only when no tool covers
// github-actions while update-tool-actions-cooldown fires only when one does,
// so those conditions are exact complements and no single repository can fail
// both.
func TestEveryRuleHasPassAndFailCoverage(t *testing.T) {
	passing := make(map[string]bool)
	failing := make(map[string]bool)

	for _, fx := range fixtureRepos {
		var g golden
		raw, err := os.ReadFile(filepath.Join(goldenDir, fx.repo+".golden.json"))
		if err != nil {
			t.Fatalf("read golden for %s: %v", fx.repo, err)
		}
		if err := json.Unmarshal(raw, &g); err != nil {
			t.Fatalf("parse golden for %s: %v", fx.repo, err)
		}
		for _, e := range g.Findings {
			if e.Success {
				passing[e.Rule] = true
			} else {
				failing[e.Rule] = true
			}
		}
	}

	for _, r := range scanner.AvailableRules() {
		if !passing[r.Name] {
			t.Errorf("rule %q has no passing case in any fixture; gasa-pass should demonstrate it clean", r.Name)
		}
		if !failing[r.Name] {
			t.Errorf("rule %q has no failing case in any fixture; add one to a fail fixture or the rule is untested end to end", r.Name)
		}
	}
}

// TestNoRuleIsSilent guards the failure mode that motivated this whole phase: a
// rule that produces neither a finding nor a success vanishes from the report,
// which in every output format is indistinguishable from a clean pass.
func TestNoRuleIsSilent(t *testing.T) {
	s := newScanner(t)

	for _, fx := range fixtureRepos {
		t.Run(fx.repo, func(t *testing.T) {
			result := scanFixture(t, s, fx.owner, fx.repo)

			reported := make(map[string]bool)
			for _, f := range result.Findings {
				reported[f.Rule] = true
			}
			for _, r := range scanner.AvailableRules() {
				if !reported[r.Name] {
					t.Errorf("rule %q reported nothing at all for %s (%s) — neither a finding nor a success",
						r.Name, fx.repo, fx.role)
				}
			}
		})
	}
}
