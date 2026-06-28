package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bretfisher/gasa/internal/scanner"
)

func TestRepoStateClass(t *testing.T) {
	tests := []struct {
		name   string
		result batchRepoResult
		want   string
	}{
		{
			name: "error when scan failed",
			result: batchRepoResult{
				RepoFullName: "owner/repo",
				Err:          errors.New("scan failed"),
			},
			want: "error",
		},
		{
			name: "error when result has error",
			result: batchRepoResult{
				RepoFullName: "owner/repo",
				Result: &scanner.ScanResult{
					Error: "API error",
				},
			},
			want: "error",
		},
		{
			name: "clean when no findings",
			result: batchRepoResult{
				RepoFullName: "owner/repo",
				Result: &scanner.ScanResult{
					Findings: []scanner.Finding{},
				},
			},
			want: "clean",
		},
		{
			name: "clean when all findings are success",
			result: batchRepoResult{
				RepoFullName: "owner/repo",
				Result: &scanner.ScanResult{
					Findings: []scanner.Finding{
						{Success: true, Severity: scanner.SeverityHigh},
						{Success: true, Severity: scanner.SeverityMedium},
					},
				},
			},
			want: "clean",
		},
		{
			name: "high-findings when critical finding exists",
			result: batchRepoResult{
				RepoFullName: "owner/repo",
				Result: &scanner.ScanResult{
					Findings: []scanner.Finding{
						{Success: false, Severity: scanner.SeverityCritical},
					},
				},
			},
			want: "high-findings",
		},
		{
			name: "high-findings when high finding exists",
			result: batchRepoResult{
				RepoFullName: "owner/repo",
				Result: &scanner.ScanResult{
					Findings: []scanner.Finding{
						{Success: false, Severity: scanner.SeverityHigh},
					},
				},
			},
			want: "high-findings",
		},
		{
			name: "high-findings when mixed with lower severities",
			result: batchRepoResult{
				RepoFullName: "owner/repo",
				Result: &scanner.ScanResult{
					Findings: []scanner.Finding{
						{Success: false, Severity: scanner.SeverityMedium},
						{Success: false, Severity: scanner.SeverityHigh},
						{Success: false, Severity: scanner.SeverityLow},
					},
				},
			},
			want: "high-findings",
		},
		{
			name: "findings when only medium severity",
			result: batchRepoResult{
				RepoFullName: "owner/repo",
				Result: &scanner.ScanResult{
					Findings: []scanner.Finding{
						{Success: false, Severity: scanner.SeverityMedium},
					},
				},
			},
			want: "findings",
		},
		{
			name: "findings when only low severity",
			result: batchRepoResult{
				RepoFullName: "owner/repo",
				Result: &scanner.ScanResult{
					Findings: []scanner.Finding{
						{Success: false, Severity: scanner.SeverityLow},
					},
				},
			},
			want: "findings",
		},
		{
			name: "findings when only info severity",
			result: batchRepoResult{
				RepoFullName: "owner/repo",
				Result: &scanner.ScanResult{
					Findings: []scanner.Finding{
						{Success: false, Severity: scanner.SeverityInfo},
					},
				},
			},
			want: "findings",
		},
		{
			name: "findings when multiple lower severities",
			result: batchRepoResult{
				RepoFullName: "owner/repo",
				Result: &scanner.ScanResult{
					Findings: []scanner.Finding{
						{Success: false, Severity: scanner.SeverityMedium},
						{Success: false, Severity: scanner.SeverityLow},
						{Success: false, Severity: scanner.SeverityInfo},
					},
				},
			},
			want: "findings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := repoStateClass(tt.result)
			if got != tt.want {
				t.Errorf("repoStateClass() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPrintBatchJSONStdout(t *testing.T) {
	results := []batchRepoResult{
		{RepoFullName: "owner/clean", Result: &scanner.ScanResult{RepoFullName: "owner/clean"}},
		{RepoFullName: "owner/broken", Err: errors.New("api failure")},
	}

	out := captureStdout(t, func() {
		// Empty outputPath means stdout — the agent-native default.
		if err := printBatchJSON(results, ""); err != nil {
			t.Errorf("printBatchJSON() error = %v", err)
		}
	})

	var got []scanner.ScanResult
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not a valid JSON array: %v\noutput: %q", err, out)
	}
	if len(got) != 2 {
		t.Fatalf("got %d results, want 2", len(got))
	}
	if got[0].RepoFullName != "owner/clean" {
		t.Errorf("got[0].RepoFullName = %q, want %q", got[0].RepoFullName, "owner/clean")
	}
	// Hard errors are surfaced as a minimal ScanResult with Error set.
	if got[1].Error != "api failure" {
		t.Errorf("got[1].Error = %q, want %q", got[1].Error, "api failure")
	}
	if got[1].RepoURL != "https://github.com/owner/broken" {
		t.Errorf("got[1].RepoURL = %q, want %q", got[1].RepoURL, "https://github.com/owner/broken")
	}
}

// Incomplete checks must be visible in every output mode so a partial scan is
// never mistaken for a clean one.
func TestPrintTable_ShowsIncomplete(t *testing.T) {
	result := &scanner.ScanResult{
		RepoFullName: "owner/repo",
		Incomplete:   []string{"renovate config: timed out before GitHub responded (raise --timeout)"},
	}
	out := captureStdout(t, func() { printTable(result) })
	for _, want := range []string{"Incomplete:", "renovate config", "timed out"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q\noutput:\n%s", want, out)
		}
	}
}

func TestPrintHTML_ShowsIncomplete(t *testing.T) {
	result := &scanner.ScanResult{
		RepoFullName: "owner/repo",
		Incomplete:   []string{"workflows: GitHub secondary rate limit triggered"},
	}
	out := captureStdout(t, func() {
		if err := printHTML(result); err != nil {
			t.Fatalf("printHTML() error = %v", err)
		}
	})
	for _, want := range []string{`class="card incomplete"`, "could not be completed", "secondary rate limit"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML output missing %q", want)
		}
	}
}

func TestBatchHTML_ShowsIncomplete(t *testing.T) {
	results := []batchRepoResult{
		{RepoFullName: "o/partial", Result: &scanner.ScanResult{
			RepoFullName: "o/partial",
			Incomplete:   []string{"dependabot config: GitHub returned HTTP 502"},
		}},
	}
	view := buildBatchView(results)
	var buf bytes.Buffer
	if err := renderHTMLTemplate(&buf, htmlBatchTemplate, view); err != nil {
		t.Fatalf("renderHTMLTemplate() error: %v", err)
	}
	html := buf.String()
	for _, want := range []string{`class="card incomplete"`, "dependabot config", "HTTP 502"} {
		if !strings.Contains(html, want) {
			t.Errorf("batch HTML missing %q", want)
		}
	}
}

func TestBuildBatchViewStateCounts(t *testing.T) {
	results := []batchRepoResult{
		{RepoFullName: "o/clean", Result: &scanner.ScanResult{}},
		{RepoFullName: "o/findings", Result: &scanner.ScanResult{Findings: []scanner.Finding{{Success: false, Severity: scanner.SeverityMedium}}}},
		{RepoFullName: "o/high", Result: &scanner.ScanResult{Findings: []scanner.Finding{{Success: false, Severity: scanner.SeverityHigh}}}},
		{RepoFullName: "o/err", Err: errors.New("api failure")},
	}
	view := buildBatchView(results)

	want := map[string]int{
		stateClassClean:        1,
		stateClassFindings:     1,
		stateClassHighFindings: 1,
		stateClassError:        1,
	}
	for state, wantCount := range want {
		if got := view.StateCounts[state]; got != wantCount {
			t.Errorf("StateCounts[%q] = %d, want %d", state, got, wantCount)
		}
	}
}

func TestBatchHTMLFilterAttributes(t *testing.T) {
	results := []batchRepoResult{
		{RepoFullName: "o/clean", Result: &scanner.ScanResult{}},
		{RepoFullName: "o/high", Result: &scanner.ScanResult{Findings: []scanner.Finding{{Success: false, Severity: scanner.SeverityHigh}}}},
		{RepoFullName: "o/err", Err: errors.New("api failure")},
	}
	view := buildBatchView(results)
	var buf bytes.Buffer
	if err := renderHTMLTemplate(&buf, htmlBatchTemplate, view); err != nil {
		t.Fatalf("renderHTMLTemplate() error: %v", err)
	}
	html := buf.String()

	mustContain := []string{
		// legend filter buttons (All must be first)
		`data-filter="all"`,
		`data-filter="clean"`,
		`data-filter="findings"`,
		`data-filter="high-findings"`,
		`data-filter="error"`,
		// sidebar links carry state
		`data-state="clean"`,
		`data-state="high-findings"`,
		`data-state="error"`,
		// main sections carry state
		`class="repo-section" id="o-clean" data-state="clean"`,
		`class="repo-section" id="o-high" data-state="high-findings"`,
		// filter JS with All-aware logic and init call
		`applyFilter`,
		`filter-hidden`,
		`applyFilter(active)`,
	}
	// "All" must appear before the first state filter
	allIdx := strings.Index(html, `data-filter="all"`)
	cleanIdx := strings.Index(html, `data-filter="clean"`)
	if allIdx < 0 || cleanIdx < 0 || allIdx > cleanIdx {
		t.Errorf("expected data-filter=\"all\" to appear before data-filter=\"clean\" in sidebar")
	}
	for _, want := range mustContain {
		if !strings.Contains(html, want) {
			t.Errorf("output missing %q", want)
		}
	}

	// Summary section must be gone
	for _, gone := range []string{"summary-section", "aggr-counts", "error-list"} {
		if strings.Contains(html, gone) {
			t.Errorf("output unexpectedly contains removed element %q", gone)
		}
	}
}
