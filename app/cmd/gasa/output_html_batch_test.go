package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/bretfisher/github-security-assessment/app/internal/scanner"
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
