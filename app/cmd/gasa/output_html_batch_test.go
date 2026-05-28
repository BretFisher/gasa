package main

import (
	"errors"
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
