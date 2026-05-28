package scanner

import "testing"

func TestCountBySeverity(t *testing.T) {
	r := &ScanResult{Findings: []Finding{
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityHigh},
		{Severity: SeverityMedium},
		{Severity: SeverityLow},
		{Severity: SeverityInfo},
		{Severity: SeverityInfo},
		{Severity: SeverityInfo},
	}}

	counts := r.CountBySeverity()
	if counts[SeverityCritical] != 1 {
		t.Errorf("critical = %d, want 1", counts[SeverityCritical])
	}
	if counts[SeverityHigh] != 2 {
		t.Errorf("high = %d, want 2", counts[SeverityHigh])
	}
	if counts[SeverityMedium] != 1 {
		t.Errorf("medium = %d, want 1", counts[SeverityMedium])
	}
	if counts[SeverityLow] != 1 {
		t.Errorf("low = %d, want 1", counts[SeverityLow])
	}
	if counts[SeverityInfo] != 3 {
		t.Errorf("info = %d, want 3", counts[SeverityInfo])
	}
}

func TestSeverityOrder(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{severity: SeverityCritical, want: 0},
		{severity: SeverityHigh, want: 1},
		{severity: SeverityMedium, want: 2},
		{severity: SeverityLow, want: 3},
		{severity: SeverityInfo, want: 4},
		{severity: "unknown", want: 5},
	}

	for _, tt := range tests {
		if got := SeverityOrder(tt.severity); got != tt.want {
			t.Errorf("SeverityOrder(%q) = %d, want %d", tt.severity, got, tt.want)
		}
	}
}

func TestSortFindingsDeterministicTiebreakers(t *testing.T) {
	findings := []Finding{
		{ID: "success-z", Rule: "z-rule", Severity: SeverityCritical, Success: true, Title: "success z"},
		{ID: "same-later", Rule: "workflows/workflow-permissions", Severity: SeverityHigh, File: ".github/workflows/b.yml", Line: 2, Title: "same later"},
		{ID: "same-earlier", Rule: "workflows/workflow-permissions", Severity: SeverityHigh, File: ".github/workflows/b.yml", Line: 2, Title: "same earlier"},
		{ID: "line-1", Rule: "workflows/workflow-permissions", Severity: SeverityHigh, File: ".github/workflows/b.yml", Line: 1, Title: "line 1"},
		{ID: "file-a", Rule: "workflows/workflow-permissions", Severity: SeverityHigh, File: ".github/workflows/a.yml", Line: 10, Title: "file a"},
		{ID: "critical", Rule: "updates/update-tool-configuration", Severity: SeverityCritical, Title: "critical"},
		{ID: "other-rule", Rule: "actions/permissions/workflow/default-workflow-permissions", Severity: SeverityHigh, Title: "other rule"},
		{ID: "success-a", Rule: "a-rule", Severity: SeverityCritical, Success: true, Title: "success a"},
	}

	sortFindings(findings)

	wantIDs := []string{
		"critical",
		"other-rule",
		"file-a",
		"line-1",
		"same-earlier",
		"same-later",
		"success-a",
		"success-z",
	}
	for i, want := range wantIDs {
		if findings[i].ID != want {
			t.Fatalf("findings[%d].ID = %q, want %q\nfindings=%+v", i, findings[i].ID, want, findings)
		}
	}
}

func TestNormalizeSeverities(t *testing.T) {
	got, err := normalizeSeverities([]string{"Critical", "high", "critical", " info "})
	if err != nil {
		t.Fatalf("normalizeSeverities() error: %v", err)
	}
	want := []string{SeverityCritical, SeverityHigh, SeverityInfo}
	if len(got) != len(want) {
		t.Fatalf("len(normalized) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalized[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	if _, err := normalizeSeverities([]string{"urgent"}); err == nil {
		t.Fatalf("expected error for invalid severity")
	}
}
