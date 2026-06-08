package scanner

import (
	"fmt"
	"sort"
	"strings"
)

// Severity levels for findings
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Finding represents a single security issue found during scanning
type Finding struct {
	ID          string `json:"id"`
	Rule        string `json:"rule,omitempty"`
	Category    string `json:"category,omitempty"`
	Severity    string `json:"severity"`
	Success     bool   `json:"success"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location,omitempty"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	Remediation string `json:"remediation"`
	FixURL      string `json:"fix_url,omitempty"`
	DocURL      string `json:"doc_url,omitempty"`
}

// ScanResult holds the complete results for a repository scan
type ScanResult struct {
	RepoFullName string    `json:"repo_full_name"`
	RepoURL      string    `json:"repo_url"`
	Findings     []Finding `json:"findings"`
	ScannedAt    string    `json:"scanned_at"`
	Error        string    `json:"error,omitempty"`
}

// CountBySeverity returns counts for each severity level
func (r *ScanResult) CountBySeverity() map[string]int {
	counts := map[string]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}
	for _, f := range r.Findings {
		if f.Success {
			continue
		}
		counts[f.Severity]++
	}
	return counts
}

func (r *ScanResult) CountSuccesses() int {
	count := 0
	for _, f := range r.Findings {
		if f.Success {
			count++
		}
	}
	return count
}

// SeverityOrder returns a number for sorting (lower = more severe)
func SeverityOrder(severity string) int {
	switch severity {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	case SeverityInfo:
		return 4
	default:
		return 5
	}
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]

		if a.Success != b.Success {
			return !a.Success
		}
		if SeverityOrder(a.Severity) != SeverityOrder(b.Severity) {
			return SeverityOrder(a.Severity) < SeverityOrder(b.Severity)
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		return a.Title < b.Title
	})
}

func AvailableSeverities() []string {
	return []string{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}
}

func isValidSeverity(severity string) bool {
	switch severity {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	default:
		return false
	}
}

func normalizeSeverity(severity string) string {
	return strings.ToLower(strings.TrimSpace(severity))
}

func normalizeSeverities(severities []string) ([]string, error) {
	if len(severities) == 0 {
		return nil, nil
	}

	normalized := make([]string, 0, len(severities))
	seen := make(map[string]bool, len(severities))
	for _, severity := range severities {
		normalizedSeverity := normalizeSeverity(severity)
		if !isValidSeverity(normalizedSeverity) {
			return nil, fmt.Errorf("unknown severity %q", severity)
		}
		if seen[normalizedSeverity] {
			continue
		}
		seen[normalizedSeverity] = true
		normalized = append(normalized, normalizedSeverity)
	}

	return normalized, nil
}
