package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/bretfisher/github-security-assessment/internal/scanner"
	"github.com/charmbracelet/x/term"

	lipgloss "charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
)

const (
	defaultWidth      = 120
	minWidth          = 40
	outputFormatTable = "table"
	outputFormatJSON  = "json"
	outputFormatHTML  = "html"

	// HTML table label strings
	labelRule        = "Rule"
	labelCategory    = "Category"
	labelDescription = "Description"
	labelFix         = "Fix"
	labelFixURL      = "Fix URL"

	// Batch report state CSS classes
	stateClassError        = "error"
	stateClassFindings     = "findings"
	stateClassClean        = "clean"
	stateClassHighFindings = "high-findings"

	// GitHub API account type values
	githubAccountTypeOrg = "Organization"
)

func termWidth() int {
	w, _, err := term.GetSize(os.Stdout.Fd())
	if err != nil {
		return defaultWidth
	}
	if w < minWidth {
		return minWidth
	}
	return w
}

func severityStyle(severity string) lipgloss.Style {
	switch severity {
	case scanner.SeverityCritical:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.BrightWhite).Background(lipgloss.Red)
	case scanner.SeverityHigh:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Red)
	case scanner.SeverityMedium:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Yellow)
	case scanner.SeverityLow:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Cyan)
	case scanner.SeverityInfo:
		return lipgloss.NewStyle().Faint(true)
	default:
		return lipgloss.NewStyle()
	}
}

func successStyle() lipgloss.Style {
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Green)
}

func printFindingTable(f scanner.Finding, width int) {
	titleText := f.Title
	style := severityStyle(f.Severity)
	if f.Success {
		style = successStyle()
	} else {
		severity := strings.ToUpper(f.Severity)
		titleText = severity + "  " + f.Title
	}

	printLipglossLine(style.Render(titleText))

	rows := [][]string{
		{labelRule, f.Rule},
		{labelCategory, f.Category},
		{labelDescription, f.Description},
	}
	if !f.Success {
		rows = append(rows, []string{labelFix, f.Remediation})
	}
	if f.FixURL != "" {
		rows = append(rows, []string{labelFixURL, f.FixURL})
	}

	t := table.New().
		Width(width).
		Border(lipgloss.RoundedBorder()).
		BorderTop(false).
		BorderHeader(false).
		BorderRow(false).
		BorderColumn(true).
		StyleFunc(func(_, col int) lipgloss.Style {
			if col == 0 {
				return lipgloss.NewStyle().Bold(true).Width(13).Padding(0, 1)
			}
			return lipgloss.NewStyle().Padding(0, 1)
		}).
		Rows(rows...)

	printLipglossLine(t.Render())
}

func printLipglossLine(s string) {
	if _, err := lipgloss.Println(s); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing terminal output: %v\n", err)
	}
}

func printTable(result *scanner.ScanResult) {
	width := termWidth()

	fmt.Printf("Repository: %s\n", result.RepoFullName)

	counts := result.CountBySeverity()
	parts := []string{}
	if c := counts[scanner.SeverityCritical]; c > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", c))
	}
	if c := counts[scanner.SeverityHigh]; c > 0 {
		parts = append(parts, fmt.Sprintf("%d high", c))
	}
	if c := counts[scanner.SeverityMedium]; c > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", c))
	}
	if c := counts[scanner.SeverityLow]; c > 0 {
		parts = append(parts, fmt.Sprintf("%d low", c))
	}
	if c := counts[scanner.SeverityInfo]; c > 0 {
		parts = append(parts, fmt.Sprintf("%d info", c))
	}

	if len(parts) > 0 {
		fmt.Printf("Findings:   %s\n", strings.Join(parts, ", "))
	} else {
		fmt.Printf("Findings:   none\n")
	}
	if successes := result.CountSuccesses(); successes > 0 {
		fmt.Printf("Successes:  %d\n", successes)
	}
	fmt.Println()

	for i, f := range result.Findings {
		printFindingTable(f, width)
		if i < len(result.Findings)-1 {
			fmt.Println()
		}
	}
}

func printJSON(result *scanner.ScanResult) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func printRulesTable() {
	width := termWidth()
	rules := scanner.AvailableRules()

	fmt.Printf("Available rules: %d\n\n", len(rules))

	for i, rule := range rules {
		style := severityStyle(rule.Severity)
		titleText := strings.ToUpper(rule.Severity) + "  " + rule.Title
		printLipglossLine(style.Render(titleText))

		rows := [][]string{
			{labelRule, rule.Name},
			{labelCategory, rule.Category},
			{labelDescription, rule.Description},
		}
		if len(rule.Aliases) > 0 {
			rows = append(rows, []string{"Aliases", strings.Join(rule.Aliases, ", ")})
		}

		t := table.New().
			Width(width).
			Border(lipgloss.RoundedBorder()).
			BorderTop(false).
			BorderHeader(false).
			BorderRow(false).
			BorderColumn(true).
			StyleFunc(func(_, col int) lipgloss.Style {
				if col == 0 {
					return lipgloss.NewStyle().Bold(true).Width(13).Padding(0, 1)
				}
				return lipgloss.NewStyle().Padding(0, 1)
			}).
			Rows(rows...)

		printLipglossLine(t.Render())

		if i < len(rules)-1 {
			fmt.Println()
		}
	}
}

func printRulesJSON() {
	rules := scanner.AvailableRules()
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}
