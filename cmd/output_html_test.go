package cmd

import (
	"regexp"
	"strings"
	"testing"

	"github.com/bretfisher/gasa/internal/scanner"
)

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// styleInlineCode strips Markdown backticks and colours the code span. The
// colour is profile-dependent, so the deterministic contract — verified here
// after stripping ANSI — is: backticks removed, code text preserved in place,
// nothing left behind.
func TestStyleInlineCode(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text unchanged", "no code here", "no code here"},
		{"inline span stripped", "Add a `permissions:` block", "Add a permissions: block"},
		{"multiple spans", "use `a` and `b`", "use a and b"},
		{"fenced block", "x\n```yaml\nk: v\n```\ny", "x\nk: v\ny"},
		{"unmatched backtick kept", "a `lonely tick", "a `lonely tick"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ansiRE.ReplaceAllString(styleInlineCode(tt.in), "")
			if got != tt.want {
				t.Fatalf("styleInlineCode(%q) (ANSI-stripped) = %q, want %q", tt.in, got, tt.want)
			}
			if strings.Contains(got, "`") && tt.name != "unmatched backtick kept" {
				t.Errorf("styleInlineCode(%q) left a literal backtick: %q", tt.in, got)
			}
		})
	}
}

func TestMarkdownCodeToHTML(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "plain text is escaped, no code",
			in:   "use a <permissions> block & go",
			want: "use a &lt;permissions&gt; block &amp; go",
		},
		{
			name: "inline code becomes code element",
			in:   "Start with `permissions: {}` today",
			want: "Start with <code>permissions: {}</code> today",
		},
		{
			name: "multiple inline spans",
			in:   "set `permissions` not `pull_request_target`",
			want: "set <code>permissions</code> not <code>pull_request_target</code>",
		},
		{
			name: "code content is html-escaped",
			in:   "render `a < b && c` safely",
			want: "render <code>a &lt; b &amp;&amp; c</code> safely",
		},
		{
			name: "fenced block with language token",
			in:   "before\n```yaml\npermissions: {}\n```\nafter",
			want: "before\n<pre><code>permissions: {}</code></pre>\nafter",
		},
		{
			name: "unmatched backtick is literal",
			in:   "a `lonely backtick",
			want: "a `lonely backtick",
		},
		{
			name: "empty string",
			in:   "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(markdownCodeToHTML(tt.in)); got != tt.want {
				t.Fatalf("markdownCodeToHTML(%q) =\n  %q\nwant\n  %q", tt.in, got, tt.want)
			}
		})
	}
}

// A finding whose copy carries inline code must render as a styled <code>
// element in the HTML report, not literal backticks.
func TestPrintHTML_RendersInlineCode(t *testing.T) {
	result := &scanner.ScanResult{
		RepoFullName: "owner/repo",
		Findings: []scanner.Finding{{
			ID:          "no-permissions",
			Severity:    scanner.SeverityHigh,
			Rule:        "workflows/workflow-permissions",
			Category:    "Workflows",
			Title:       "No explicit permissions defined",
			Description: "This workflow inherits broad defaults.",
			Remediation: "Add a `permissions:` block; start with `permissions: {}`.",
		}},
	}
	out := captureStdout(t, func() {
		if err := printHTML(result); err != nil {
			t.Fatalf("printHTML() error = %v", err)
		}
	})
	for _, want := range []string{
		"<code>permissions:</code>",
		"<code>permissions: {}</code>",
		"pre code { background", // the code styling is present
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML output missing %q", want)
		}
	}
	// The raw backtick form must not survive into the rendered fix text.
	if strings.Contains(out, "`permissions:`") {
		t.Errorf("HTML output still contains literal backticks")
	}
}
