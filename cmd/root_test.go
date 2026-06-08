package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bretfisher/github-security-assessment/internal/scanner"
	"github.com/charmbracelet/colorprofile"

	lipgloss "charm.land/lipgloss/v2"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	originalStdout := os.Stdout
	originalWriter := lipgloss.Writer

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error: %v", err)
	}
	os.Stdout = w
	lipgloss.Writer = colorprofile.NewWriter(w, os.Environ())

	fn()

	_ = w.Close()
	os.Stdout = originalStdout
	lipgloss.Writer = originalWriter

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("io.Copy() error: %v", err)
	}
	_ = r.Close()
	return buf.String()
}

func TestPrintJSON(t *testing.T) {
	result := &scanner.ScanResult{
		RepoFullName: "owner/repo",
		RepoURL:      "https://github.com/owner/repo",
		Findings: []scanner.Finding{{
			ID:          "test-finding",
			Success:     false,
			Severity:    scanner.SeverityHigh,
			Title:       "High risk finding",
			Description: "Description",
			Remediation: "Fix it",
			FixURL:      "https://github.com/owner/repo/settings/actions",
		}},
	}

	output := captureStdout(t, func() {
		printJSON(result)
	})

	var parsed scanner.ScanResult
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("json.Unmarshal() error: %v\noutput=%s", err, output)
	}
	if parsed.RepoFullName != result.RepoFullName {
		t.Fatalf("RepoFullName = %s, want %s", parsed.RepoFullName, result.RepoFullName)
	}
	if len(parsed.Findings) != 1 || parsed.Findings[0].FixURL != result.Findings[0].FixURL {
		t.Fatalf("parsed findings = %+v", parsed.Findings)
	}
	if parsed.Findings[0].Success {
		t.Fatalf("parsed success = true, want false")
	}
}

func TestPrintHTML(t *testing.T) {
	result := &scanner.ScanResult{
		RepoFullName: "owner/repo",
		Findings: []scanner.Finding{{
			ID:          "test-finding",
			Rule:        "workflows/action-version-pinning",
			Category:    "Workflows",
			Success:     false,
			Severity:    scanner.SeverityHigh,
			Title:       "High risk finding",
			Description: "This is bad",
			Remediation: "Fix it",
			FixURL:      "https://github.com/owner/repo/blob/main/.github/workflows/ci.yml#L12",
		}},
	}

	output := captureStdout(t, func() {
		if err := printHTML(result); err != nil {
			t.Fatalf("printHTML() error: %v", err)
		}
	})

	checks := []string{
		"<!doctype html>",
		"owner/repo - gasa report",
		"HIGH  High risk finding",
		"workflows/action-version-pinning",
		"Fix URL",
		"href=\"https://github.com/owner/repo/blob/main/.github/workflows/ci.yml#L12\"",
		">owner/repo/blob/main/.github/workflows/ci.yml#L12<",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Fatalf("output missing %q\n%s", check, output)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestRenderHTMLTemplateReturnsWriteError(t *testing.T) {
	err := renderHTMLTemplate(failingWriter{}, htmlResultTemplate, htmlResultView{RepoFullName: "owner/repo"})
	if err == nil {
		t.Fatal("expected render error")
	}
	if !strings.Contains(err.Error(), "rendering HTML") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrintTable(t *testing.T) {
	result := &scanner.ScanResult{
		RepoFullName: "owner/repo",
		Findings: []scanner.Finding{{
			ID:          "test-finding",
			Rule:        "workflows/action-version-pinning",
			Category:    "Workflows",
			Success:     false,
			Severity:    scanner.SeverityHigh,
			Title:       "High risk finding",
			Description: "This is bad",
			File:        ".github/workflows/ci.yml",
			Line:        12,
			Remediation: "Fix it",
			FixURL:      "https://github.com/owner/repo/blob/main/.github/workflows/ci.yml#L12",
		}},
	}

	output := captureStdout(t, func() {
		printTable(result)
	})

	checks := []string{
		"Repository: owner/repo",
		"Findings:   1 high",
		"HIGH  High risk finding",
		"Rule",
		"workflows/action-version-pinning",
		"Category",
		"Workflows",
		"Description",
		"This is bad",
		"Fix",
		"Fix it",
		"Fix URL",
		"https://github.com/owner/repo/blob/main/.github/workflows/ci.yml#L12",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Fatalf("output missing %q\n%s", check, output)
		}
	}
}

func TestPrintTableNoFindings(t *testing.T) {
	result := &scanner.ScanResult{RepoFullName: "owner/repo", Findings: []scanner.Finding{}}
	output := captureStdout(t, func() {
		printTable(result)
	})
	if !strings.Contains(output, "Findings:   none") {
		t.Fatalf("output missing no findings line\n%s", output)
	}
}

func TestPrintRulesTable(t *testing.T) {
	output := captureStdout(t, func() {
		printRulesTable()
	})
	checks := []string{
		"Available rules: 10",
		"workflows/pull-request-target",
		"actions/permissions/allowed-actions-policy",
		"updates/update-tool-configuration",
		"updates/update-tool-actions-cooldown",
		"Pull Request Target",
		"Aliases",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Fatalf("output missing %q\n%s", check, output)
		}
	}
}

func TestPrintRulesJSON(t *testing.T) {
	output := captureStdout(t, func() {
		printRulesJSON()
	})
	var rules []scanner.RuleInfo
	if err := json.Unmarshal([]byte(output), &rules); err != nil {
		t.Fatalf("json.Unmarshal() error: %v\noutput=%s", err, output)
	}
	if len(rules) != 10 {
		t.Fatalf("len(rules) = %d, want 10", len(rules))
	}
	if rules[0].Name == "" {
		t.Fatal("expected populated rule names")
	}
}

func TestPrintRulesHTML(t *testing.T) {
	output := captureStdout(t, func() {
		if err := printRulesHTML(); err != nil {
			t.Fatalf("printRulesHTML() error: %v", err)
		}
	})
	checks := []string{
		"<!doctype html>",
		"Available Rules",
		"workflows/pull-request-target",
		"Pull Request Target",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Fatalf("output missing %q\n%s", check, output)
		}
	}
}

func TestRenderBatchHTMLUsesGenericTitle(t *testing.T) {
	view := buildBatchView([]batchRepoResult{
		{RepoFullName: "owner-one/repo-a", Result: &scanner.ScanResult{RepoFullName: "owner-one/repo-a"}},
		{RepoFullName: "owner-two/repo-b", Result: &scanner.ScanResult{RepoFullName: "owner-two/repo-b"}},
	})
	var buf bytes.Buffer
	if err := renderHTMLTemplate(&buf, htmlBatchTemplate, view); err != nil {
		t.Fatalf("renderHTMLTemplate() error: %v", err)
	}

	output := buf.String()
	checks := []string{
		"<title>GitHub Actions Security Assessment Batch Report</title>",
		"<h1>GitHub Actions Security Assessment Batch Report</h1>",
		"owner-one/repo-a",
		"owner-two/repo-b",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Fatalf("output missing %q\n%s", check, output)
		}
	}
	if strings.Contains(output, "owner-one &mdash;") || strings.Contains(output, "owner-two &mdash;") {
		t.Fatalf("output unexpectedly used an owner-specific report title\n%s", output)
	}
}

func TestValidateOutputFormat(t *testing.T) {
	for _, format := range []string{outputFormatTable, outputFormatJSON, outputFormatHTML} {
		if err := validateOutputFormat(format); err != nil {
			t.Fatalf("validateOutputFormat(%q) unexpected error: %v", format, err)
		}
	}
	if err := validateOutputFormat("yaml"); err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestValidateTimeout(t *testing.T) {
	if err := validateTimeout(time.Second); err != nil {
		t.Fatalf("validateTimeout(time.Second) unexpected error: %v", err)
	}
	if err := validateTimeout(0); err == nil {
		t.Fatal("expected error for zero timeout")
	}
	if err := validateTimeout(-time.Second); err == nil {
		t.Fatal("expected error for negative timeout")
	}
}

func TestBuildScanRequest(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		opts    scanCommandOptions
		want    scanRequest
		wantErr string
	}{
		{
			name: "explicit repo",
			args: []string{"owner/repo"},
			opts: scanCommandOptions{
				Format:         outputFormatJSON,
				Rules:          []string{"workflows/action-version-pinning"},
				Categories:     []string{"workflows"},
				Severities:     []string{"high"},
				IncludeSuccess: true,
				Debug:          true,
				Timeout:        time.Minute,
				TokenStdin:     true,
				ConfigPath:     ".gasa.yml",
				WorkDir:        ".",
			},
			want: scanRequest{
				Owner:          "owner",
				Repo:           "repo",
				Format:         outputFormatJSON,
				Rules:          []string{"workflows/action-version-pinning"},
				Categories:     []string{"workflows"},
				Severities:     []string{"high"},
				IncludeSuccess: true,
				Debug:          true,
				Timeout:        time.Minute,
				TokenStdin:     true,
				ConfigPath:     ".gasa.yml",
			},
		},
		{
			name:    "invalid format",
			args:    []string{"owner/repo"},
			opts:    scanCommandOptions{Format: "yaml", Timeout: time.Minute, WorkDir: "."},
			wantErr: "invalid --format",
		},
		{
			name:    "invalid repo",
			args:    []string{"bad owner/repo"},
			opts:    scanCommandOptions{Format: outputFormatTable, Timeout: time.Minute, WorkDir: "."},
			wantErr: "invalid GitHub owner",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildScanRequest(context.Background(), tt.args, tt.opts)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("buildScanRequest() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildScanRequest() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("buildScanRequest() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestResolveTokenFromStdin(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")

	token, source, err := resolveToken(context.Background(), true, strings.NewReader(" ghp_test\n"))
	if err != nil {
		t.Fatalf("resolveToken() error = %v", err)
	}
	if token != "ghp_test" || source != "using token from stdin" {
		t.Fatalf("resolveToken() = %q, %q", token, source)
	}
}

func TestResolveTokenFromStdinEmpty(t *testing.T) {
	_, _, err := resolveToken(context.Background(), true, strings.NewReader("\n"))
	if err == nil {
		t.Fatal("expected error for empty stdin token")
	}
	if !strings.Contains(err.Error(), "--token-stdin") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveTokenEnvironmentOrder(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "github-token")
	t.Setenv("GH_TOKEN", "gh-token")

	token, source, err := resolveToken(context.Background(), false, strings.NewReader(""))
	if err != nil {
		t.Fatalf("resolveToken() error = %v", err)
	}
	if token != "github-token" || source != "using token from GITHUB_TOKEN" {
		t.Fatalf("resolveToken() = %q, %q", token, source)
	}
}

func TestRunCommand_RuleAndSeverityMutuallyExclusive(t *testing.T) {
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{"run", "--rule", "action-pinning", "--severity", "high", "owner/repo"})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		flagRules = nil
		flagCategories = nil
		flagSeverities = nil
		flagTokenStdin = false
	})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for mutually exclusive flags")
	}
	if !strings.Contains(err.Error(), "if any flags in the group [rule severity] are set none of the others can be") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunBatchScans_UsesCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results := runBatchScans(ctx, []string{"owner/repo"}, scanner.New(), nil, 1, batchScanOptions{
		OutputFormat: outputFormatJSON,
		Timeout:      time.Minute,
	})
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].Err == nil && (results[0].Result == nil || results[0].Result.Error == "") {
		t.Fatalf("expected canceled scan to fail, got %+v", results[0])
	}
}

func TestInferRepoFromGitRemote(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	gitCmd := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	gitCmd("init")
	gitCmd("remote", "add", "origin", "git@github.com:owner/repo.git")

	owner, repo, err := inferRepoFromGitRemote(context.Background(), dir)
	if err != nil {
		t.Fatalf("inferRepoFromGitRemote() error: %v", err)
	}
	if owner != "owner" || repo != "repo" {
		t.Fatalf("inferRepoFromGitRemote() = %s/%s, want owner/repo", owner, repo)
	}
}

func TestInferRepoFromGitRemote_NoOrigin(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	cmd := exec.Command("git", "init")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v\n%s", err, out)
	}

	_, _, err := inferRepoFromGitRemote(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error when origin remote is missing")
	}
	if !strings.Contains(err.Error(), "is not a git clone with a github remote") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInferRepoFromGitRemote_NonGitHubOrigin(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	gitCmd := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	gitCmd("init")
	gitCmd("remote", "add", "origin", "https://gitlab.com/owner/repo.git")

	_, _, err := inferRepoFromGitRemote(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for non-github origin")
	}
	if !strings.Contains(err.Error(), "is not a git clone with a github remote") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrintTable_WithSuccesses(t *testing.T) {
	result := &scanner.ScanResult{
		RepoFullName: "owner/repo",
		Findings: []scanner.Finding{{
			ID:          "success-workflows-action-version-pinning",
			Rule:        "workflows/action-version-pinning",
			Severity:    scanner.SeverityHigh,
			Success:     true,
			Title:       "SUCCESS Action versions are pinned safely",
			Description: "All detected third-party actions are pinned to immutable commit SHAs instead of mutable tags or branches.",
			Category:    "Workflows",
			Remediation: "No action needed.",
		}},
	}

	output := captureStdout(t, func() {
		printTable(result)
	})

	checks := []string{
		"Findings:   none",
		"Successes:  1",
		"SUCCESS Action versions are pinned safely",
		"Rule",
		"workflows/action-version-pinning",
		"Category",
		"Description",
		"Workflows",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Fatalf("output missing %q\n%s", check, output)
		}
	}
	if strings.Contains(output, "No action needed.") {
		t.Fatalf("success output unexpectedly included fix text\n%s", output)
	}
}
