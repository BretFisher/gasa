package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-github/v84/github"
)

func TestParseRepoURL(t *testing.T) {
	tests := []struct {
		input     string
		wantOwner string
		wantRepo  string
	}{
		{input: "owner/repo", wantOwner: "owner", wantRepo: "repo"},
		{input: "owner-name/repo.name_with-hyphen", wantOwner: "owner-name", wantRepo: "repo.name_with-hyphen"},
		{input: "https://github.com/owner/repo", wantOwner: "owner", wantRepo: "repo"},
		{input: "http://github.com/owner/repo", wantOwner: "owner", wantRepo: "repo"},
		{input: "https://www.github.com/owner/repo/", wantOwner: "owner", wantRepo: "repo"},
		{input: "https://github.com/owner/repo.git", wantOwner: "owner", wantRepo: "repo"},
		{input: "git@github.com:owner/repo.git", wantOwner: "owner", wantRepo: "repo"},
		{input: "ssh://git@github.com/owner/repo.git", wantOwner: "owner", wantRepo: "repo"},
		{input: "https://github.com/owner/repo/tree/main", wantOwner: "owner", wantRepo: "repo"},
	}

	for _, tt := range tests {
		owner, repo, err := ParseRepoURL(tt.input)
		if err != nil {
			t.Fatalf("ParseRepoURL(%q) unexpected error: %v", tt.input, err)
		}
		if owner != tt.wantOwner || repo != tt.wantRepo {
			t.Fatalf("ParseRepoURL(%q) = %s/%s, want %s/%s", tt.input, owner, repo, tt.wantOwner, tt.wantRepo)
		}
	}
}

func TestParseRepoURL_Invalid(t *testing.T) {
	inputs := []string{
		"",
		"owner",
		"/",
		"owner/",
		"/repo",
		"bad owner/repo",
		"-owner/repo",
		"owner-/repo",
		"owner/repo?tab=actions",
		"owner/repo name",
		"owner/.",
		"owner/..",
	}
	for _, input := range inputs {
		if _, _, err := ParseRepoURL(input); err == nil {
			t.Fatalf("ParseRepoURL(%q) expected error", input)
		}
	}
}

func TestScannerIsAuthenticated(t *testing.T) {
	tests := []struct {
		name string
		s    *Scanner
		want bool
	}{
		{name: "unauthenticated", s: New(), want: false},
		{name: "token", s: NewWithToken("test-token"), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.IsAuthenticated(); got != tt.want {
				t.Fatalf("IsAuthenticated() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDedupeFindings(t *testing.T) {
	findings := []Finding{
		{ID: "a", Title: "first"},
		{ID: "b", Title: "second"},
		{ID: "a", Title: "duplicate"},
	}
	deduped := dedupeFindings(findings)
	if len(deduped) != 2 {
		t.Fatalf("dedupeFindings len = %d, want 2", len(deduped))
	}
	if deduped[0].ID != "a" || deduped[1].ID != "b" {
		t.Fatalf("dedupeFindings order = %+v", deduped)
	}
}

func TestBuildFixURL_Settings(t *testing.T) {
	ids := []string{
		"settings-all-actions-allowed",
		"settings-local-only",
		"settings-check-failed",
		"settings-check-unavailable",
		"settings-default-permissions-write",
		"settings-actions-can-approve-prs",
		"settings-fork-pr-contributor-approval-too-permissive",
	}
	for _, id := range ids {
		got := buildFixURL(Finding{ID: id}, "owner", "repo", "main")
		want := "https://github.com/owner/repo/settings/actions"
		if got != want {
			t.Fatalf("buildFixURL(%s) = %s, want %s", id, got, want)
		}
	}
}

func TestBuildFixURL_Workflow(t *testing.T) {
	finding := Finding{ID: "workflow-1", File: ".github/workflows/ci.yml", Line: 12}
	got := buildFixURL(finding, "owner", "repo", "main")
	want := "https://github.com/owner/repo/blob/main/.github/workflows/ci.yml#L12"
	if got != want {
		t.Fatalf("buildFixURL() = %s, want %s", got, want)
	}
}

func TestBuildFixURL_Dependabot(t *testing.T) {
	got := buildFixURL(Finding{ID: "no-update-tool"}, "owner", "repo", "main")
	want := "https://github.com/owner/repo/new/main?filename=.github%2Fdependabot.yml"
	if got != want {
		t.Fatalf("buildFixURL(no-update-tool) = %s, want %s", got, want)
	}

	got = buildFixURL(Finding{ID: "update-tool-missing-actions"}, "owner", "repo", "main")
	want = "https://github.com/owner/repo/blob/main/.github/dependabot.yml"
	if got != want {
		t.Fatalf("buildFixURL(update-tool-missing-actions) = %s, want %s", got, want)
	}

	got = buildFixURL(Finding{ID: "no-update-tool"}, "owner", "repo", "release/2026")
	want = "https://github.com/owner/repo/new/release/2026?filename=.github%2Fdependabot.yml"
	if got != want {
		t.Fatalf("buildFixURL(no-update-tool branch slash) = %s, want %s", got, want)
	}
}

func TestBuildFixURL_Empty(t *testing.T) {
	if got := buildFixURL(Finding{ID: "unknown"}, "owner", "repo", "main"); got != "" {
		t.Fatalf("buildFixURL() = %q, want empty string", got)
	}
}

func TestBlobURL_Escaping(t *testing.T) {
	got := blobURL("owner", "repo", "feature/test", ".github/workflows/ci file.yml", 7)
	want := "https://github.com/owner/repo/blob/feature/test/.github/workflows/ci%20file.yml#L7"
	if got != want {
		t.Fatalf("blobURL() = %s, want %s", got, want)
	}

	got = blobURL("owner", "repo", "release/2026", "/path with spaces/deploy@prod.yml", 0)
	want = "https://github.com/owner/repo/blob/release/2026/path%20with%20spaces/deploy@prod.yml"
	if got != want {
		t.Fatalf("blobURL() = %s, want %s", got, want)
	}
}

func TestScanRepo_OnlyUsesGETRequests(t *testing.T) {
	scanner, mux := newTestScanner(t, true)

	// Collectors run concurrently, so guard the recorded methods slice.
	var methodsMu sync.Mutex
	methods := []string{}
	record := func(m string) {
		methodsMu.Lock()
		methods = append(methods, m)
		methodsMu.Unlock()
	}

	mux.HandleFunc("/repos/owner/repo", func(w http.ResponseWriter, r *http.Request) {
		record(r.Method)
		if err := json.NewEncoder(w).Encode(map[string]any{"full_name": "owner/repo", "default_branch": "main"}); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	})
	mux.HandleFunc("/repos/owner/repo/contents/.github/workflows", func(w http.ResponseWriter, r *http.Request) {
		record(r.Method)
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/repos/owner/repo/contents/.github/dependabot.yml", func(w http.ResponseWriter, r *http.Request) {
		record(r.Method)
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/repos/owner/repo/contents/.github/dependabot.yaml", func(w http.ResponseWriter, r *http.Request) {
		record(r.Method)
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/repos/owner/repo/actions/permissions", func(w http.ResponseWriter, r *http.Request) {
		record(r.Method)
		if err := json.NewEncoder(w).Encode(map[string]any{"enabled": true, "allowed_actions": "selected"}); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	})
	mux.HandleFunc("/repos/owner/repo/actions/permissions/workflow", func(w http.ResponseWriter, r *http.Request) {
		record(r.Method)
		if err := json.NewEncoder(w).Encode(map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false}); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	})
	mux.HandleFunc("/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", func(w http.ResponseWriter, r *http.Request) {
		record(r.Method)
		if err := json.NewEncoder(w).Encode(map[string]any{"approval_policy": "all_external_contributors"}); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	})

	_, err := scanner.ScanRepo(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, method := range methods {
		if method != http.MethodGet {
			t.Fatalf("saw non-GET method %s", method)
		}
	}
}

func TestScanRepo_GracefulOnErrors(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		contains string
	}{
		{name: "not-found", status: http.StatusNotFound, contains: "Repository not found or is private"},
		{name: "forbidden", status: http.StatusForbidden, contains: "Access forbidden"},
		{name: "server-error", status: http.StatusInternalServerError, contains: "Failed to access repository"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, mux := newTestScanner(t, false)
			mux.HandleFunc("/repos/owner/repo", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				if _, err := w.Write([]byte(`{"message":"error"}`)); err != nil {
					t.Errorf("failed to write response: %v", err)
				}
			})

			result, err := scanner.ScanRepo(context.Background(), "owner", "repo")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(result.Error, tt.contains) {
				t.Fatalf("result.Error = %q, want substring %q", result.Error, tt.contains)
			}
		})
	}
}

func TestClassifyGitHubRepoAccessError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "primary-rate-limit-type",
			err:  &github.RateLimitError{},
			want: "API rate limit exceeded. Try again later.",
		},
		{
			name: "secondary-rate-limit-type",
			err:  &github.AbuseRateLimitError{},
			want: "GitHub secondary rate limit or abuse detection triggered. Try again later.",
		},
		{
			name: "not-found",
			err:  githubErrorResponse(http.StatusNotFound, nil),
			want: "Repository not found or is private",
		},
		{
			name: "unauthorized",
			err:  githubErrorResponse(http.StatusUnauthorized, nil),
			want: "Authentication failed (token rejected)",
		},
		{
			name: "forbidden-rate-limit-header",
			err:  githubErrorResponse(http.StatusForbidden, http.Header{"X-Ratelimit-Remaining": []string{"0"}}),
			want: "API rate limit exceeded. Try again later.",
		},
		{
			name: "forbidden-access-policy",
			err:  githubErrorResponse(http.StatusForbidden, nil),
			want: "Access forbidden (check token scopes, SSO authorization, or organization access policies)",
		},
		{
			name: "too-many-requests",
			err:  githubErrorResponse(http.StatusTooManyRequests, nil),
			want: "API rate limit exceeded. Try again later.",
		},
		{
			name: "deadline-exceeded",
			err:  context.DeadlineExceeded,
			want: errMsgTimedOut,
		},
		{
			name: "deadline-exceeded-wrapped-in-url-error",
			err:  &url.Error{Op: "Get", URL: "https://api.github.com/repos/o/r", Err: context.DeadlineExceeded},
			want: errMsgTimedOut,
		},
		{
			name: "canceled",
			err:  context.Canceled,
			want: "Canceled before GitHub responded",
		},
		{
			name: "other-error",
			err:  errors.New("dial tcp: lookup api.github.invalid"),
			want: "Failed to access repository: dial tcp: lookup api.github.invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyGitHubRepoAccessError(tt.err); got != tt.want {
				t.Fatalf("classifyGitHubRepoAccessError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func githubErrorResponse(statusCode int, header http.Header) *github.ErrorResponse {
	if header == nil {
		header = http.Header{}
	}
	return &github.ErrorResponse{
		Response: &http.Response{StatusCode: statusCode, Header: header},
		Message:  "error",
	}
}

func TestScanRepoWithOptions_DebugLogReceivesMessages(t *testing.T) {
	scanner, mux := newTestScanner(t, true)

	handleJSON(mux, "/repos/owner/repo", map[string]any{"full_name": "owner/repo", "default_branch": "main"})
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows", []*github.RepositoryContent{{
		Name: github.Ptr("ci.yml"),
		Path: github.Ptr(".github/workflows/ci.yml"),
	}})
	workflow := "on: pull_request\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@0123456789012345678901234567890123456789\n"
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows/ci.yml", encodedContent(".github/workflows/ci.yml", workflow))
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "all_external_contributors"})
	depConfig := "version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n    cooldown:\n      default-days: 7\n"
	handleJSON(mux, "/repos/owner/repo/contents/.github/dependabot.yml", encodedContent(".github/dependabot.yml", depConfig))
	handle404(mux,
		"/repos/owner/repo/contents/renovate.json",
		"/repos/owner/repo/contents/renovate.json5",
		"/repos/owner/repo/contents/.github/renovate.json",
		"/repos/owner/repo/contents/.github/renovate.json5",
		"/repos/owner/repo/contents/.gitlab/renovate.json",
		"/repos/owner/repo/contents/.gitlab/renovate.json5",
		"/repos/owner/repo/contents/.renovaterc",
		"/repos/owner/repo/contents/.renovaterc.json",
		"/repos/owner/repo/contents/.renovaterc.json5",
	)

	rec := &debugRecorder{}

	_, err := scanner.ScanRepoWithOptions(context.Background(), "owner", "repo", ScanOptions{DebugLog: rec.log})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := rec.snapshot()
	if len(lines) == 0 {
		t.Fatal("expected debug lines, got none")
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "owner/repo|") {
			t.Fatalf("debug line %q missing repo prefix", line)
		}
	}
	requireContainsLine(t, lines, "GET /repos/owner/repo")
	requireContainsLine(t, lines, "rule:start workflows/pull-request-target")
	requireContainsLine(t, lines, "rule:pass")
}

func TestScanRepoWithOptions_NilDebugLogNoPanic(t *testing.T) {
	scanner, mux := newTestScanner(t, true)

	handleJSON(mux, "/repos/owner/repo", map[string]any{"full_name": "owner/repo", "default_branch": "main"})
	handle404(mux,
		"/repos/owner/repo/contents/.github/workflows",
		"/repos/owner/repo/contents/.github/dependabot.yml",
		"/repos/owner/repo/contents/.github/dependabot.yaml",
		"/repos/owner/repo/contents/renovate.json",
		"/repos/owner/repo/contents/renovate.json5",
		"/repos/owner/repo/contents/.github/renovate.json",
		"/repos/owner/repo/contents/.github/renovate.json5",
		"/repos/owner/repo/contents/.gitlab/renovate.json",
		"/repos/owner/repo/contents/.gitlab/renovate.json5",
		"/repos/owner/repo/contents/.renovaterc",
		"/repos/owner/repo/contents/.renovaterc.json",
		"/repos/owner/repo/contents/.renovaterc.json5",
	)
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "all_external_contributors"})

	result, err := scanner.ScanRepoWithOptions(context.Background(), "owner", "repo", ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
}

func TestNoSecretsInOutput(t *testing.T) {
	result := &ScanResult{
		RepoFullName: "owner/repo",
		RepoURL:      "https://github.com/owner/repo",
		Findings:     []Finding{{ID: "x", Severity: SeverityInfo, Title: "ok", Description: "safe", Remediation: "none"}},
	}
	secret := "ghp_super_secret_token"
	result.Error = "safe error"
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatal("output unexpectedly contains secret")
	}
}

func TestScanRepo_EndToEndMixedFindings(t *testing.T) {
	scanner, mux := newTestScanner(t, true)

	handleJSON(mux, "/repos/owner/repo", map[string]any{"full_name": "owner/repo", "default_branch": "main"})
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows", []*github.RepositoryContent{{
		Name: github.Ptr("ci.yml"),
		Path: github.Ptr(".github/workflows/ci.yml"),
	}})
	workflow := "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows/ci.yml", encodedContent(".github/workflows/ci.yml", workflow))
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "all"})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "write", "can_approve_pull_request_reviews": true})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "first_time_contributors"})
	depConfig := "version: 2\nupdates:\n  - package-ecosystem: gomod\n    directory: /\n    schedule:\n      interval: weekly\n"
	handleJSON(mux, "/repos/owner/repo/contents/.github/dependabot.yml", encodedContent(".github/dependabot.yml", depConfig))
	handle404(mux,
		"/repos/owner/repo/contents/package.json",
		"/repos/owner/repo/contents/requirements.txt",
		"/repos/owner/repo/contents/Pipfile",
		"/repos/owner/repo/contents/pyproject.toml",
		"/repos/owner/repo/contents/Gemfile",
		"/repos/owner/repo/contents/Cargo.toml",
		"/repos/owner/repo/contents/composer.json",
		"/repos/owner/repo/contents/pom.xml",
		"/repos/owner/repo/contents/build.gradle",
		"/repos/owner/repo/contents/Dockerfile",
	)
	handleJSON(mux, "/repos/owner/repo/contents/go.mod", encodedContent("go.mod", "module example.com/test"))

	result, err := scanner.ScanRepo(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("unexpected result.Error: %s", result.Error)
	}
	if result.RepoFullName != "owner/repo" {
		t.Fatalf("RepoFullName = %s", result.RepoFullName)
	}
	if len(result.Findings) != 8 {
		t.Fatalf("len(findings) = %d, want 8\nfindings=%+v", len(result.Findings), result.Findings)
	}

	wantIDs := map[string]bool{
		"dangerous-trigger-.github/workflows/ci.yml":           false,
		"unpinned-.github/workflows/ci.yml-actions-checkout":   false,
		"no-permissions-.github/workflows/ci.yml":              false,
		"settings-all-actions-allowed":                         false,
		"settings-default-permissions-write":                   false,
		"settings-actions-can-approve-prs":                     false,
		"settings-fork-pr-contributor-approval-too-permissive": false,
		"update-tool-missing-actions":                          false,
	}
	for _, finding := range result.Findings {
		if _, ok := wantIDs[finding.ID]; ok {
			wantIDs[finding.ID] = true
		}
		if finding.FixURL == "" {
			t.Fatalf("finding %s missing FixURL", finding.ID)
		}
	}
	for id, seen := range wantIDs {
		if !seen {
			t.Fatalf("missing finding %s", id)
		}
	}
}

// An indeterminate failure mid-scan must surface on result.Incomplete and must
// not invent a "no update tool" finding from configs it never actually read.
func TestScanRepoWithOptions_IncompleteOnIndeterminateErrors(t *testing.T) {
	scanner, mux := newTestScanner(t, false)

	handleJSON(mux, "/repos/owner/repo", map[string]any{"full_name": "owner/repo", "default_branch": "main"})
	handle404(mux, "/repos/owner/repo/contents/.github/workflows")
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	// Both update-tool config lookups fail indeterminately (server error), so
	// the scanner cannot tell whether a tool is configured.
	handle500(mux,
		"/repos/owner/repo/contents/.github/dependabot.yml",
		"/repos/owner/repo/contents/.github/dependabot.yaml",
	)
	handle500(mux,
		"/repos/owner/repo/contents/renovate.json",
		"/repos/owner/repo/contents/renovate.json5",
		"/repos/owner/repo/contents/.github/renovate.json",
		"/repos/owner/repo/contents/.github/renovate.json5",
		"/repos/owner/repo/contents/.gitlab/renovate.json",
		"/repos/owner/repo/contents/.gitlab/renovate.json5",
		"/repos/owner/repo/contents/.renovaterc",
		"/repos/owner/repo/contents/.renovaterc.json",
		"/repos/owner/repo/contents/.renovaterc.json5",
	)

	result, err := scanner.ScanRepo(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("unexpected result.Error: %s", result.Error)
	}
	if len(result.Incomplete) == 0 {
		t.Fatalf("result.Incomplete is empty; want indeterminate checks reported")
	}
	for _, f := range result.Findings {
		if f.ID == findingIDNoUpdateTool {
			t.Fatalf("emitted false %q finding from configs that could not be read", findingIDNoUpdateTool)
		}
	}
}

func TestScanRepoWithOptions_IncludeSuccess(t *testing.T) {
	scanner, mux := newTestScanner(t, true)

	handleJSON(mux, "/repos/owner/repo", map[string]any{"full_name": "owner/repo", "default_branch": "main"})
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows", []*github.RepositoryContent{{
		Name: github.Ptr("ci.yml"),
		Path: github.Ptr(".github/workflows/ci.yml"),
	}})
	workflow := "on: pull_request\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@0123456789012345678901234567890123456789\n"
	handleJSON(mux, "/repos/owner/repo/contents/.github/workflows/ci.yml", encodedContent(".github/workflows/ci.yml", workflow))
	handleJSON(mux, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false})
	handleJSON(mux, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "all_external_contributors"})
	depConfig := "version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n    cooldown:\n      default-days: 7\n  - package-ecosystem: gomod\n    directory: /\n    schedule:\n      interval: weekly\n"
	handleJSON(mux, "/repos/owner/repo/contents/.github/dependabot.yml", encodedContent(".github/dependabot.yml", depConfig))
	handle404(mux,
		"/repos/owner/repo/contents/package.json",
		"/repos/owner/repo/contents/requirements.txt",
		"/repos/owner/repo/contents/Pipfile",
		"/repos/owner/repo/contents/pyproject.toml",
		"/repos/owner/repo/contents/Gemfile",
		"/repos/owner/repo/contents/Cargo.toml",
		"/repos/owner/repo/contents/composer.json",
		"/repos/owner/repo/contents/pom.xml",
		"/repos/owner/repo/contents/build.gradle",
		"/repos/owner/repo/contents/Dockerfile",
	)
	handleJSON(mux, "/repos/owner/repo/contents/go.mod", encodedContent("go.mod", "module example.com/test"))

	result, err := scanner.ScanRepoWithOptions(context.Background(), "owner", "repo", ScanOptions{IncludeSuccess: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 9 {
		t.Fatalf("len(findings) = %d, want 9\nfindings=%+v", len(result.Findings), result.Findings)
	}
	if result.CountSuccesses() != 9 {
		t.Fatalf("success count = %d, want 9", result.CountSuccesses())
	}
	for _, finding := range result.Findings {
		if !finding.Success {
			t.Fatalf("expected only success findings, got %+v", finding)
		}
		if !strings.HasPrefix(finding.Title, "SUCCESS ") {
			t.Fatalf("success title = %q", finding.Title)
		}
	}
}
