package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-github/v84/github"
)

const (
	rateLimitMsg          = "API rate limit exceeded. Try again later."
	findingIDNoUpdateTool = "no-update-tool"

	// Rule categories
	categoryWorkflows = "Workflows"
	categorySettings  = "Settings"
	categoryUpdates   = "Updates"

	// Rule names
	ruleNamePullRequestTarget          = "workflows/pull-request-target"
	ruleNameActionVersionPinning       = "workflows/action-version-pinning"
	ruleNameWorkflowPermissions        = "workflows/workflow-permissions"
	ruleNameAllowedActionsPolicy       = "actions/permissions/allowed-actions-policy"
	ruleNameDefaultWorkflowPermissions = "actions/permissions/workflow/default-workflow-permissions"
	ruleNameActionsCanApprovePRs       = "actions/permissions/workflow/actions-can-approve-prs"
	ruleNameForkPRContributorApproval  = "actions/permissions/fork-pr-contributor-approval"
	ruleNameUpdateToolConfiguration    = "updates/update-tool-configuration"
	ruleNameUpdateToolActionsCooldown  = "updates/update-tool-actions-cooldown"
	ruleNameUpdateToolActionsPinning   = "updates/update-tool-actions-pinning"

	// Finding IDs
	findingIDSettingsCheckFailed      = "settings-check-failed"
	findingIDSettingsCheckUnavailable = "settings-check-unavailable"
	findingIDInvalidDependabot        = "invalid-dependabot"
	findingIDMissingActionsUpdateTool = "update-tool-missing-actions"
	findingIDMissingActionsCooldown   = "update-tool-actions-missing-cooldown"

	// File paths
	defaultDependabotPath = ".github/dependabot.yml"
	defaultRenovatePath   = ".github/renovate.json"

	// Trigger events
	triggerPullRequestTarget = "pull_request_target"

	// Doc URLs
	docURLActionsSettings = "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository"

	// Additional finding IDs used in rules and buildFixURL
	findingIDAllActionsAllowed       = "settings-all-actions-allowed"
	findingIDDefaultPermissionsWrite = "settings-default-permissions-write"
	findingIDActionsCanApprovePRs    = "settings-actions-can-approve-prs"
	findingIDForkPRTooPermissive     = "settings-fork-pr-contributor-approval-too-permissive"

	// GitHub Actions permission values
	actionsAllowedAll         = "all"
	actionsAllowedSelected    = "selected"
	permissionsRead           = "read"
	permissionsWrite          = "write"
	forkPRApprovalAllExternal = "all_external_contributors"

	// Error messages
	errMsgRepoNotFound = "Repository not found or is private"
)

// Scanner performs security checks on GitHub repositories
type Scanner struct {
	client        *github.Client
	authenticated bool
}

// DebugLogger is a function that receives a single-line debug message.
// The repo parameter is "owner/repo" and is included so interleaved batch
// output can be filtered or sorted by repository.
// When nil, debug output is suppressed entirely.
//
// Fact collection runs concurrently, so a DebugLogger may be called from
// multiple goroutines at once and must be safe for concurrent use. Each call
// is expected to emit one whole line so interleaved output stays readable.
type DebugLogger func(repo, msg string)

type ScanOptions struct {
	RuleNames      []string
	Categories     []string
	Severities     []string
	IncludeSuccess bool
	Config         *Config
	DebugLog       DebugLogger
}

// New creates a new Scanner with an unauthenticated GitHub client
func New() *Scanner {
	return &Scanner{
		client:        newGitHubClient(),
		authenticated: false,
	}
}

// NewWithToken creates a Scanner with an authenticated GitHub client
func NewWithToken(token string) *Scanner {
	return &Scanner{
		client:        newGitHubClient().WithAuthToken(token),
		authenticated: true,
	}
}

// IsAuthenticated reports whether the scanner was constructed with a token.
func (s *Scanner) IsAuthenticated() bool {
	return s.authenticated
}

// GitHubClient returns the underlying github.Client for use in batch operations
// such as listing repositories for a user or organization.
func (s *Scanner) GitHubClient() *github.Client {
	return s.client
}

// ScanRepo performs all security checks on a repository.
func (s *Scanner) ScanRepo(ctx context.Context, owner, repo string) (*ScanResult, error) {
	return s.ScanRepoWithOptions(ctx, owner, repo, ScanOptions{})
}

func (s *Scanner) ScanRepoWithOptions(ctx context.Context, owner, repo string, opts ScanOptions) (*ScanResult, error) {
	repoFull := fmt.Sprintf("%s/%s", owner, repo)
	dbg := opts.DebugLog

	result := &ScanResult{
		RepoFullName: fmt.Sprintf("%s/%s", owner, repo),
		RepoURL:      fmt.Sprintf("https://github.com/%s/%s", owner, repo),
		Findings:     []Finding{},
		ScannedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	// Verify repo exists and is accessible
	if dbg != nil {
		dbg(repoFull, "GET /repos/"+repoFull)
	}
	repository, _, err := s.client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		result.Error = classifyGitHubRepoAccessError(err)
		if dbg != nil {
			dbg(repoFull, "repo fetch failed: "+result.Error)
		}
		return result, nil
	}
	if dbg != nil {
		dbg(repoFull, "repo fetch OK — default branch: "+repository.GetDefaultBranch())
	}

	collector := &factCollector{client: s.client, authenticated: s.authenticated}
	facts := collector.collectFacts(ctx, owner, repo, repository, opts.Config, dbg)

	rules, err := resolveRules(opts.RuleNames, opts.Categories, opts.Severities, opts.Config)
	if err != nil {
		return nil, err
	}

	for _, r := range rules {
		if dbg != nil {
			dbg(repoFull, "rule:start "+r.Name)
		}
		findings := r.run(facts)
		findings = applyRuleConfig(findings, r, opts.Config)
		if len(findings) == 0 && opts.IncludeSuccess {
			if success := buildRuleSuccessFinding(r, facts, opts.Config); success != nil {
				if dbg != nil {
					dbg(repoFull, "rule:pass "+r.Name)
				}
				result.Findings = append(result.Findings, *success)
				continue
			}
		}
		if dbg != nil {
			if len(findings) == 0 {
				dbg(repoFull, "rule:pass "+r.Name+" (no findings)")
			} else {
				for _, f := range findings {
					dbg(repoFull, "rule:finding "+r.Name+" id="+f.ID+" severity="+f.Severity)
				}
			}
		}
		result.Findings = append(result.Findings, findings...)
	}
	result.Findings = applySuppressions(result.Findings, opts.Config)
	result.Findings = addFixURLs(result.Findings, owner, repo, facts.DefaultBranch)
	result.Findings = dedupeFindings(result.Findings)

	sortFindings(result.Findings)

	return result, nil
}

func classifyGitHubRepoAccessError(err error) string {
	var rateLimitErr *github.RateLimitError
	if errors.As(err, &rateLimitErr) {
		return rateLimitMsg
	}

	var abuseRateLimitErr *github.AbuseRateLimitError
	if errors.As(err, &abuseRateLimitErr) {
		return "GitHub secondary rate limit or abuse detection triggered. Try again later."
	}

	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) {
		statusCode := 0
		if ghErr.Response != nil {
			statusCode = ghErr.Response.StatusCode
		}

		switch statusCode {
		case http.StatusNotFound:
			return errMsgRepoNotFound
		case http.StatusUnauthorized:
			return "Authentication failed (token rejected)"
		case http.StatusForbidden:
			if isPrimaryRateLimitResponse(ghErr.Response) {
				return rateLimitMsg
			}
			return "Access forbidden (check token scopes, SSO authorization, or organization access policies)"
		case http.StatusTooManyRequests:
			return rateLimitMsg
		}
	}

	return fmt.Sprintf("Failed to access repository: %v", err)
}

func isPrimaryRateLimitResponse(resp *http.Response) bool {
	return resp != nil && resp.Header.Get("X-RateLimit-Remaining") == "0"
}

func addFixURLs(findings []Finding, owner, repo, defaultBranch string) []Finding {
	for i := range findings {
		findings[i].FixURL = buildFixURL(findings[i], owner, repo, defaultBranch)
	}
	return findings
}

func buildFixURL(f Finding, owner, repo, defaultBranch string) string {
	repoURL := fmt.Sprintf("https://github.com/%s/%s", owner, repo)
	settingsURL := repoURL + "/settings/actions"

	switch f.ID {
	case findingIDAllActionsAllowed, "settings-local-only", findingIDSettingsCheckFailed, findingIDSettingsCheckUnavailable:
		return settingsURL
	case findingIDDefaultPermissionsWrite, findingIDActionsCanApprovePRs:
		return settingsURL
	case findingIDForkPRTooPermissive:
		return settingsURL
	case findingIDNoUpdateTool:
		return fmt.Sprintf("%s/new/%s?filename=%s", repoURL, pathEscapeSegments(defaultBranch), url.QueryEscape(defaultDependabotPath))
	case findingIDInvalidDependabot, findingIDMissingActionsUpdateTool:
		return blobURL(owner, repo, defaultBranch, defaultDependabotPath, 0)
	case "invalid-renovate":
		return blobURL(owner, repo, defaultBranch, defaultRenovatePath, 0)
	}

	if f.File != "" {
		return blobURL(owner, repo, defaultBranch, f.File, f.Line)
	}

	return ""
}

func blobURL(owner, repo, defaultBranch, path string, line int) string {
	link := fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", owner, repo, pathEscapeSegments(defaultBranch), pathEscapeSegments(path))
	if line > 0 {
		link = fmt.Sprintf("%s#L%d", link, line)
	}
	return link
}

func pathEscapeSegments(path string) string {
	path = strings.Trim(path, "/")
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/")
}

func dedupeFindings(findings []Finding) []Finding {
	seen := make(map[string]bool)
	deduped := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		deduped = append(deduped, f)
	}
	return deduped
}

// ParseRepoURL extracts owner and repo from various GitHub URL formats
func ParseRepoURL(input string) (owner, repo string, err error) {
	input = strings.TrimSpace(input)
	input = strings.TrimSuffix(input, "/")
	input = strings.TrimSuffix(input, ".git")

	// Handle full URLs
	input = strings.TrimPrefix(input, "ssh://")
	input = strings.TrimPrefix(input, "git@")
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimPrefix(input, "github.com:")
	input = strings.TrimPrefix(input, "github.com/")
	input = strings.TrimPrefix(input, "www.github.com/")

	// Now we should have "owner/repo" or "owner/repo/..."
	parts := strings.Split(input, "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid repository format: expected 'owner/repo' or GitHub URL")
	}

	owner = parts[0]
	repo = parts[1]

	if err := validateGitHubOwner(owner); err != nil {
		return "", "", err
	}
	if err := validateGitHubRepo(repo); err != nil {
		return "", "", err
	}

	return owner, repo, nil
}

var (
	githubOwnerPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	githubRepoPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

func validateGitHubOwner(owner string) error {
	if !githubOwnerPattern.MatchString(owner) {
		return fmt.Errorf("invalid GitHub owner %q: use 1-39 letters, numbers, or hyphens; hyphens cannot start or end the name", owner)
	}
	return nil
}

func validateGitHubRepo(repo string) error {
	if !githubRepoPattern.MatchString(repo) || repo == "." || repo == ".." {
		return fmt.Errorf("invalid GitHub repository %q: use 1-100 letters, numbers, dots, underscores, or hyphens", repo)
	}
	return nil
}
