package scanner

import (
	"context"
	"sync"

	"github.com/google/go-github/v84/github"
)

// addWarning records an indeterminate fact (see FactWarning). It is safe for
// concurrent use because the four collectors — and the per-file workflow
// fetches within one of them — run in parallel goroutines.
func (c *factCollector) addWarning(area, detail string) {
	c.warnMu.Lock()
	defer c.warnMu.Unlock()
	c.warnings = append(c.warnings, FactWarning{Area: area, Detail: detail})
}

type ScanFacts struct {
	Repository                              *github.Repository
	RepositoryOwner                         string
	DefaultBranch                           string
	Workflows                               []WorkflowFact
	ActionsSettings                         ActionsSettingsFacts
	Dependabot                              DependabotFacts
	Renovate                                RenovateFacts
	ActionVersionPinningIgnoreSameOwner     bool
	UpdateToolConfigurationRequireWorkflows bool

	// Incomplete lists facts that could not be determined because a GitHub
	// request failed for a reason other than a clean 404 (timeout, rate limit,
	// 5xx, …). A non-empty slice means the scan is partial.
	Incomplete []FactWarning
}

type WorkflowFact struct {
	Path     string
	Content  string
	Workflow *WorkflowFile
	Valid    bool
}

type ActionsSettingsFacts struct {
	Permissions                *github.ActionsPermissionsRepository
	AccessFinding              *Finding
	DefaultWorkflowPermissions *github.DefaultWorkflowPermissionRepository
	ForkPRContributorApproval  *github.ContributorApprovalPermissions
}

type DependabotFacts struct {
	Path         string
	Content      string
	Config       *DependabotConfig
	Missing      bool
	Invalid      error
	HasWorkflows bool
	// Unknown is set when presence could not be determined (an indeterminate
	// fetch error, not a clean 404). It is mutually exclusive with Missing:
	// when Unknown, rules must not treat the tool as absent.
	Unknown bool
}

type RenovateFacts struct {
	Path         string
	Content      string
	Config       *RenovateConfig
	Missing      bool
	Invalid      error
	HasWorkflows bool
	// Unknown is set when presence could not be determined (an indeterminate
	// fetch error, not a clean 404). It is mutually exclusive with Missing:
	// when Unknown, rules must not treat the tool as absent.
	Unknown bool
}

type factCollector struct {
	client        *github.Client
	authenticated bool

	warnMu   sync.Mutex
	warnings []FactWarning
}

func (c *factCollector) collectFacts(ctx context.Context, owner, repo string, repository *github.Repository, cfg *Config, dbg DebugLogger) *ScanFacts {
	facts := &ScanFacts{
		Repository:                              repository,
		RepositoryOwner:                         owner,
		DefaultBranch:                           "HEAD",
		ActionVersionPinningIgnoreSameOwner:     cfg.actionVersionPinningIgnoreSameOwner(),
		UpdateToolConfigurationRequireWorkflows: cfg.updateToolConfigurationRequireWorkflows(),
	}

	if repository != nil && repository.DefaultBranch != nil && *repository.DefaultBranch != "" {
		facts.DefaultBranch = *repository.DefaultBranch
	}

	// The four collectors hit independent GitHub endpoints, so run them
	// concurrently. Each goroutine writes only its own local, read back after
	// Wait, so there are no shared writes. HasWorkflows isn't needed to fetch the
	// update-tool configs (only to interpret them later), so it's stamped onto
	// the results once the workflow listing is known. Total in-flight requests
	// are bounded by the transport-level semaphore (see retry.go), which keeps
	// per-repo fan-out from tripping GitHub's secondary rate limits under batch.
	var (
		wg         sync.WaitGroup
		workflows  []WorkflowFact
		settings   ActionsSettingsFacts
		dependabot DependabotFacts
		renovate   RenovateFacts
	)
	wg.Add(4)
	go func() { defer wg.Done(); workflows = c.collectWorkflowFacts(ctx, owner, repo, dbg) }()
	go func() { defer wg.Done(); settings = c.collectActionsSettingsFacts(ctx, owner, repo, dbg) }()
	go func() { defer wg.Done(); dependabot = c.collectDependabotFacts(ctx, owner, repo, false, dbg) }()
	go func() { defer wg.Done(); renovate = c.collectRenovateFacts(ctx, owner, repo, false, dbg) }()
	wg.Wait()

	hasWorkflows := len(workflows) > 0
	dependabot.HasWorkflows = hasWorkflows
	renovate.HasWorkflows = hasWorkflows

	facts.Workflows = workflows
	facts.ActionsSettings = settings
	facts.Dependabot = dependabot
	facts.Renovate = renovate

	// Collected after Wait so every collector goroutine (and the per-file
	// workflow fetches) has finished recording any indeterminate failures.
	facts.Incomplete = c.warnings

	return facts
}
