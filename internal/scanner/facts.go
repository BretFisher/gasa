package scanner

import (
	"context"
	"sync"

	"github.com/google/go-github/v84/github"
)

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
}

type RenovateFacts struct {
	Path         string
	Content      string
	Config       *RenovateConfig
	Missing      bool
	Invalid      error
	HasWorkflows bool
}

type factCollector struct {
	client        *github.Client
	authenticated bool
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

	return facts
}
