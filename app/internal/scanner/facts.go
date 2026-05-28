package scanner

import (
	"context"

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

	facts.Workflows = c.collectWorkflowFacts(ctx, owner, repo, dbg)
	facts.ActionsSettings = c.collectActionsSettingsFacts(ctx, owner, repo, dbg)
	hasWorkflows := len(facts.Workflows) > 0
	facts.Dependabot = c.collectDependabotFacts(ctx, owner, repo, hasWorkflows, dbg)
	facts.Renovate = c.collectRenovateFacts(ctx, owner, repo, hasWorkflows, dbg)

	return facts
}
