package scanner

import (
	"context"
	"sync"

	"github.com/google/go-github/v90/github"
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
	Repository      *github.Repository
	RepositoryOwner string
	DefaultBranch   string
	// PullRequestCreationPolicy is the repository setting controlling who may
	// open pull requests ("all", "collaborators_only", …). Carried separately
	// from Repository because go-github does not model the field. Empty when
	// GitHub did not report it.
	PullRequestCreationPolicy               string
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

	// ForkPRApprovalNotApplicable is set when GitHub reports that fork-PR
	// approval does not exist for this repository at all. Private repositories
	// answer the endpoint with 422 "Fork PR approval is not allowed for private
	// repositories".
	//
	// This is deliberately distinct from Undetermined: the setting was not
	// unreadable, it has no meaning here. Reporting it as unreadable produced a
	// finding and an incomplete-scan warning on every private repository scan,
	// for a control that cannot be misconfigured because it does not exist.
	ForkPRApprovalNotApplicable bool

	// Undetermined records settings the scanner tried to read but could not,
	// keyed by the constants below and holding a human-readable cause.
	//
	// A nil settings pointer is ambiguous on its own: it means either "GitHub
	// told us nothing because the sub-call was refused" or "the field was
	// genuinely absent". Rules previously could not tell those apart from
	// "everything is fine", so a refused sub-call made a rule emit no finding,
	// no success, and no warning — the check silently vanished from the report
	// while the scan still looked clean. This map is what lets a rule say "could
	// not determine" out loud instead.
	Undetermined map[string]string
}

// Keys for ActionsSettingsFacts.Undetermined. One key per API sub-call, since
// that is the granularity at which a read succeeds or fails.
const (
	settingAllowedActions      = "allowed-actions policy"
	settingWorkflowPermissions = "workflow permissions"
	settingForkPRApproval      = "fork-PR contributor approval"
	settingSHAPinning          = "SHA pinning requirement"
)

// markUndetermined records that a setting could not be read, and why.
func (f *ActionsSettingsFacts) markUndetermined(setting, cause string) {
	if f.Undetermined == nil {
		f.Undetermined = make(map[string]string)
	}
	f.Undetermined[setting] = cause
}

// undeterminedCause returns the recorded cause and whether the setting was
// marked undetermined.
func (f *ActionsSettingsFacts) undeterminedCause(setting string) (string, bool) {
	cause, ok := f.Undetermined[setting]
	return cause, ok
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

func (c *factCollector) collectFacts(ctx context.Context, owner, repo string, repository *github.Repository, prCreationPolicy string, cfg *Config, dbg DebugLogger) *ScanFacts {
	facts := &ScanFacts{
		Repository:                              repository,
		RepositoryOwner:                         owner,
		PullRequestCreationPolicy:               prCreationPolicy,
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

	// The file inventory (one or two directory listings) is what lets the
	// Dependabot and Renovate collectors skip absent config paths without a
	// request each. It runs concurrently with the workflow and settings
	// collectors, which do not consume it; only the two update-tool collectors
	// wait for it before starting.
	invCh := make(chan fileInventory, 1)
	go func() { invCh <- c.collectFileInventory(ctx, owner, repo, dbg) }()

	wg.Add(2)
	go func() { defer wg.Done(); workflows = c.collectWorkflowFacts(ctx, owner, repo, dbg) }()
	go func() { defer wg.Done(); settings = c.collectActionsSettingsFacts(ctx, owner, repo, dbg) }()

	inv := <-invCh
	wg.Add(2)
	go func() { defer wg.Done(); dependabot = c.collectDependabotFacts(ctx, owner, repo, false, inv, dbg) }()
	go func() { defer wg.Done(); renovate = c.collectRenovateFacts(ctx, owner, repo, false, inv, dbg) }()
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
