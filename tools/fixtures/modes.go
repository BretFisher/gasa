package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-github/v84/github"
	"gopkg.in/yaml.v3"
)

// verify compares every fixture against its repository and reports differences
// without changing anything. This is what CI runs, before the assertions, so
// that drift is reported as drift rather than surfacing later as a bogus rule
// regression.
func verify(ctx context.Context, client *github.Client, fixtures []fixture) error {
	var problems []string

	for _, f := range fixtures {
		fmt.Printf("checking %s\n", f.Repo)

		want, err := f.localFiles()
		if err != nil {
			return err
		}
		got, err := remoteFiles(ctx, client, f)
		if err != nil {
			return err
		}
		problems = append(problems, diffFiles(f.Repo, want, got)...)

		wantActions := f.Actions
		gotActions, err := remoteActions(ctx, client, f)
		if err != nil {
			return err
		}
		problems = append(problems, diffActions(f.Repo, wantActions, gotActions)...)
	}

	if len(problems) == 0 {
		fmt.Printf("\nall %d fixtures match\n", len(fixtures))
		return nil
	}

	fmt.Fprintf(os.Stderr, "\n%d fixture difference(s):\n", len(problems))
	for _, p := range problems {
		fmt.Fprintf(os.Stderr, "  - %s\n", p)
	}
	return fmt.Errorf("fixtures do not match their repositories; run `make fixtures-apply` from a machine with an admin token, or `make fixtures-capture` if the repositories are correct and the checkout is stale")
}

func diffFiles(repo string, want, got map[string]string) []string {
	var problems []string

	for _, path := range sortedKeys(want) {
		remote, ok := got[path]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s: %s is missing from the repository", repo, path))
		case remote != want[path]:
			problems = append(problems, fmt.Sprintf("%s: %s differs from the checked-in fixture", repo, path))
		}
	}
	for _, path := range sortedKeys(got) {
		if _, ok := want[path]; !ok {
			problems = append(problems, fmt.Sprintf("%s: %s exists in the repository but not in the fixture (add it, or list it under `unmanaged`)", repo, path))
		}
	}
	return problems
}

func diffActions(repo string, want, got Actions) []string {
	var problems []string
	add := func(field, w, g string) {
		if w != g {
			problems = append(problems, fmt.Sprintf("%s: actions.%s is %q, fixture declares %q", repo, field, g, w))
		}
	}

	add("enabled", boolText(want.Enabled), boolText(got.Enabled))
	add("allowed_actions", want.AllowedActions, got.AllowedActions)
	add("sha_pinning_required", boolText(want.SHAPinningRequired), boolText(got.SHAPinningRequired))
	add("default_workflow_permissions", want.DefaultWorkflowPermissions, got.DefaultWorkflowPermissions)
	add("can_approve_pull_request_reviews", boolText(want.CanApprovePullRequestReviews), boolText(got.CanApprovePullRequestReviews))
	add("fork_pr_contributor_approval", want.ForkPRContributorApproval, got.ForkPRContributorApproval)
	return problems
}

// apply pushes the checked-in fixture back over the repository. It is additive:
// files present remotely but absent locally are reported, never deleted, so a
// mistake in the checkout cannot destroy repository content.
func apply(ctx context.Context, client *github.Client, fixtures []fixture) error {
	for _, f := range fixtures {
		owner, name, err := splitRepo(f.Repo)
		if err != nil {
			return err
		}
		fmt.Printf("applying %s\n", f.Repo)

		want, err := f.localFiles()
		if err != nil {
			return err
		}
		got, err := remoteFiles(ctx, client, f)
		if err != nil {
			return err
		}

		for _, path := range sortedKeys(want) {
			if remote, ok := got[path]; ok && remote == want[path] {
				continue
			}
			if err := putFile(ctx, client, owner, name, path, want[path]); err != nil {
				return err
			}
			fmt.Printf("  wrote %s\n", path)
		}
		for _, path := range sortedKeys(got) {
			if _, ok := want[path]; !ok {
				fmt.Printf("  note: %s exists in the repository but not in the fixture; left in place\n", path)
			}
		}

		if err := applyActions(ctx, client, owner, name, f); err != nil {
			return err
		}
	}
	fmt.Println("\napply complete")
	return nil
}

func putFile(ctx context.Context, client *github.Client, owner, name, path, content string) error {
	opts := &github.RepositoryContentFileOptions{
		Message: github.Ptr("Sync fixture from gasa testdata"),
		Content: []byte(content),
	}
	// An update needs the blob SHA it replaces; a create must not send one.
	existing, _, resp, err := client.Repositories.GetContents(ctx, owner, name, path, nil)
	switch {
	case err == nil && existing != nil:
		opts.SHA = existing.SHA
	case resp != nil && resp.StatusCode == 404:
		// create
	case err != nil:
		return fmt.Errorf("%s/%s: read %s: %w", owner, name, path, err)
	}

	if _, _, err := client.Repositories.CreateFile(ctx, owner, name, path, opts); err != nil {
		return fmt.Errorf("%s/%s: write %s: %w", owner, name, path, err)
	}
	return nil
}

func applyActions(ctx context.Context, client *github.Client, owner, name string, f fixture) error {
	a := f.Actions

	if err := applyActionsPermissions(ctx, client, owner, name, f.Repo, a); err != nil {
		return err
	}

	if a.DefaultWorkflowPermissions != "" || a.CanApprovePullRequestReviews != nil {
		workflow := github.DefaultWorkflowPermissionRepository{}
		if a.DefaultWorkflowPermissions != "" {
			workflow.DefaultWorkflowPermissions = github.Ptr(a.DefaultWorkflowPermissions)
		}
		if a.CanApprovePullRequestReviews != nil {
			workflow.CanApprovePullRequestReviews = a.CanApprovePullRequestReviews
		}
		if _, _, err := client.Repositories.UpdateDefaultWorkflowPermissions(ctx, owner, name, workflow); err != nil {
			return fmt.Errorf("%s: set workflow permissions: %w", f.Repo, err)
		}
		fmt.Printf("  set default_workflow_permissions=%s can_approve_pull_request_reviews=%s\n",
			a.DefaultWorkflowPermissions, boolText(a.CanApprovePullRequestReviews))
	}

	// notApplicable means GitHub does not offer the setting here, so there is
	// nothing to write and attempting it would 422.
	if a.ForkPRContributorApproval != "" && a.ForkPRContributorApproval != notApplicable {
		policy := github.ContributorApprovalPermissions{ApprovalPolicy: a.ForkPRContributorApproval}
		if _, err := client.Actions.UpdateForkPRContributorApprovalPermissions(ctx, owner, name, policy); err != nil {
			return fmt.Errorf("%s: set fork-PR approval: %w", f.Repo, err)
		}
		fmt.Printf("  set fork_pr_contributor_approval=%s\n", a.ForkPRContributorApproval)
	}

	return nil
}

// applyActionsPermissions writes the top-level Actions permissions (enablement,
// allowed-actions policy, SHA-pinning enforcement) when the manifest declares
// any of them.
func applyActionsPermissions(ctx context.Context, client *github.Client, owner, name, repoFull string, a Actions) error {
	if a.Enabled == nil && a.AllowedActions == "" && a.SHAPinningRequired == nil {
		return nil
	}
	perms := github.ActionsPermissionsRepository{
		Enabled:            a.Enabled,
		SHAPinningRequired: a.SHAPinningRequired,
	}
	if a.AllowedActions != "" {
		perms.AllowedActions = github.Ptr(a.AllowedActions)
	}
	if _, _, err := client.Repositories.UpdateActionsPermissions(ctx, owner, name, perms); err != nil {
		return fmt.Errorf("%s: set actions permissions: %w", repoFull, err)
	}
	fmt.Printf("  set allowed_actions=%s sha_pinning_required=%s\n", a.AllowedActions, boolText(a.SHAPinningRequired))
	return nil
}

// capture records the repositories' current state into the checkout. It is the
// inverse of apply and is how a fixture is first created or re-baselined after a
// deliberate change made through the GitHub UI.
func capture(ctx context.Context, client *github.Client, fixtures []fixture) error {
	for _, f := range fixtures {
		fmt.Printf("capturing %s\n", f.Repo)

		got, err := remoteFiles(ctx, client, f)
		if err != nil {
			return err
		}

		root := filepath.Join(f.dir, filesDirName)
		if err = os.RemoveAll(root); err != nil {
			return err
		}
		for _, path := range sortedKeys(got) {
			dest := filepath.Join(root, filepath.FromSlash(path))
			if err = os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
				return err
			}
			if err = os.WriteFile(dest, []byte(got[path]), 0o600); err != nil {
				return err
			}
			fmt.Printf("  %s\n", path)
		}

		actions, err := remoteActions(ctx, client, f)
		if err != nil {
			return err
		}
		f.Actions = actions
		if err := writeManifest(f); err != nil {
			return err
		}
	}
	fmt.Println("\ncapture complete; review the diff before committing")
	return nil
}

func writeManifest(f fixture) error {
	out, err := yaml.Marshal(f.Manifest)
	if err != nil {
		return err
	}
	header := "# Declarative description of a gasa end-to-end test fixture repository.\n" +
		"# Managed by `make fixtures-apply`; do not edit the repository directly.\n"
	return os.WriteFile(filepath.Join(f.dir, manifestName), append([]byte(header), out...), 0o600)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// boolText renders a tri-state so an undeclared setting is visibly different
// from one declared false.
func boolText(b *bool) string {
	if b == nil {
		return "(unset)"
	}
	return strings.ToLower(fmt.Sprintf("%t", *b))
}
