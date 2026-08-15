package scanner

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-github/v84/github"
)

// countingMux records every request path so tests can assert not just what the
// scanner concluded but how many requests it spent getting there — the entire
// point of the file inventory.
type countingMux struct {
	mu    sync.Mutex
	paths []string
}

func (c *countingMux) record(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paths = append(c.paths, path)
}

func (c *countingMux) contentsRequests() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, p := range c.paths {
		if strings.Contains(p, "/contents/") {
			out = append(out, p)
		}
	}
	return out
}

func newCountingScanner(t *testing.T) (*Scanner, *http.ServeMux, *countingMux) {
	t.Helper()
	s, mux := newTestScanner(t, true)
	counter := &countingMux{}
	// Wrap by re-registering: net/http has no middleware hook on ServeMux, so
	// tests register through recordJSON/record404 below instead.
	return s, mux, counter
}

func recordJSON(mux *http.ServeMux, counter *countingMux, path string, v any) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		counter.record(r.URL.Path)
		handleJSONResponse(w, v)
	})
}

// TestInventorySkipsAbsentConfigProbes is the R17 regression test: a repository
// with Dependabot only must resolve both update tools from the directory
// listings plus one config fetch — never the nine Renovate 404 probes and the
// second Dependabot probe it used to pay.
func TestInventorySkipsAbsentConfigProbes(t *testing.T) {
	s, mux, counter := newCountingScanner(t)

	recordJSON(mux, counter, "/repos/owner/repo", map[string]any{"full_name": "owner/repo", "default_branch": "main"})
	recordJSON(mux, counter, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	recordJSON(mux, counter, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false})
	recordJSON(mux, counter, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "all_external_contributors"})

	depConfig := "version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n    cooldown:\n      default-days: 7\n"
	rootListing := []*github.RepositoryContent{dirEntry(".github"), fileEntry("README.md")}
	githubListing := []*github.RepositoryContent{fileEntry("dependabot.yml"), dirEntry("workflows")}
	mux.HandleFunc("/repos/owner/repo/contents/", func(w http.ResponseWriter, r *http.Request) {
		counter.record(r.URL.Path)
		switch r.URL.Path {
		case "/repos/owner/repo/contents/":
			handleJSONResponse(w, rootListing)
		case "/repos/owner/repo/contents/.github":
			handleJSONResponse(w, githubListing)
		case "/repos/owner/repo/contents/.github/dependabot.yml":
			handleJSONResponse(w, encodedContent(".github/dependabot.yml", depConfig))
		case "/repos/owner/repo/contents/.github/workflows":
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Errorf("unexpected contents request: %s — the inventory should have proven this path absent", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	result, err := s.ScanRepo(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("unexpected result.Error: %s", result.Error)
	}
	if len(result.Incomplete) != 0 {
		t.Fatalf("scan reported incomplete: %v", result.Incomplete)
	}

	// Root listing + .github listing + workflows listing + one dependabot
	// fetch. Anything more means probes the inventory should have prevented.
	if got := counter.contentsRequests(); len(got) != 4 {
		t.Fatalf("contents requests = %d, want 4:\n%s", len(got), strings.Join(got, "\n"))
	}
}

// A repository with no files at all is one listing: the root 404 is a
// determinate "empty repository", not a failure to look.
func TestInventoryEmptyRepositoryIsOneListing(t *testing.T) {
	s, mux, counter := newCountingScanner(t)

	recordJSON(mux, counter, "/repos/owner/repo", map[string]any{"full_name": "owner/repo", "default_branch": "main"})
	recordJSON(mux, counter, "/repos/owner/repo/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"})
	recordJSON(mux, counter, "/repos/owner/repo/actions/permissions/workflow", map[string]any{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false})
	recordJSON(mux, counter, "/repos/owner/repo/actions/permissions/fork-pr-contributor-approval", map[string]any{"approval_policy": "all_external_contributors"})
	mux.HandleFunc("/repos/owner/repo/contents/", func(w http.ResponseWriter, r *http.Request) {
		counter.record(r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	})

	result, err := s.ScanRepo(context.Background(), "owner", "repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Incomplete) != 0 {
		t.Fatalf("an empty repository is determinate, not incomplete: %v", result.Incomplete)
	}

	// Root listing + the workflows-directory listing (the workflow collector
	// does not consume the inventory). No update-tool probes at all.
	if got := counter.contentsRequests(); len(got) != 2 {
		t.Fatalf("contents requests = %d, want 2:\n%s", len(got), strings.Join(got, "\n"))
	}
}

// A listing at the contents API's 1000-entry cap cannot prove absence, so the
// inventory must refuse to vouch and the collectors must fall back to probing.
func TestInventoryTruncatedListingFallsBackToProbing(t *testing.T) {
	s, mux := newTestScanner(t, true)

	huge := make([]*github.RepositoryContent, contentsListingCap)
	for i := range huge {
		huge[i] = fileEntry("file-" + strings.Repeat("x", i%5) + ".txt")
	}
	handleContentsListing(mux, "", huge)

	collector := newTestFactCollector(s)
	inv := collector.collectFileInventory(context.Background(), "owner", "repo", nil)
	if inv.Complete {
		t.Fatal("a listing at the API cap may be truncated and must not be treated as complete")
	}
}

// A complete inventory that saw the config must still fetch and parse it.
func TestInventoryFindsRenovateAtLaterPath(t *testing.T) {
	s, mux := newTestScanner(t, true)

	handleContentsListing(mux, "", []*github.RepositoryContent{dirEntry(".github")})
	handleContentsListing(mux, ".github", []*github.RepositoryContent{fileEntry("renovate.json")})
	handleJSON(mux, "/repos/owner/repo/contents/.github/renovate.json",
		encodedContent(".github/renovate.json", `{"extends": ["config:recommended"]}`))

	collector := newTestFactCollector(s)
	inv := collector.collectFileInventory(context.Background(), "owner", "repo", nil)
	if !inv.Complete {
		t.Fatal("expected a complete inventory")
	}

	facts := collector.collectRenovateFacts(context.Background(), "owner", "repo", true, inv, nil)
	if facts.Missing || facts.Config == nil {
		t.Fatalf("renovate config should be found via the listing, got %+v", facts)
	}
	if facts.Path != ".github/renovate.json" {
		t.Fatalf("path = %q, want .github/renovate.json", facts.Path)
	}
}
