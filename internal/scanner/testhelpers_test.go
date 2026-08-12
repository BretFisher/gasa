package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-github/v84/github"
)

const testBaseURLPath = "/api-v3"

// debugRecorder is a concurrency-safe DebugLogger sink for tests. Fact
// collection runs collectors (and workflow-file fetches) concurrently, so the
// logger may be invoked from multiple goroutines at once.
type debugRecorder struct {
	mu    sync.Mutex
	lines []string
}

// log satisfies the scanner.DebugLogger signature.
func (d *debugRecorder) log(repo, msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lines = append(d.lines, repo+"|"+msg)
}

// snapshot returns a copy of the recorded lines safe to read after collection.
func (d *debugRecorder) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.lines...)
}

func newTestScanner(t *testing.T, authenticated bool) (*Scanner, *http.ServeMux) {
	t.Helper()

	mux := http.NewServeMux()
	apiHandler := http.NewServeMux()
	apiHandler.Handle(testBaseURLPath+"/", http.StripPrefix(testBaseURLPath, mux))

	server := httptest.NewServer(apiHandler)
	t.Cleanup(server.Close)

	client := github.NewClient(nil)
	baseURL, err := url.Parse(server.URL + testBaseURLPath + "/")
	if err != nil {
		t.Fatalf("failed to parse test URL: %v", err)
	}
	client.BaseURL = baseURL

	return &Scanner{
		client:        client,
		authenticated: authenticated,
	}, mux
}

func newTestFactCollector(s *Scanner) *factCollector {
	return &factCollector{client: s.client, authenticated: s.authenticated}
}

func handleJSON(mux *http.ServeMux, path string, v any) {
	mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			panic(fmt.Sprintf("failed to encode test JSON: %v", err))
		}
	})
}

func handle404(mux *http.ServeMux, paths ...string) {
	for _, path := range paths {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
	}
}

// handle500 makes the given paths return a server error — an indeterminate
// failure (not a clean 404) used to exercise incomplete-scan reporting.
func handle500(mux *http.ServeMux, paths ...string) {
	for _, path := range paths {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
	}
}

func requireContainsLine(t *testing.T, lines []string, want string) {
	t.Helper()

	for _, line := range lines {
		if strings.Contains(line, want) {
			return
		}
	}

	t.Fatalf("did not find %q in lines: %+v", want, lines)
}

// handleContentsListing mocks a directory listing at the given repo-relative
// directory ("" for the root). The root listing URL carries a trailing slash,
// which net/http treats as a subtree pattern, so the handler answers only the
// exact listing URL and returns 404 for anything below it — unregistered file
// fetches keep behaving exactly as they would on an empty mux.
func handleContentsListing(mux *http.ServeMux, dir string, entries []*github.RepositoryContent) {
	base := "/repos/owner/repo/contents/" + dir
	mux.HandleFunc(base, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != base {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewEncoder(w).Encode(entries); err != nil {
			panic(err)
		}
	})
}

func fileEntry(name string) *github.RepositoryContent {
	return &github.RepositoryContent{Type: github.Ptr("file"), Name: github.Ptr(name)}
}

func dirEntry(name string) *github.RepositoryContent {
	return &github.RepositoryContent{Type: github.Ptr("dir"), Name: github.Ptr(name)}
}

// handleJSONResponse writes v as the response body — the encoding half of
// handleJSON, for handlers that need their own routing or recording logic.
func handleJSONResponse(w http.ResponseWriter, v any) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(fmt.Sprintf("failed to encode test JSON: %v", err))
	}
}
