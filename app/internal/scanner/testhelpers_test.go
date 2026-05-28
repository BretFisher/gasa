package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-github/v84/github"
)

const testBaseURLPath = "/api-v3"

func newTestScanner(t *testing.T, authenticated bool) (*Scanner, *http.ServeMux) {
	t.Helper()

	mux := http.NewServeMux()
	apiHandler := http.NewServeMux()
	apiHandler.Handle(testBaseURLPath+"/", http.StripPrefix(testBaseURLPath, mux))

	server := httptest.NewServer(apiHandler)
	t.Cleanup(server.Close)

	client := github.NewClient(nil)
	baseURL, _ := url.Parse(server.URL + testBaseURLPath + "/")
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
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(v)
	})
}

func handle404(mux *http.ServeMux, paths ...string) {
	for _, path := range paths {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
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
