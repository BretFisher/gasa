package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v84/github"
)

func TestBuildBatchRequest(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		opts    batchCommandOptions
		want    batchRequest
		wantErr string
	}{
		{
			name: "explicit target",
			args: []string{"owner/repo"},
			opts: batchCommandOptions{
				Format:          outputFormatHTML,
				OutputPath:      "report.html",
				Concurrency:     3,
				IncludeArchived: true,
				Rules:           []string{"pinning"},
				Categories:      []string{"workflows"},
				Severities:      []string{"high"},
				IncludeSuccess:  true,
				Debug:           true,
				Timeout:         time.Minute,
				TokenStdin:      true,
				ConfigPath:      ".gasa.yml",
			},
			want: batchRequest{
				Target:          "owner/repo",
				Format:          outputFormatHTML,
				OutputPath:      "report.html",
				Concurrency:     3,
				IncludeArchived: true,
				Rules:           []string{"pinning"},
				Categories:      []string{"workflows"},
				Severities:      []string{"high"},
				IncludeSuccess:  true,
				Debug:           true,
				Timeout:         time.Minute,
				TokenStdin:      true,
				ConfigPath:      ".gasa.yml",
			},
		},
		{
			name: "input file",
			opts: batchCommandOptions{Format: outputFormatTable, Concurrency: 1, InputPath: "repos.txt", Timeout: time.Minute},
			want: batchRequest{Format: outputFormatTable, Concurrency: 1, InputPath: "repos.txt", Timeout: time.Minute},
		},
		{
			name:    "missing html output",
			args:    []string{"owner/repo"},
			opts:    batchCommandOptions{Format: outputFormatHTML, Concurrency: 1, Timeout: time.Minute},
			wantErr: "--output",
		},
		{
			name: "json without output defaults to stdout",
			args: []string{"owner/repo"},
			opts: batchCommandOptions{Format: outputFormatJSON, Concurrency: 1, Timeout: time.Minute},
			want: batchRequest{Target: "owner/repo", Format: outputFormatJSON, Concurrency: 1, Timeout: time.Minute},
		},
		{
			name:    "invalid concurrency",
			args:    []string{"owner/repo"},
			opts:    batchCommandOptions{Format: outputFormatTable, Concurrency: 0, Timeout: time.Minute},
			wantErr: "--concurrency",
		},
		{
			name:    "arg and input",
			args:    []string{"owner/repo"},
			opts:    batchCommandOptions{Format: outputFormatTable, Concurrency: 1, InputPath: "repos.txt", Timeout: time.Minute},
			wantErr: "provide either",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildBatchRequest(tt.args, tt.opts)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("buildBatchRequest() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildBatchRequest() error = %v", err)
			}
			if got.Target != tt.want.Target || got.Format != tt.want.Format || got.OutputPath != tt.want.OutputPath || got.Concurrency != tt.want.Concurrency || got.InputPath != tt.want.InputPath || got.Timeout != tt.want.Timeout || got.ConfigPath != tt.want.ConfigPath {
				t.Fatalf("buildBatchRequest() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestFetchRepoList_UsesOrgEndpointForOrganizations(t *testing.T) {
	var sawOrgRepos bool
	client := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users/acme":
			if err := json.NewEncoder(w).Encode(map[string]any{"type": "Organization"}); err != nil {
				t.Errorf("encode response: %v", err)
			}
		case "/orgs/acme/repos":
			sawOrgRepos = true
			if got := r.URL.Query().Get("type"); got != "all" {
				t.Fatalf("org repos type query = %q, want all", got)
			}
			if err := json.NewEncoder(w).Encode([]map[string]any{{"full_name": "acme/repo", "archived": false}}); err != nil {
				t.Errorf("encode response: %v", err)
			}
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))

	repos, err := fetchRepoList(context.Background(), client, "acme", false)
	if err != nil {
		t.Fatalf("fetchRepoList() error = %v", err)
	}
	if !sawOrgRepos {
		t.Fatal("expected organization repo endpoint to be called")
	}
	if len(repos) != 1 || repos[0] != "acme/repo" {
		t.Fatalf("repos = %v, want [acme/repo]", repos)
	}
}

func TestFetchRepoList_UsesUserEndpointForUsers(t *testing.T) {
	var sawUserRepos bool
	client := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users/bret":
			if err := json.NewEncoder(w).Encode(map[string]any{"type": "User"}); err != nil {
				t.Errorf("encode response: %v", err)
			}
		case "/users/bret/repos":
			sawUserRepos = true
			if err := json.NewEncoder(w).Encode([]map[string]any{{"full_name": "bret/repo", "archived": false}}); err != nil {
				t.Errorf("encode response: %v", err)
			}
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))

	repos, err := fetchRepoList(context.Background(), client, "bret", false)
	if err != nil {
		t.Fatalf("fetchRepoList() error = %v", err)
	}
	if !sawUserRepos {
		t.Fatal("expected user repo endpoint to be called")
	}
	if len(repos) != 1 || repos[0] != "bret/repo" {
		t.Fatalf("repos = %v, want [bret/repo]", repos)
	}
}

func TestFetchRepoList_FiltersArchivedRepos(t *testing.T) {
	client := newTestGitHubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users/acme":
			if err := json.NewEncoder(w).Encode(map[string]any{"type": "Organization"}); err != nil {
				t.Errorf("encode response: %v", err)
			}
		case "/orgs/acme/repos":
			if err := json.NewEncoder(w).Encode([]map[string]any{
				{"full_name": "acme/active", "archived": false},
				{"full_name": "acme/archived", "archived": true},
			}); err != nil {
				t.Errorf("encode response: %v", err)
			}
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))

	repos, err := fetchRepoList(context.Background(), client, "acme", false)
	if err != nil {
		t.Fatalf("fetchRepoList() error = %v", err)
	}
	if len(repos) != 1 || repos[0] != "acme/active" {
		t.Fatalf("repos = %v, want [acme/active]", repos)
	}
}

func newTestGitHubClient(t *testing.T, handler http.Handler) *github.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client := github.NewClient(server.Client())
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	client.BaseURL = baseURL
	return client
}
