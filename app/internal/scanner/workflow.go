package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/google/go-github/v84/github"
	"gopkg.in/yaml.v3"
)

// WorkflowFile represents a parsed GitHub Actions workflow
type WorkflowFile struct {
	Name        string                 `yaml:"name"`
	On          interface{}            `yaml:"on"` // Can be string, []string, or map
	Permissions interface{}            `yaml:"permissions"`
	Jobs        map[string]WorkflowJob `yaml:"jobs"`
}

// WorkflowJob represents a job in a workflow
type WorkflowJob struct {
	Name        string            `yaml:"name"`
	Permissions interface{}       `yaml:"permissions"`
	Steps       []WorkflowStep    `yaml:"steps"`
	RunsOn      interface{}       `yaml:"runs-on"`
	Uses        string            `yaml:"uses"` // For reusable workflows
	Env         map[string]string `yaml:"env"`
}

// WorkflowStep represents a step in a job
type WorkflowStep struct {
	Name string                 `yaml:"name"`
	Uses string                 `yaml:"uses"`
	Run  string                 `yaml:"run"`
	With map[string]interface{} `yaml:"with"`
	Env  map[string]string      `yaml:"env"`
}

func (c *factCollector) collectWorkflowFacts(ctx context.Context, owner, repo string, dbg DebugLogger) []WorkflowFact {
	var workflows []WorkflowFact
	repoFull := owner + "/" + repo

	// Get .github/workflows directory contents
	if dbg != nil {
		dbg(repoFull, "GET /repos/"+repoFull+"/contents/.github/workflows")
	}
	_, dirContent, _, err := c.client.Repositories.GetContents(
		ctx, owner, repo, ".github/workflows", nil,
	)
	if err != nil {
		if dbg != nil {
			dbg(repoFull, "workflows dir not found or inaccessible: "+err.Error())
		}
		return workflows
	}
	if dbg != nil {
		dbg(repoFull, fmt.Sprintf("workflows dir: found %d entries", len(dirContent)))
	}

	for _, file := range dirContent {
		if file.Name == nil || !strings.HasSuffix(*file.Name, ".yml") && !strings.HasSuffix(*file.Name, ".yaml") {
			continue
		}

		if dbg != nil {
			dbg(repoFull, "GET /repos/"+repoFull+"/contents/"+*file.Path)
		}
		// Get file contents
		fileContent, _, _, err := c.client.Repositories.GetContents(
			ctx, owner, repo, *file.Path, nil,
		)
		if err != nil {
			if dbg != nil {
				dbg(repoFull, "workflow file fetch error "+*file.Path+": "+err.Error())
			}
			continue
		}

		content, err := decodeContent(fileContent)
		if err != nil {
			if dbg != nil {
				dbg(repoFull, "workflow file decode error "+*file.Path+": "+err.Error())
			}
			continue
		}

		fact := WorkflowFact{
			Path:    *file.Path,
			Content: content,
		}

		var workflow WorkflowFile
		if err := yaml.Unmarshal([]byte(content), &workflow); err == nil {
			fact.Workflow = &workflow
			fact.Valid = true
			if dbg != nil {
				dbg(repoFull, "workflow parsed OK: "+*file.Path)
			}
		} else if dbg != nil {
			dbg(repoFull, "workflow parse error "+*file.Path+": "+err.Error())
		}

		workflows = append(workflows, fact)
	}

	return workflows
}

// hasDangerousTrigger checks if the workflow uses pull_request_target
func hasDangerousTrigger(on interface{}) bool {
	switch v := on.(type) {
	case string:
		return v == "pull_request_target"
	case []interface{}:
		for _, trigger := range v {
			if str, ok := trigger.(string); ok && str == "pull_request_target" {
				return true
			}
		}
	case map[string]interface{}:
		_, exists := v["pull_request_target"]
		return exists
	}
	return false
}

// ActionRef holds information about an action reference
type ActionRef struct {
	name    string
	version string
	line    int
}

func findUnpinnedActionsInWorkflow(workflow *WorkflowFile, content string) []ActionRef {
	if workflow == nil {
		return findUnpinnedActions(content)
	}

	var unpinned []ActionRef
	jobNames := make([]string, 0, len(workflow.Jobs))
	for name := range workflow.Jobs {
		jobNames = append(jobNames, name)
	}
	sort.Strings(jobNames)
	for _, name := range jobNames {
		job := workflow.Jobs[name]
		if action, ok := parseActionRef(job.Uses); ok && !isSHA(action.version) {
			action.line = findUsesLine(content, job.Uses)
			unpinned = append(unpinned, action)
		}
		for _, step := range job.Steps {
			if action, ok := parseActionRef(step.Uses); ok && !isSHA(action.version) {
				action.line = findUsesLine(content, step.Uses)
				unpinned = append(unpinned, action)
			}
		}
	}
	return unpinned
}

func parseActionRef(uses string) (ActionRef, bool) {
	uses = strings.TrimSpace(uses)
	if uses == "" || strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://") {
		return ActionRef{}, false
	}

	at := strings.LastIndex(uses, "@")
	if at <= 0 || at == len(uses)-1 {
		return ActionRef{}, false
	}

	return ActionRef{name: uses[:at], version: uses[at+1:]}, true
}

func findUsesLine(content, uses string) int {
	if uses == "" {
		return 0
	}
	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "uses:") && strings.Contains(trimmed, uses) {
			return i + 1
		}
	}
	return 0
}

// findUnpinnedActions finds all actions not pinned to a commit SHA
func findUnpinnedActions(content string) []ActionRef {
	var unpinned []ActionRef

	// Match uses: statements
	usesRegex := regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*['"]?([^'"@\s]+)@([^'"@\s]+)['"]?`)
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		matches := usesRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			actionName := matches[1]
			version := matches[2]

			// Skip local actions (start with ./)
			if strings.HasPrefix(actionName, "./") {
				continue
			}

			// Skip Docker actions
			if strings.HasPrefix(actionName, "docker://") {
				continue
			}

			// Check if version is a full commit SHA.
			if !isSHA(version) {
				unpinned = append(unpinned, ActionRef{
					name:    actionName,
					version: version,
					line:    lineNum + 1,
				})
			}
		}
	}

	return unpinned
}

// isSHA checks if a string is a full SHA-1 or SHA-256 object ID.
func isSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// hasExplicitPermissions checks if workflow or all jobs have permissions defined
func hasExplicitPermissions(workflow *WorkflowFile) bool {
	// Check workflow-level permissions
	if workflow.Permissions != nil {
		return true
	}

	// Check if all jobs have permissions
	if len(workflow.Jobs) == 0 {
		return false
	}

	for _, job := range workflow.Jobs {
		if job.Permissions == nil {
			return false
		}
	}

	return true
}

// decodeContent decodes base64 encoded file content from GitHub API
func decodeContent(content *github.RepositoryContent) (string, error) {
	if content.Content == nil {
		return "", fmt.Errorf("no content")
	}
	decoded, err := base64.StdEncoding.DecodeString(*content.Content)
	if err != nil {
		// Try without padding issues
		raw := strings.ReplaceAll(*content.Content, "\n", "")
		decoded, err = base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return "", err
		}
	}
	return string(decoded), nil
}

// sanitizeID creates a safe ID from a string
func sanitizeID(s string) string {
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "@", "-")
	return s
}
