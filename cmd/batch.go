package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bretfisher/gasa/internal/scanner"
	"github.com/google/go-github/v84/github"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

var (
	flagBatchOutput          string
	flagBatchConcurrency     int
	flagBatchIncludeArchived bool
	flagBatchInput           string
	// batch also gets its own copies of the run-level filters
	flagBatchRules      []string
	flagBatchCategories []string
	flagBatchSeverities []string
	flagBatchSuccess    bool
)

// batchRepoResult holds the outcome of scanning a single repo in a batch run.
type batchRepoResult struct {
	RepoFullName string
	Result       *scanner.ScanResult // nil when Err is set
	Err          error               // non-nil means the scan failed entirely
	Index        int                 // preserves input ordering
}

type batchScanOptions struct {
	Rules          []string
	Categories     []string
	Severities     []string
	IncludeSuccess bool
	OutputFormat   string
	Debug          bool
	Timeout        time.Duration
}

type batchCommandOptions struct {
	Format          string
	OutputPath      string
	Concurrency     int
	IncludeArchived bool
	InputPath       string
	Rules           []string
	Categories      []string
	Severities      []string
	IncludeSuccess  bool
	Debug           bool
	Timeout         time.Duration
	TokenStdin      bool
	ConfigPath      string
	NoConfig        bool
}

type batchRequest struct {
	Target          string
	Format          string
	OutputPath      string
	Concurrency     int
	IncludeArchived bool
	InputPath       string
	Rules           []string
	Categories      []string
	Severities      []string
	IncludeSuccess  bool
	Debug           bool
	Timeout         time.Duration
	TokenStdin      bool
	ConfigPath      string
	NoConfig        bool
}

var batchCmd = &cobra.Command{
	Use:   "batch [owner-or-user | owner/repo,owner/repo,...]",
	Short: "Scan multiple repositories and produce a combined report",
	Long: `Scan multiple repositories and produce a combined report.

Input modes (exactly one required):
  owner-or-user         A single GitHub username or org name — fetches all repos
  owner/repo,...        One or more explicit owner/repo pairs (comma-separated)
  --input <file>        A file with one owner/repo per line (#-comments and blank lines ignored)

Output behavior:
  --format table        Streams each repo result to stdout as it completes
  --format json         Prints a JSON array of all results to stdout, or to --output if set
  --format html         Writes a combined HTML report to --output (required)

Status and progress lines always go to stderr.`,
	Example: `  gasa batch owner --format html --output owner-security-report.html
  gasa batch owner --config .gasa.yaml --concurrency 5 --format html --output report.html
  gasa batch owner/repo1,owner/repo2 --format html --output report.html
  gasa batch --input repos.txt --format html --output report.html
  gasa batch owner --format table
  gasa batch owner --format json | jq '.[] | select(.findings | length > 0)'
  gasa batch owner --format json --output owner-report.json
  gasa batch owner --rule action-pinning --severity high,critical --format html --output report.html
  gasa batch owner --include-archived --format html --output report.html`,
	Args: cobra.MaximumNArgs(1),
	RunE: runBatch,
}

func init() {
	rootCmd.AddCommand(batchCmd)
	batchCmd.Flags().StringVar(&flagBatchOutput, "output", "", "write report to this file path (required for --format html; optional for --format json, defaults to stdout)")
	batchCmd.Flags().IntVar(&flagBatchConcurrency, "concurrency", 5, "number of repos to scan in parallel")
	batchCmd.Flags().BoolVar(&flagBatchIncludeArchived, "include-archived", false, "include archived repos when scanning by owner/user")
	batchCmd.Flags().StringVar(&flagBatchInput, "input", "", "path to a file with one owner/repo per line")
	batchCmd.Flags().StringSliceVarP(&flagBatchRules, "rule", "r", nil, "run only the specified rule (repeat or comma-separate)")
	batchCmd.Flags().StringSliceVar(&flagBatchCategories, "category", nil, "run only rules in the specified category (workflows,settings,updates)")
	batchCmd.Flags().StringSliceVar(&flagBatchSeverities, "severity", nil, "run only rules with the specified severity (critical,high,medium,low,info)")
	batchCmd.Flags().BoolVar(&flagBatchSuccess, "success", false, "include successful rule results in the output")
	batchCmd.MarkFlagsMutuallyExclusive("rule", "category")
	batchCmd.MarkFlagsMutuallyExclusive("rule", "severity")
}

func runBatch(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	req, err := buildBatchRequest(args, batchCommandOptions{
		Format:          flagFormat,
		OutputPath:      flagBatchOutput,
		Concurrency:     flagBatchConcurrency,
		IncludeArchived: flagBatchIncludeArchived,
		InputPath:       flagBatchInput,
		Rules:           flagBatchRules,
		Categories:      flagBatchCategories,
		Severities:      flagBatchSeverities,
		IncludeSuccess:  flagBatchSuccess,
		Debug:           flagDebug,
		Timeout:         flagTimeout,
		TokenStdin:      flagTokenStdin,
		ConfigPath:      flagConfig,
		NoConfig:        flagNoConfig,
	})
	if err != nil {
		return err
	}

	// Resolve token and build scanner
	resolvedToken, authSource, err := resolveToken(ctx, req.TokenStdin, os.Stdin)
	if err != nil {
		return err
	}
	var s *scanner.Scanner
	if resolvedToken != "" {
		s = scanner.NewWithToken(resolvedToken)
	} else {
		s = scanner.New()
	}

	// Load config
	cfg, loadedConfigPath, err := resolveScanConfig(req.ConfigPath, req.NoConfig, ".")
	if err != nil {
		return err
	}

	// Build repo list
	repos, err := resolveRepoList(ctx, s, req, resolvedToken)
	if err != nil {
		return err
	}

	if len(repos) == 0 {
		return fmt.Errorf("no repositories found to scan")
	}

	// Print batch header to stderr
	fmt.Fprintf(os.Stderr, "Batch scan: %d repositories, concurrency %d\n", len(repos), req.Concurrency)
	if len(req.Rules) > 0 {
		fmt.Fprintf(os.Stderr, "Rules: %s\n", strings.Join(req.Rules, ", "))
	}
	if len(req.Categories) > 0 {
		fmt.Fprintf(os.Stderr, "Categories: %s\n", strings.Join(req.Categories, ", "))
	}
	if len(req.Severities) > 0 {
		fmt.Fprintf(os.Stderr, "Severities: %s\n", strings.Join(req.Severities, ", "))
	}
	if loadedConfigPath != "" {
		fmt.Fprintf(os.Stderr, "Config: %s\n", loadedConfigPath)
	}
	if resolvedToken != "" {
		fmt.Fprintf(os.Stderr, "Auth: %s\n", authSource)
	} else {
		fmt.Fprintf(os.Stderr, "Auth: unauthenticated (60 req/hr limit, some checks unavailable)\n")
	}
	fmt.Fprintln(os.Stderr)

	// Run scans with worker pool
	results := runBatchScans(ctx, repos, s, cfg, req.Concurrency, batchScanOptions{
		Rules:          req.Rules,
		Categories:     req.Categories,
		Severities:     req.Severities,
		IncludeSuccess: req.IncludeSuccess,
		OutputFormat:   req.Format,
		Debug:          req.Debug,
		Timeout:        req.Timeout,
	})

	// Warn loudly if any repo's scan was partial, so an incomplete batch is
	// never mistaken for a clean run.
	printIncompleteSummary(results)

	// Dispatch output
	switch req.Format {
	case outputFormatHTML:
		return printBatchHTML(results, req.OutputPath)
	case outputFormatJSON:
		return printBatchJSON(results, req.OutputPath)
	default:
		// table: already streamed during scan; nothing more to do
	}
	return nil
}

func buildBatchRequest(args []string, opts batchCommandOptions) (batchRequest, error) {
	if err := validateOutputFormat(opts.Format); err != nil {
		return batchRequest{}, err
	}
	if err := validateTimeout(opts.Timeout); err != nil {
		return batchRequest{}, err
	}
	if opts.Format == outputFormatHTML && opts.OutputPath == "" {
		return batchRequest{}, fmt.Errorf("--output <file> is required when --format html")
	}
	if opts.Concurrency < 1 {
		return batchRequest{}, fmt.Errorf("--concurrency must be at least 1")
	}

	hasArg := len(args) == 1 && args[0] != ""
	hasInput := opts.InputPath != ""
	if hasArg && hasInput {
		return batchRequest{}, fmt.Errorf("provide either a positional owner/repo argument or --input, not both")
	}
	if !hasArg && !hasInput {
		return batchRequest{}, fmt.Errorf("provide either an owner/user name, a comma-separated list of owner/repo, or --input <file>")
	}

	target := ""
	if hasArg {
		target = args[0]
	}

	return batchRequest{
		Target:          target,
		Format:          opts.Format,
		OutputPath:      opts.OutputPath,
		Concurrency:     opts.Concurrency,
		IncludeArchived: opts.IncludeArchived,
		InputPath:       opts.InputPath,
		Rules:           opts.Rules,
		Categories:      opts.Categories,
		Severities:      opts.Severities,
		IncludeSuccess:  opts.IncludeSuccess,
		Debug:           opts.Debug,
		Timeout:         opts.Timeout,
		TokenStdin:      opts.TokenStdin,
		ConfigPath:      opts.ConfigPath,
		NoConfig:        opts.NoConfig,
	}, nil
}

// printIncompleteSummary writes a stderr warning when any repo's scan was
// partial, so an incomplete batch is never mistaken for a clean run. It goes to
// stderr and so is visible in every output format, including JSON/HTML written
// to a file. No-op when every scan completed.
func printIncompleteSummary(results []batchRepoResult) {
	repos, checks := countIncomplete(results)
	if repos == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\n⚠ %d repositor%s had %d incomplete check(s); findings may be partial. Re-scan affected repos or raise --timeout.\n",
		repos, pluralRepos(repos), checks)
}

// countIncomplete returns how many repos had at least one incomplete check and
// the total number of incomplete checks across the batch.
func countIncomplete(results []batchRepoResult) (repos, checks int) {
	for _, r := range results {
		if r.Result == nil || len(r.Result.Incomplete) == 0 {
			continue
		}
		repos++
		checks += len(r.Result.Incomplete)
	}
	return repos, checks
}

func pluralRepos(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// runBatchScans executes scans concurrently and returns ordered results.
// For table format, it also streams each result to stdout as it completes.
func runBatchScans(ctx context.Context, repos []string, s *scanner.Scanner, cfg *scanner.Config, concurrency int, opts batchScanOptions) []batchRepoResult {
	total := len(repos)
	// Each worker owns one unique result index. The slice is pre-sized and never
	// appended to while workers run, so concurrent writes to distinct elements are safe.
	results := make([]batchRepoResult, total)

	var progressMu sync.Mutex
	completed := 0
	g, groupCtx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)

	for i, repoURL := range repos {
		idx, repoFull := i, repoURL
		g.Go(func() error {
			owner, repo, err := scanner.ParseRepoURL(repoFull)
			if err != nil {
				progressMu.Lock()
				completed++
				fmt.Fprintf(os.Stderr, "[%d/%d] %s — skipped: %v\n", completed, total, repoFull, err)
				progressMu.Unlock()
				results[idx] = batchRepoResult{RepoFullName: repoFull, Err: err, Index: idx}
				return nil
			}

			// Build a per-repo debug logger that writes under progressMu so
			// interleaved batch output doesn't corrupt the terminal.
			var repoDebugLog scanner.DebugLogger
			if opts.Debug {
				repoDebugLog = func(repo, msg string) {
					progressMu.Lock()
					fmt.Fprintf(os.Stderr, "[DEBUG] %s | %s\n", repo, msg)
					progressMu.Unlock()
				}
			}

			scanCtx, cancel := context.WithTimeout(groupCtx, opts.Timeout)
			result, scanErr := s.ScanRepoWithOptions(scanCtx, owner, repo, scanner.ScanOptions{
				RuleNames:      opts.Rules,
				Categories:     opts.Categories,
				Severities:     opts.Severities,
				IncludeSuccess: opts.IncludeSuccess,
				Config:         cfg,
				DebugLog:       repoDebugLog,
			})
			cancel()

			progressMu.Lock()
			completed++
			switch {
			case scanErr != nil:
				fmt.Fprintf(os.Stderr, "[%d/%d] %s — error: %v\n", completed, total, repoFull, scanErr)
			case result.Error != "":
				fmt.Fprintf(os.Stderr, "[%d/%d] %s — %s\n", completed, total, repoFull, result.Error)
			default:
				counts := result.CountBySeverity()
				numFindings := 0
				for _, c := range counts {
					numFindings += c
				}
				if n := len(result.Incomplete); n > 0 {
					fmt.Fprintf(os.Stderr, "[%d/%d] %s — %d finding(s), %d check(s) incomplete\n", completed, total, repoFull, numFindings, n)
				} else {
					fmt.Fprintf(os.Stderr, "[%d/%d] %s — %d finding(s)\n", completed, total, repoFull, numFindings)
				}
			}

			// Stream table output immediately
			if opts.OutputFormat == outputFormatTable {
				if scanErr != nil {
					fmt.Printf("Repository: %s\nError: %v\n\n", repoFull, scanErr)
				} else {
					printTable(result)
					fmt.Println()
				}
			}
			progressMu.Unlock()

			if scanErr != nil {
				results[idx] = batchRepoResult{RepoFullName: repoFull, Err: scanErr, Index: idx}
			} else {
				results[idx] = batchRepoResult{RepoFullName: repoFull, Result: result, Index: idx}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return []batchRepoResult{{Err: err}}
	}
	return results
}

// resolveRepoList builds the list of owner/repo strings to scan from the three
// supported input modes: explicit file (--input), comma-separated list, or owner fetch.
func resolveRepoList(ctx context.Context, s *scanner.Scanner, req batchRequest, resolvedToken string) ([]string, error) {
	if req.InputPath != "" {
		repos, err := repoListFromFile(req.InputPath)
		if err != nil {
			return nil, fmt.Errorf("reading --input file: %w", err)
		}
		return repos, nil
	}

	arg := req.Target
	if strings.Contains(arg, "/") {
		// Explicit owner/repo list (comma-separated)
		return parseRepoList(arg)
	}

	// Owner/user name — fetch all repos via API
	if resolvedToken == "" {
		fmt.Fprintln(os.Stderr, "Warning: unauthenticated — repo listing is limited to 60 req/hr and may be incomplete")
	}
	listCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	repos, err := fetchRepoList(listCtx, s.GitHubClient(), arg, req.IncludeArchived)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("fetching repo list for %q: %w", arg, err)
	}
	return repos, nil
}

// fetchRepoList returns all non-archived (or all if includeArchived) repos
// for the given user or org sorted by most recent push, using pagination.
func fetchRepoList(ctx context.Context, client *github.Client, owner string, includeArchived bool) ([]string, error) {
	user, _, err := client.Users.Get(ctx, owner)
	if err == nil && user.GetType() == githubAccountTypeOrg {
		return fetchOrgRepoList(ctx, client, owner, includeArchived)
	}
	return fetchUserRepoList(ctx, client, owner, includeArchived)
}

func fetchUserRepoList(ctx context.Context, client *github.Client, owner string, includeArchived bool) ([]string, error) {
	var repos []string
	opts := &github.RepositoryListByUserOptions{
		Sort:      "pushed",
		Direction: "desc",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	for {
		page, resp, err := client.Repositories.ListByUser(ctx, owner, opts)
		if err != nil {
			return nil, err
		}
		for _, r := range page {
			if !includeArchived && r.GetArchived() {
				continue
			}
			repos = append(repos, r.GetFullName())
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	fmt.Fprintf(os.Stderr, "Repo listing: used user endpoint for %s, found %d repo(s)\n", owner, len(repos))
	return repos, nil
}

func fetchOrgRepoList(ctx context.Context, client *github.Client, owner string, includeArchived bool) ([]string, error) {
	var repos []string
	opts := &github.RepositoryListByOrgOptions{
		Type:      "all",
		Sort:      "pushed",
		Direction: "desc",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	for {
		page, resp, err := client.Repositories.ListByOrg(ctx, owner, opts)
		if err != nil {
			return nil, err
		}
		for _, r := range page {
			if !includeArchived && r.GetArchived() {
				continue
			}
			repos = append(repos, r.GetFullName())
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	fmt.Fprintf(os.Stderr, "Repo listing: used organization endpoint for %s, found %d repo(s)\n", owner, len(repos))
	return repos, nil
}

// parseRepoList parses a comma-separated list of owner/repo strings.
func parseRepoList(input string) ([]string, error) {
	parts := strings.Split(input, ",")
	var repos []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		owner, repo, err := scanner.ParseRepoURL(p)
		if err != nil {
			return nil, fmt.Errorf("invalid repo %q: %w", p, err)
		}
		repos = append(repos, owner+"/"+repo)
	}
	if len(repos) == 0 {
		return nil, fmt.Errorf("no valid owner/repo entries found in argument")
	}
	return repos, nil
}

// repoListFromFile reads one owner/repo per line from a file.
// Blank lines and lines starting with # are ignored.
func repoListFromFile(path string) (repos []string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		owner, repo, err := scanner.ParseRepoURL(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid repo %q: %w", lineNum, line, err)
		}
		repos = append(repos, owner+"/"+repo)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(repos) == 0 {
		return nil, fmt.Errorf("no valid owner/repo entries found in %q", path)
	}
	return repos, nil
}
