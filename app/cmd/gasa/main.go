package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bretfisher/github-security-assessment/app/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	Version        = "dev"
	flagTokenStdin bool
	flagConfig     string
	flagFormat     string
	flagRules      []string
	flagCategories []string
	flagSeverities []string
	flagSuccess    bool
	flagDebug      bool
	flagTimeout    time.Duration
)

var rootCmd = &cobra.Command{
	Use:     "gasa",
	Short:   "GitHub Actions Security Assessment",
	Version: Version,
	Long: `GitHub Actions Security Assessment (gasa)

Scans GitHub repositories for Actions security misconfigurations,
pinning issues, and missing dependency update automation.`,
}

type scanCommandOptions struct {
	Format         string
	Rules          []string
	Categories     []string
	Severities     []string
	IncludeSuccess bool
	Debug          bool
	Timeout        time.Duration
	TokenStdin     bool
	ConfigPath     string
	WorkDir        string
}

type scanRequest struct {
	Owner          string
	Repo           string
	Format         string
	Rules          []string
	Categories     []string
	Severities     []string
	IncludeSuccess bool
	Debug          bool
	Timeout        time.Duration
	TokenStdin     bool
	ConfigPath     string
}

var runCmd = &cobra.Command{
	Use:   "run [owner/repo]",
	Short: "Scan a repository for Actions security issues",
	Example: `  gasa run owner/repo
  gasa run
  gasa run --rule fork-pr-approval owner/repo
  gasa run --rule action-pinning,permissions owner/repo
  gasa run --category workflows owner/repo
  gasa run --severity critical,high owner/repo
  gasa run --success owner/repo
  gasa run --format json owner/repo
  gasa run --format html owner/repo > report.html
  printf '%s' "$GITHUB_TOKEN" | gasa run --token-stdin owner/repo`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List available rule names and aliases",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		if err := validateOutputFormat(flagFormat); err != nil {
			return err
		}
		switch flagFormat {
		case outputFormatJSON:
			printRulesJSON()
		case outputFormatHTML:
			return printRulesHTML()
		default:
			printRulesTable()
		}
		return nil
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the gasa version",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), Version)
		return err
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&flagTokenStdin, "token-stdin", false, "read GitHub token from stdin")
	rootCmd.PersistentFlags().StringVarP(&flagConfig, "config", "c", "", "path to gasa YAML config file")
	rootCmd.PersistentFlags().StringVar(&flagFormat, "format", outputFormatTable, "output format: table, json, or html")
	rootCmd.PersistentFlags().BoolVar(&flagDebug, "debug", false, "print diagnostic debug output to stderr")
	rootCmd.PersistentFlags().DurationVar(&flagTimeout, "timeout", time.Minute, "maximum time for each repo scan or repo listing operation")
	runCmd.Flags().StringSliceVarP(&flagRules, "rule", "r", nil, "run only the specified rule (repeat or comma-separate; use 'gasa rules' to list rules)")
	runCmd.Flags().StringSliceVar(&flagCategories, "category", nil, "run only rules in the specified category (workflows,settings,updates; repeat or comma-separate)")
	runCmd.Flags().StringSliceVar(&flagSeverities, "severity", nil, "run only rules with the specified severity (critical,high,medium,low,info; repeat or comma-separate)")
	runCmd.Flags().BoolVar(&flagSuccess, "success", false, "include successful rule results in the output")
	runCmd.MarkFlagsMutuallyExclusive("rule", "category")
	runCmd.MarkFlagsMutuallyExclusive("rule", "severity")

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(batchCmd)
	rootCmd.AddCommand(versionCmd)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		cancel()
		os.Exit(1)
	}
	cancel()
}

func runScan(cmd *cobra.Command, args []string) error {
	req, err := buildScanRequest(cmd.Context(), args, scanCommandOptions{
		Format:         flagFormat,
		Rules:          flagRules,
		Categories:     flagCategories,
		Severities:     flagSeverities,
		IncludeSuccess: flagSuccess,
		Debug:          flagDebug,
		Timeout:        flagTimeout,
		TokenStdin:     flagTokenStdin,
		ConfigPath:     flagConfig,
		WorkDir:        ".",
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), req.Timeout)
	defer cancel()

	var cfg *scanner.Config
	loadedConfigPath := ""
	if req.ConfigPath != "" {
		cfg, err = scanner.LoadConfig(req.ConfigPath)
		loadedConfigPath = req.ConfigPath
	} else {
		cfg, loadedConfigPath, err = scanner.LoadConfigFromDir(".")
	}
	if err != nil {
		return err
	}

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

	if req.Format == outputFormatTable {
		printScanHeader(req, loadedConfigPath, resolvedToken, authSource)
	}

	result, err := s.ScanRepoWithOptions(ctx, req.Owner, req.Repo, scanner.ScanOptions{
		RuleNames:      req.Rules,
		Categories:     req.Categories,
		Severities:     req.Severities,
		IncludeSuccess: req.IncludeSuccess,
		Config:         cfg,
		DebugLog:       buildDebugLogger(req.Debug),
	})
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if result.Error != "" {
		return fmt.Errorf("%s", result.Error)
	}

	switch req.Format {
	case outputFormatJSON:
		printJSON(result)
	case outputFormatHTML:
		return printHTML(result)
	default:
		printTable(result)
	}
	return nil
}

func buildScanRequest(ctx context.Context, args []string, opts scanCommandOptions) (scanRequest, error) {
	if err := validateOutputFormat(opts.Format); err != nil {
		return scanRequest{}, err
	}
	if err := validateTimeout(opts.Timeout); err != nil {
		return scanRequest{}, err
	}

	owner := ""
	repo := ""
	var err error
	if len(args) == 0 {
		inferCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		owner, repo, err = inferRepoFromGitRemote(inferCtx, opts.WorkDir)
		cancel()
	} else {
		owner, repo, err = scanner.ParseRepoURL(args[0])
	}
	if err != nil {
		return scanRequest{}, err
	}

	return scanRequest{
		Owner:          owner,
		Repo:           repo,
		Format:         opts.Format,
		Rules:          opts.Rules,
		Categories:     opts.Categories,
		Severities:     opts.Severities,
		IncludeSuccess: opts.IncludeSuccess,
		Debug:          opts.Debug,
		Timeout:        opts.Timeout,
		TokenStdin:     opts.TokenStdin,
		ConfigPath:     opts.ConfigPath,
	}, nil
}

func validateOutputFormat(format string) error {
	switch format {
	case outputFormatTable, outputFormatJSON, outputFormatHTML:
		return nil
	default:
		return fmt.Errorf("invalid --format %q: expected table, json, or html", format)
	}
}

func validateTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return fmt.Errorf("--timeout must be greater than 0")
	}
	return nil
}

func inferRepoFromGitRemote(ctx context.Context, dir string) (owner, repo string, err error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return "", "", fmt.Errorf("repository argument omitted and git is not available; pass <owner/repo>")
	}

	cmd := exec.CommandContext(ctx, gitPath, "config", "--get", "remote.origin.url")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("repository argument omitted and current directory is not a git clone with a github remote; pass <owner/repo>")
	}

	remote := strings.TrimSpace(string(out))
	if remote == "" {
		return "", "", fmt.Errorf("repository argument omitted and current directory is not a git clone with a github remote; pass <owner/repo>")
	}
	if !isGitHubRemote(remote) {
		return "", "", fmt.Errorf("repository argument omitted and current directory is not a git clone with a github remote; pass <owner/repo>")
	}

	owner, repo, err = scanner.ParseRepoURL(remote)
	if err != nil {
		return "", "", fmt.Errorf("repository argument omitted and origin remote %q is not a supported GitHub repository URL; pass <owner/repo>", remote)
	}
	return owner, repo, nil
}

func isGitHubRemote(remote string) bool {
	remote = strings.TrimSpace(remote)
	return strings.HasPrefix(remote, "git@github.com:") ||
		strings.HasPrefix(remote, "ssh://git@github.com/") ||
		strings.HasPrefix(remote, "https://github.com/") ||
		strings.HasPrefix(remote, "http://github.com/")
}

// buildDebugLogger returns a DebugLogger that writes [DEBUG] prefixed lines to
// stderr when debug is true, or nil when debug is false.
func buildDebugLogger(debug bool) scanner.DebugLogger {
	if !debug {
		return nil
	}
	return func(repo, msg string) {
		fmt.Fprintf(os.Stderr, "[DEBUG] %s | %s\n", repo, msg)
	}
}

const ghAuthTokenTimeout = 5 * time.Second

// printScanHeader writes the pre-scan diagnostic header to stderr for table output.
func printScanHeader(req scanRequest, loadedConfigPath, resolvedToken, authSource string) {
	fmt.Fprintf(os.Stderr, "Scanning %s/%s...\n", req.Owner, req.Repo)
	if len(req.Rules) > 0 {
		fmt.Fprintf(os.Stderr, "Rules: %s\n", strings.Join(req.Rules, ", "))
	}
	if len(req.Categories) > 0 {
		fmt.Fprintf(os.Stderr, "Categories: %s\n", strings.Join(req.Categories, ", "))
	}
	if len(req.Severities) > 0 {
		fmt.Fprintf(os.Stderr, "Severities: %s\n", strings.Join(req.Severities, ", "))
	}
	if req.IncludeSuccess {
		fmt.Fprintf(os.Stderr, "Include successes: yes\n")
	}
	if loadedConfigPath != "" {
		fmt.Fprintf(os.Stderr, "Config: %s\n", loadedConfigPath)
	}
	if resolvedToken != "" {
		fmt.Fprintf(os.Stderr, "Auth: %s\n", authSource)
	} else {
		fmt.Fprintf(os.Stderr, "Auth: unauthenticated (60 req/hr limit, some checks unavailable)\n")
		fmt.Fprintf(os.Stderr, "  Tip: set GITHUB_TOKEN or install gh CLI for full scanning\n")
	}
	fmt.Fprintln(os.Stderr)
}

func resolveToken(ctx context.Context, tokenStdin bool, stdin io.Reader) (token, source string, err error) {
	if tokenStdin {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return "", "", fmt.Errorf("reading token from stdin: %w", err)
		}
		if t := strings.TrimSpace(string(data)); t != "" {
			return t, "using token from stdin", nil
		}
		return "", "", fmt.Errorf("--token-stdin was set but stdin did not contain a token")
	}

	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		return t, "using token from GITHUB_TOKEN", nil
	}

	if t := os.Getenv("GH_TOKEN"); t != "" {
		return t, "using token from GH_TOKEN", nil
	}

	if ghPath, err := exec.LookPath("gh"); err == nil {
		ghCtx, cancel := context.WithTimeout(ctx, ghAuthTokenTimeout)
		defer cancel()

		cmd := exec.CommandContext(ghCtx, ghPath, "auth", "token")
		out, err := cmd.Output()
		if err == nil {
			t := strings.TrimSpace(string(out))
			if t != "" {
				return t, "using token from gh CLI", nil
			}
		}
	}

	return "", "", nil
}
