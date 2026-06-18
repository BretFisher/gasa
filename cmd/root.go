// Package cmd holds the gasa CLI command tree built on spf13/cobra.
package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// Version is the gasa version. It is overridden at build time via
// -ldflags "-X github.com/bretfisher/gasa/cmd.Version=<version>".
var Version = "dev"

// Persistent flags shared by all subcommands.
var (
	flagTokenStdin bool
	flagConfig     string
	flagFormat     string
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

func init() {
	rootCmd.PersistentFlags().BoolVar(&flagTokenStdin, "token-stdin", false, "read GitHub token from stdin")
	rootCmd.PersistentFlags().StringVarP(&flagConfig, "config", "c", "", "path to gasa YAML config file")
	rootCmd.PersistentFlags().StringVar(&flagFormat, "format", outputFormatTable, "output format: table, json, or html")
	rootCmd.PersistentFlags().BoolVar(&flagDebug, "debug", false, "print diagnostic debug output to stderr")
	rootCmd.PersistentFlags().DurationVar(&flagTimeout, "timeout", time.Minute, "maximum time for each repo scan or repo listing operation")
}

// Execute runs the root command with a signal-aware context so an interrupt or
// SIGTERM cancels in-flight scans cleanly. It exits the process with status 1
// on error.
func Execute() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		cancel()
		os.Exit(1)
	}
	cancel()
}
