// Package cli provides the command-line interface implementation for scanoss-cf.
package cli

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "scanoss-cf",
	Short: "SCANOSS Crypto-Finder scans source code for cryptographic algorithm usage",
	Long: `SCANOSS Crypto-Finder is a CLI tool that scans source code repositories to detect
	cryptographic operations and extract relevant values. It executes Semgrep
	as the default scanning engine and outputs results in a standardized interim JSON format.`,
	SilenceUsage: true,
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose logging")

	// Subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
