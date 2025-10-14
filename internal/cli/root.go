// Package cli provides the command-line interface implementation for scanoss-cf.
package cli

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	debug   bool
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "scanoss-cf",
	Short: "SCANOSS Crypto-Finder scans source code for cryptographic algorithm usage",
	Long: `SCANOSS Crypto-Finder is a CLI tool that scans source code repositories to detect
	cryptographic operations and extract relevant values. It executes Semgrep
	as the default scanning engine and outputs results in a standardized interim JSON format.`,
	SilenceUsage: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		setupLogging()
	},
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose logging")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "enable debug logging")

	// Subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
}

func setupLogging() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else if verbose {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
