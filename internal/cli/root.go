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
	quiet   bool
)

var rootCmd = &cobra.Command{
	Use:   "scanoss-cf",
	Short: "SCANOSS Crypto-Finder scans source code for cryptographic algorithm usage",
	Long: `SCANOSS Crypto-Finder is a CLI tool that scans source code repositories to detect
	cryptographic operations and extract relevant values. It executes OpenGrep
	as the default scanning engine and outputs results in a standardized interim JSON format.`,
	SilenceUsage: true,
	PersistentPreRun: func(_ *cobra.Command, _ []string) {
		setupLogging()
	},
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Enable quiet logging")

	// Subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(convertCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(configureCmd)
}

func setupLogging() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	switch {
	case quiet:
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case verbose:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case debug:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}
}

// Execute runs the root command and exits on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
