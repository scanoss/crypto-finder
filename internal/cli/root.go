// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

// Package cli provides the command-line interface implementation for crypto-finder.
package cli

import (
	"fmt"
	"os"

	"github.com/pterm/pterm"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	debug   bool
	verbose bool
	quiet   bool
)

var rootCmd = &cobra.Command{
	Use:   "crypto-finder",
	Short: "SCANOSS Crypto-Finder scans source code for cryptographic algorithm usage",
	Long: `SCANOSS Crypto-Finder is a CLI tool that scans source code repositories to detect
	cryptographic operations and extract relevant values. It executes OpenGrep
	as the default scanning engine and outputs results in a standardized interim JSON format.`,
	SilenceUsage:  true,
	SilenceErrors: true,
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
	// Disable pterm colors if not running in a TTY (e.g., piped output or non-interactive terminal)
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		pterm.DisableColor()
	}

	if err := rootCmd.Execute(); err != nil {
		// Use plain error output in non-TTY environments to avoid color artifacts
		if !term.IsTerminal(int(os.Stderr.Fd())) {
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		} else {
			pterm.Error.Printfln("%s", err)
		}
		os.Exit(1)
	}
}
