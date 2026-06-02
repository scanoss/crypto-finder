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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pterm/pterm"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/scanner/semgrep"
	"github.com/scanoss/crypto-finder/internal/utils"
)

var (
	debug             bool
	verbose           bool
	quiet             bool
	errorOutputFormat string
)

var rootCmd = &cobra.Command{
	Use:   "crypto-finder",
	Short: "SCANOSS Crypto-Finder scans source code for cryptographic algorithm usage",
	Long: `SCANOSS Crypto-Finder is a CLI tool that scans source code repositories to detect
	cryptographic operations and extract relevant values. It executes OpenGrep
	as the default scanning engine and outputs results in a standardized interim JSON format.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		if err := validateErrorOutputFormat(errorOutputFormat); err != nil {
			return err
		}
		setupLogging()
		return nil
	},
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Enable quiet logging")
	rootCmd.PersistentFlags().StringVar(&errorOutputFormat, "error-format", "text", "Error output format: text, json")

	// Subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(annotateCmd)
	rootCmd.AddCommand(convertCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(configureCmd)
}

func setupLogging() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	semgrep.SetHumanErrorOutputEnabled(normalizedErrorOutputFormat() != formatJSON)

	if normalizedErrorOutputFormat() == formatJSON {
		pterm.DisableColor()
		zerolog.SetGlobalLevel(zerolog.Disabled)
		return
	}

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
	stderrFD, ok := utils.FDToInt(os.Stderr.Fd())
	isTTY := ok && term.IsTerminal(stderrFD)
	if !ok {
		pterm.DisableColor()
	}

	// Disable pterm colors if not running in a TTY (e.g., piped output or non-interactive terminal)
	if !isTTY {
		pterm.DisableColor()
	}

	if err := rootCmd.Execute(); err != nil {
		switch {
		case normalizedErrorOutputFormat() == formatJSON:
			renderJSONError(os.Stderr, err)
		case !isTTY:
			fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		default:
			pterm.Error.Printfln("%s", err)
		}
		os.Exit(1)
	}
}

func validateErrorOutputFormat(format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", formatText, formatJSON:
		return nil
	default:
		return failure.New(
			failure.CodeInvalidArguments,
			failure.StageInput,
			fmt.Sprintf("invalid --error-format %q (supported: text, json)", format),
			failure.WithDetail("error_format", format),
		)
	}
}

func normalizedErrorOutputFormat() string {
	format := strings.ToLower(strings.TrimSpace(errorOutputFormat))
	if format == "" {
		return formatText
	}
	return format
}

func renderJSONError(output io.Writer, err error) {
	data, marshalErr := failure.MarshalJSON(err)
	if marshalErr != nil {
		fallback := failure.ToPayload(err)
		fallbackData, fallbackErr := json.Marshal(fallback)
		if fallbackErr != nil {
			data = []byte(fmt.Sprintf(`{"code":%q,"stage":%q,"retryable":false,"message":%q}`, failure.CodeUnknown, failure.StageUnknown, err.Error()))
		} else {
			data = fallbackData
		}
	}
	if _, writeErr := output.Write(append(data, '\n')); writeErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
	}
}
