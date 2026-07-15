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

package semgrep

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"

	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
)

var humanErrorOutputEnabled atomic.Bool

func init() {
	humanErrorOutputEnabled.Store(true)
}

// SetHumanErrorOutputEnabled controls whether Semgrep-compatible scanner errors
// are rendered for humans on stderr.
func SetHumanErrorOutputEnabled(enabled bool) {
	humanErrorOutputEnabled.Store(enabled)
}

// ParseSemgrepCompatibleOutput parses Semgrep's JSON output into the SemgrepOutput schema.
// This function can be reused by other compatible scanners (e.g., OpenGrep).
func ParseSemgrepCompatibleOutput(data []byte) (*entities.SemgrepOutput, error) {
	if len(data) == 0 {
		// Empty output means no findings, which is valid
		return &entities.SemgrepOutput{
			Results: []entities.SemgrepResult{},
			Errors:  []entities.SemgrepError{},
		}, nil
	}

	var output entities.SemgrepOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to unmarshal semgrep JSON: %w", err)
	}

	return &output, nil
}

// getErrorType extracts the error type string from the Type field.
// Type can be either a string or an array [string, locations].
func getErrorType(typeField any) string {
	if typeField == nil {
		return ""
	}

	// If it's a string, return it directly
	if typeStr, ok := typeField.(string); ok {
		return typeStr
	}

	// If it's an array, extract the first element
	if typeSlice, ok := typeField.([]any); ok && len(typeSlice) > 0 {
		if typeStr, ok := typeSlice[0].(string); ok {
			return typeStr
		}
	}

	return ""
}

// LogSemgrepCompatibleErrors displays opengrep errors in a user-friendly format.
// Returns true if there were any errors logged.
func LogSemgrepCompatibleErrors(errors []entities.SemgrepError) bool {
	if len(errors) == 0 {
		return false
	}

	var errorItems []pterm.BulletListItem

	for _, e := range errors {
		errType := "Unknown"

		if e.Type != nil {
			errType = getErrorType(e.Type)
		}

		msg := e.Message
		if e.Path != "" {
			if len(e.Spans) > 0 {
				msg += pterm.Gray(fmt.Sprintf(" → %s:%d:%d", e.Path, e.Spans[0].Start.Line, e.Spans[0].Start.Col))
			} else {
				msg += pterm.Gray(fmt.Sprintf(" → %s", e.Path))
			}
		}

		item := pterm.BulletListItem{
			Level:  1,
			Text:   msg,
			Bullet: errType,
		}

		if e.Level == "error" {
			item.BulletStyle = pterm.NewStyle(pterm.FgRed)
			errorItems = append(errorItems, item)
		}
	}

	// Display errors
	if len(errorItems) > 0 && humanErrorOutputEnabled.Load() {
		pterm.Error.Println("Scanner Errors")
		err := pterm.DefaultBulletList.WithItems(errorItems).WithWriter(os.Stderr).Render()
		if err != nil {
			log.Error().Err(err).Msg("failed while displaying output errors")
		}
	}

	return true
}

// exitCodeMeanings maps documented semgrep/opengrep exit codes to a
// human-readable cause (https://semgrep.dev/docs/cli-reference#exit-codes).
// Exit code 7 also fires when the effective rule configuration contains zero
// rules, which opengrep treats as an invalid configuration.
var exitCodeMeanings = map[int]string{
	2:  "scanner failed unexpectedly",
	3:  "invalid syntax in scanned code",
	4:  "invalid pattern in rule schema",
	5:  "rule configuration is not valid YAML",
	7:  "rule configuration contains no valid rules",
	8:  "unsupported language specified",
	13: "invalid API key",
}

func exitCodeMeaning(exitCode int) string {
	if meaning, ok := exitCodeMeanings[exitCode]; ok {
		return meaning
	}
	return "unknown error"
}

// ansiEscapeRE matches ANSI terminal escape sequences (colors, cursor moves).
var ansiEscapeRE = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// maxStderrTail bounds how much scanner stderr is attached to logs and errors.
const maxStderrTail = 500

// SanitizeScannerStderr strips ANSI escape sequences and blank lines from
// scanner stderr and keeps only the tail, so it can be attached to logs and
// error details without flooding the console with banner art.
func SanitizeScannerStderr(stderr string) string {
	clean := ansiEscapeRE.ReplaceAllString(stderr, "")
	var lines []string
	for line := range strings.SplitSeq(clean, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	out := strings.Join(lines, " | ")
	if len(out) > maxStderrTail {
		out = "…" + out[len(out)-maxStderrTail:]
	}
	return out
}

// HandleSemgrepCompatibleErrors displays semgrep compatible errors in a user-friendly format.
// Returns true if there were any errors logged.
func HandleSemgrepCompatibleErrors(stdout []byte, stderr string, duration time.Duration, exitCode int, scannerName string) error {
	parsedOutput, err := ParseSemgrepCompatibleOutput(stdout)
	if err != nil {
		log.Error().Err(err).Msgf("failed to parse %s output", scannerName)
		return failure.Wrap(
			err,
			failure.CodeScannerOutputParseFailed,
			failure.StageScan,
			fmt.Sprintf("failed to parse %s output", scannerName),
			failure.WithDetail("scanner", scannerName),
		)
	}

	// "No config given" is what semgrep/opengrep emits when none of the
	// supplied rules target any language present in the scanned files —
	// e.g., a Java ruleset run against a Kotlin-only artifact. Treat this
	// as a cleanly empty result (zero findings) instead of a hard failure
	// so the caller doesn't fail an entire scan over a language gap.
	if isNoApplicableRulesOnly(parsedOutput.Errors) {
		log.Warn().
			Int("exit_code", exitCode).
			Dur("duration", duration).
			Str("scanner", scannerName).
			Msg("scanner found no rules applicable to detected languages; emitting empty result")
		return nil
	}

	if LogSemgrepCompatibleErrors(parsedOutput.Errors) {
		return failure.New(
			failure.CodeScannerExecutionFailed,
			failure.StageScan,
			fmt.Sprintf("%s execution failed with exit code %d", scannerName, exitCode),
			failure.WithDetail("scanner", scannerName),
			failure.WithDetail("exit_code", fmt.Sprintf("%d", exitCode)),
		)
	}

	meaning := exitCodeMeaning(exitCode)
	stderrTail := SanitizeScannerStderr(stderr)
	logEvent := log.Error().
		Int("exit_code", exitCode).
		Dur("duration", duration)
	if stderrTail != "" {
		logEvent = logEvent.Str("stderr", stderrTail)
	}
	logEvent.Msgf("%s failed: %s", scannerName, meaning)

	opts := []failure.Option{
		failure.WithDetail("scanner", scannerName),
		failure.WithDetail("exit_code", fmt.Sprintf("%d", exitCode)),
	}
	if stderrTail != "" {
		opts = append(opts, failure.WithDetail("stderr", stderrTail))
	}
	return failure.New(
		failure.CodeScannerExecutionFailed,
		failure.StageScan,
		fmt.Sprintf("%s execution failed with exit code %d (%s)", scannerName, exitCode, meaning),
		opts...,
	)
}

// isNoApplicableRulesOnly reports whether every error in errs is a "No config
// given" error. Semgrep/opengrep emits this when the supplied rules don't
// target any language present in the scanned files; it's not a real failure,
// just a signal that scanning produces zero findings here.
func isNoApplicableRulesOnly(errs []entities.SemgrepError) bool {
	if len(errs) == 0 {
		return false
	}
	for _, e := range errs {
		if !strings.Contains(strings.ToLower(e.Message), "no config given") {
			return false
		}
	}
	return true
}
