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

// Package semgrep provides the Semgrep scanner adapter implementation.
// It executes Semgrep and transforms its output into the interim JSON format.
package semgrep

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// ScannerName is the identifier for the Semgrep scanner.
const ScannerName = "semgrep"

// Scanner implements the scanner.Scanner interface for Semgrep.
type Scanner struct {
	executablePath string
	version        string
	timeout        time.Duration
	workDir        string
	env            map[string]string
	extraArgs      []string
	skipPatterns   []string
}

// NewScanner creates a new Semgrep adapter with default settings.
func NewScanner() *Scanner {
	return &Scanner{
		executablePath: "semgrep", // Will search PATH
		timeout:        10 * time.Minute,
	}
}

// Initialize validates that Semgrep is available and properly configured.
func (s *Scanner) Initialize(config scanner.Config) error {
	// Use provided executable path or default
	if config.ExecutablePath != "" {
		s.executablePath = config.ExecutablePath
	}

	// Detect semgrep in PATH
	path, err := exec.LookPath(s.executablePath)
	if err != nil {
		return fmt.Errorf("semgrep not found in PATH: %w (install with: pip install semgrep)", err)
	}
	s.executablePath = path

	// Get semgrep version
	s.version = s.detectVersion()

	// Apply configuration
	if config.Timeout > 0 {
		s.timeout = config.Timeout
	}
	if config.WorkDir != "" {
		s.workDir = config.WorkDir
	}
	if config.Env != nil {
		s.env = config.Env
	}
	if config.ExtraArgs != nil {
		s.extraArgs = config.ExtraArgs
	}
	if config.SkipPatterns != nil {
		s.skipPatterns = config.SkipPatterns
	}

	return nil
}

// Scan executes Semgrep against the target with the given rule paths.
func (s *Scanner) Scan(ctx context.Context, target string, rulePaths []string, toolInfo entities.ToolInfo) (*entities.InterimReport, error) {
	if len(rulePaths) == 0 {
		return nil, fmt.Errorf("no rule paths provided")
	}

	// Apply timeout to context if not already set
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}

	// Build semgrep command
	args := s.buildCommand(target, rulePaths)

	// Execute semgrep
	output, stderr, err := s.execute(ctx, args)
	if err != nil {
		cmdStr := fmt.Sprintf("%s %s", s.executablePath, strings.Join(args, " "))
		log.Debug().
			Str("command", cmdStr).
			Str("stderr", stderr).
			Msg("semgrep command failed")

		return nil, err
	}

	semgrepResults, err := ParseSemgrepCompatibleOutput(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	LogSemgrepCompatibleErrors(semgrepResults.Errors)

	report := TransformSemgrepCompatibleOutputToInterimFormat(semgrepResults, toolInfo, target)

	return report, nil
}

// GetInfo returns metadata about the Semgrep adapter.
func (s *Scanner) GetInfo() scanner.Info {
	return scanner.Info{
		Name:        ScannerName,
		Version:     s.version,
		Description: "Static analysis tool for detecting cryptographic algorithm usage",
	}
}

// detectVersion runs `semgrep --version` to get the installed version.
func (s *Scanner) detectVersion() string {
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, s.executablePath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown" // Non-fatal, continue without version
	}

	// Parse version from output (e.g., "1.45.0")
	return strings.TrimSpace(string(output))
}

// buildCommand constructs the semgrep command arguments.
func (s *Scanner) buildCommand(target string, rulePaths []string) []string {
	args := []string{
		"--json",           // JSON output format
		"--no-git-ignore",  // Scan all files, don't respect .gitignore
		"--metrics", "off", // Disable telemetry
	}

	for _, rulePath := range rulePaths {
		args = append(args, "--config", rulePath)
	}

	for _, pattern := range s.skipPatterns {
		args = append(args, "--exclude", pattern)
	}

	if len(s.extraArgs) > 0 {
		args = append(args, s.extraArgs...)
	}

	args = append(args, target)

	return args
}

// execute runs the semgrep command and captures stdout/stderr.
func (s *Scanner) execute(ctx context.Context, args []string) (stdout []byte, stderr string, err error) {
	spinner, err := pterm.DefaultSpinner.
		WithRemoveWhenDone(true).
		Start("Running Semgrep scan...")
	if err != nil {
		return nil, "", err
	}

	cmd := exec.CommandContext(ctx, s.executablePath, args...)

	// Set working directory if specified
	if s.workDir != "" {
		cmd.Dir = s.workDir
	}

	// Set environment variables
	if len(s.env) > 0 {
		cmd.Env = append(cmd.Environ(), mapToEnvSlice(s.env)...)
	}

	startTime := time.Now()
	stderrBuf := &strings.Builder{}
	cmd.Stderr = stderrBuf
	stdout, err = cmd.Output()
	stderr = stderrBuf.String()
	duration := time.Since(startTime)

	if err != nil {
		spinner.Fail(fmt.Sprintf("OpenGrep failed after %.2fs", duration.Seconds()))
	} else {
		spinner.Success(fmt.Sprintf("OpenGrep completed in %.2fs", duration.Seconds()))
	}

	// Check for context cancellation/timeout
	if ctx.Err() != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Error().
				Dur("duration", duration).
				Msg("semgrep execution timed out")
			return nil, stderr, fmt.Errorf("semgrep execution timed out after %v", s.timeout)
		}
		return nil, stderr, fmt.Errorf("semgrep execution canceled: %w", ctx.Err())
	}

	// Semgrep exit codes:
	// 0 = success, no findings
	// 1 = findings detected (this is actually success for us)
	// >1 = error
	var exitCode int
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
			// Exit code 1 means findings were detected, which is not an error
			if exitCode == 1 {
				log.Info().
					Dur("duration", duration).
					Msgf("semgrep completed in %.2fs (exit code: %d)", duration.Seconds(), exitCode)
				return stdout, stderr, nil
			}
		}

		err = HandleSemgrepCompatibleErrors(stdout, duration, exitCode, ScannerName)
		if err != nil {
			fmt.Println(err)
			return nil, stderr, err
		}

		return nil, stderr, err
	}

	// Success with exit code 0
	exitCode = 0
	log.Info().
		Dur("duration", duration).
		Msgf("semgrep completed in %.2fs (exit code: %d)", duration.Seconds(), exitCode)

	return stdout, stderr, nil
}

// mapToEnvSlice converts a map to KEY=VALUE environment variable slice.
func mapToEnvSlice(envMap map[string]string) []string {
	env := make([]string, 0, len(envMap))
	for key, value := range envMap {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	return env
}
