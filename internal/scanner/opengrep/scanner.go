// Package opengrep provides the OpenGrep scanner adapter implementation.
// It executes OpenGrep and transforms its output into the interim JSON format.
package opengrep

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/semgrep"
)

// ScannerName is the identifier for the OpenGrep scanner.
const ScannerName = "opengrep"

// MinimumVersion is the minimum required version of OpenGrep.
const MinimumVersion = "1.12.1"

// Package-level variables for testing (can be overridden in tests).
var (
	lookPath      = exec.LookPath
	commandOutput = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).Output()
	}
)

// Scanner implements the scanner.Scanner interface for OpenGrep.
type Scanner struct {
	executablePath string
	version        string
	timeout        time.Duration
	workDir        string
	env            map[string]string
	extraArgs      []string
	skipPatterns   []string
}

// NewScanner creates a new OpenGrep adapter with default settings.
func NewScanner() *Scanner {
	return &Scanner{
		executablePath: "opengrep", // Will search PATH
		timeout:        10 * time.Minute,
	}
}

// Initialize validates that OpenGrep is available and properly configured.
func (s *Scanner) Initialize(config scanner.Config) error {
	// Use provided executable path or default
	if config.ExecutablePath != "" {
		s.executablePath = config.ExecutablePath
	}

	// Detect opengrep in PATH
	path, err := lookPath(s.executablePath)
	if err != nil {
		return fmt.Errorf("opengrep not found in PATH: %w (install with: curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash)", err)
	}
	s.executablePath = path

	// Get opengrep version
	s.version, err = s.detectVersion()
	if err != nil {
		return fmt.Errorf("failed to detect opengrep version: %w", err)
	}

	// Validate minimum version
	if err := s.validateVersion(); err != nil {
		return err
	}

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

// Scan executes OpenGrep against the target with the given rule paths.
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

	// Build opengrep command
	args := s.buildCommand(target, rulePaths)

	// Execute opengrep
	output, stderr, err := s.execute(ctx, args)
	if err != nil {
		cmdStr := fmt.Sprintf("%s %s", s.executablePath, strings.Join(args, " "))
		log.Debug().
			Str("command", cmdStr).
			Str("stderr", stderr).
			Msg("opengrep command failed")

		return nil, err
	}

	// Parse opengrep JSON output (uses same format as Semgrep)
	opengrepResults, err := semgrep.ParseSemgrepCompatibleOutput(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse opengrep output: %w", err)
	}

	semgrep.LogSemgrepCompatibleErrors(opengrepResults.Errors)

	// Transform to interim format (reuse Semgrep transformer)
	report := semgrep.TransformSemgrepCompatibleOutputToInterimFormat(opengrepResults, toolInfo, target)

	return report, nil
}

// GetInfo returns metadata about the OpenGrep adapter.
func (s *Scanner) GetInfo() scanner.Info {
	return scanner.Info{
		Name:        ScannerName,
		Version:     s.version,
		Description: "Static analysis tool for detecting cryptographic algorithm usage with taint analysis",
	}
}

// detectVersion runs `opengrep --version` to get the installed version.
func (s *Scanner) detectVersion() (string, error) {
	output, err := commandOutput(s.executablePath, "--version")
	if err != nil {
		return "", fmt.Errorf("failed to get opengrep version: %w", err)
	}

	versionStr := strings.TrimSpace(string(output))
	return versionStr, nil
}

// validateVersion checks that the installed OpenGrep version meets the minimum requirement.
// this is mostly because opengrep supports taint mode from version 1.12.0.
func (s *Scanner) validateVersion() error {
	if s.version == "" || s.version == "unknown" {
		return fmt.Errorf("could not determine opengrep version")
	}

	currentVer, err := version.NewVersion(s.version)
	if err != nil {
		return err
	}

	minVer, err := version.NewVersion(MinimumVersion)
	if err != nil {
		return err
	}

	if currentVer.LessThan(minVer) {
		return fmt.Errorf("opengrep version %s is below minimum required version %s (upgrade with: curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash)", s.version, MinimumVersion)
	}

	return nil
}

// buildCommand constructs the opengrep command arguments.
func (s *Scanner) buildCommand(target string, rulePaths []string) []string {
	args := []string{
		"--json",            // JSON output format
		"--no-git-ignore",   // Scan all files, don't respect .gitignore // TODO: Should be configurable?
		"--taint-intrafile", // Enable taint analysis
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

// execute runs the opengrep command and captures stdout/stderr.
func (s *Scanner) execute(ctx context.Context, args []string) (stdout []byte, stderr string, err error) {
	spinner, err := pterm.DefaultSpinner.
		WithRemoveWhenDone(true).
		Start("Running OpenGrep scan...")
	if err != nil {
		return nil, "", err
	}

	cmd := exec.CommandContext(ctx, s.executablePath, args...)

	if s.workDir != "" {
		cmd.Dir = s.workDir
	}

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

	if ctx.Err() != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Error().
				Dur("duration", duration).
				Msg("opengrep execution timed out")
			return nil, stderr, fmt.Errorf("opengrep execution timed out after %v", s.timeout)
		}
		return nil, stderr, fmt.Errorf("opengrep execution canceled: %w", ctx.Err())
	}

	// OpenGrep exit codes (same as Semgrep):
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
					Msgf("opengrep completed in %.2fs (exit code: %d)", duration.Seconds(), exitCode)
				return stdout, stderr, nil
			}
		}

		err = semgrep.HandleSemgrepCompatibleErrors(stdout, duration, exitCode, ScannerName)
		if err != nil {
			return nil, stderr, err
		}
		return nil, stderr, err
	}

	exitCode = 0
	log.Info().
		Dur("duration", duration).
		Msgf("opengrep completed in %.2fs (exit code: %d)", duration.Seconds(), exitCode)

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
