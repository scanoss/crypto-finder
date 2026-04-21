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

package opengrep

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/failure"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// checkOpengrepAvailable checks if opengrep is installed.
func checkOpengrepAvailable(t *testing.T) {
	t.Helper()
	path, err := exec.LookPath("opengrep")
	if err != nil {
		t.Skip("opengrep not found in PATH - skipping integration test (install with: curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/v1.12.1/install.sh | bash)")
	}

	cmd := exec.CommandContext(context.Background(), path, "--version")
	output, err := cmd.CombinedOutput()
	if err == nil {
		return
	}

	if isOpengrepEnvironmentIssue(err, string(output)) {
		t.Skipf("opengrep is present but unusable in this environment: %s", strings.TrimSpace(string(output)))
	}
}

func skipIfOpengrepEnvironmentIssue(t *testing.T, err error) {
	t.Helper()

	if isOpengrepEnvironmentIssue(err, "") {
		t.Skipf("opengrep is present but unusable in this environment: %v", err)
	}
}

func isOpengrepEnvironmentIssue(err error, output string) bool {
	for _, text := range opengrepIssueTexts(err, output) {
		if strings.Contains(text, "operation not permitted") ||
			strings.Contains(text, "permission denied") ||
			strings.Contains(text, "semgrep.log") {
			return true
		}
	}

	return false
}

func opengrepIssueTexts(err error, output string) []string {
	texts := make([]string, 0, 4)
	if output != "" {
		texts = append(texts, strings.ToLower(output))
	}
	for current := err; current != nil; current = errors.Unwrap(current) {
		texts = append(texts, strings.ToLower(current.Error()))
	}
	if structured, ok := failure.As(err); ok && structured.Cause != nil {
		texts = append(texts, strings.ToLower(structured.Cause.Error()))
	}
	return texts
}

func initializeScannerOrSkip(t *testing.T, config scanner.Config) *Scanner {
	t.Helper()

	s := NewScanner()
	err := s.Initialize(config)
	skipIfOpengrepEnvironmentIssue(t, err)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	return s
}

func TestScanner_Integration_Initialize(t *testing.T) {
	checkOpengrepAvailable(t)

	config := scanner.Config{
		Timeout: 30 * time.Second,
	}
	s := initializeScannerOrSkip(t, config)

	if s.executablePath == "" {
		t.Error("Executable path should be set after initialization")
	}

	if s.version == "" {
		t.Error("Version should be detected after initialization")
	}
}

func TestScanner_Integration_Scan(t *testing.T) {
	checkOpengrepAvailable(t)

	config := scanner.Config{
		Timeout: 30 * time.Second,
	}
	s := initializeScannerOrSkip(t, config)

	// Use our testdata
	target, err := filepath.Abs("../../../testdata/code/go")
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	ruleFile, err := filepath.Abs("../../../testdata/rules/go.yaml")
	if err != nil {
		t.Fatalf("Failed to get absolute path to rules: %v", err)
	}

	toolInfo := entities.ToolInfo{
		Name:    "opengrep",
		Version: s.version,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := s.Scan(ctx, target, []string{ruleFile}, toolInfo)
	skipIfOpengrepEnvironmentIssue(t, err)
	if err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}

	if report == nil {
		t.Fatal("Expected non-nil report")
	}

	// Verify report structure
	if report.Version == "" {
		t.Error("Report version should not be empty")
	}

	if report.Tool.Name != "opengrep" {
		t.Errorf("Expected tool name 'opengrep', got '%s'", report.Tool.Name)
	}

	// Our test code should have findings
	if len(report.Findings) == 0 {
		t.Log("Warning: No findings detected in testdata (expected at least some crypto usage)")
	}

	// If we have findings, verify their structure
	for i, finding := range report.Findings {
		if finding.FilePath == "" {
			t.Errorf("Finding[%d]: file path should not be empty", i)
		}

		if finding.Language == "" {
			t.Errorf("Finding[%d]: language should not be empty", i)
		}

		if len(finding.CryptographicAssets) == 0 {
			t.Errorf("Finding[%d]: should have at least one cryptographic asset", i)
		}

		for j, asset := range finding.CryptographicAssets {
			if len(asset.Rules) == 0 || asset.Rules[0].ID == "" {
				t.Errorf("Finding[%d], Asset[%d]: rule ID should not be empty", i, j)
			}

			if asset.StartLine == 0 {
				t.Errorf("Finding[%d], Asset[%d]: start line should not be 0", i, j)
			}
		}
	}
}

func TestScanner_Integration_GetInfo(t *testing.T) {
	checkOpengrepAvailable(t)

	config := scanner.Config{
		Timeout: 30 * time.Second,
	}
	s := initializeScannerOrSkip(t, config)

	info := s.GetInfo()

	if info.Name != "opengrep" {
		t.Errorf("Expected tool name 'opengrep', got '%s'", info.Name)
	}

	if info.Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestScanner_Integration_Scan_EmptyRules(t *testing.T) {
	checkOpengrepAvailable(t)

	config := scanner.Config{
		Timeout: 30 * time.Second,
	}
	s := initializeScannerOrSkip(t, config)

	target, err := filepath.Abs("../../../testdata/code")
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	toolInfo := entities.ToolInfo{Name: "opengrep", Version: "1.0.0"}

	ctx := context.Background()

	// Should error with empty rules
	_, err = s.Scan(ctx, target, []string{}, toolInfo)
	skipIfOpengrepEnvironmentIssue(t, err)

	if err == nil {
		t.Error("Expected error when scanning with empty rules")
	}
}

func TestScanner_Integration_Scan_Timeout(t *testing.T) {
	checkOpengrepAvailable(t)

	config := scanner.Config{
		Timeout: 1 * time.Nanosecond, // Very short timeout
	}
	s := initializeScannerOrSkip(t, config)

	target, err := filepath.Abs("../../../testdata/code")
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	ruleFile, err := filepath.Abs("../../../testdata/rules/go.yaml")
	if err != nil {
		t.Fatalf("Failed to get absolute path to rules: %v", err)
	}

	toolInfo := entities.ToolInfo{Name: "opengrep", Version: "1.0.0"}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	_, err = s.Scan(ctx, target, []string{ruleFile}, toolInfo)
	skipIfOpengrepEnvironmentIssue(t, err)

	// Should timeout
	if err == nil {
		t.Log("Warning: Expected timeout error (may pass if scan is very fast)")
	}
}
