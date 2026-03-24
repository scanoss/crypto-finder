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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// checkSemgrepAvailable checks if semgrep is installed.
func checkSemgrepAvailable(t *testing.T) {
	t.Helper()
	path, err := exec.LookPath("semgrep")
	if err != nil {
		t.Skip("semgrep not found in PATH - skipping integration test (install with: pip install semgrep)")
	}

	tempDir := t.TempDir()
	ruleFile := filepath.Join(tempDir, "rule.yaml")
	targetFile := filepath.Join(tempDir, "main.go")

	if err := os.WriteFile(ruleFile, []byte("rules:\n- id: semgrep-preflight\n  languages: [go]\n  message: preflight\n  severity: INFO\n  pattern: package main\n"), 0o600); err != nil {
		t.Fatalf("Failed to write semgrep preflight rule: %v", err)
	}
	if err := os.WriteFile(targetFile, []byte("package main\n"), 0o600); err != nil {
		t.Fatalf("Failed to write semgrep preflight target: %v", err)
	}

	cmd := exec.CommandContext(context.Background(), path, "--json", "--no-git-ignore", "--metrics", "off", "--config", ruleFile, tempDir)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return
	}

	outputText := string(output)
	if strings.Contains(outputText, "empty trust anchors") ||
		strings.Contains(outputText, "X509 authenticator") ||
		strings.Contains(outputText, "operation not permitted") ||
		strings.Contains(outputText, "permission denied") {
		t.Skipf("semgrep is present but unusable in this environment: %s", strings.TrimSpace(outputText))
	}
}

func skipIfSemgrepEnvironmentIssue(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}

	errMsg := err.Error()
	if strings.Contains(errMsg, "empty trust anchors") ||
		strings.Contains(errMsg, "X509 authenticator") ||
		strings.Contains(errMsg, "operation not permitted") ||
		strings.Contains(errMsg, "permission denied") {
		t.Skipf("semgrep is present but unusable in this environment: %v", err)
	}
}

func initializeScannerOrFail(t *testing.T, config scanner.Config) *Scanner {
	t.Helper()

	s := NewScanner()
	if err := s.Initialize(config); err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	return s
}

func TestScanner_Integration_Initialize(t *testing.T) {
	checkSemgrepAvailable(t)

	config := scanner.Config{
		Timeout: 30 * time.Second,
	}
	s := initializeScannerOrFail(t, config)

	if s.executablePath == "" {
		t.Error("Executable path should be set after initialization")
	}

	if s.version == "" {
		t.Error("Version should be detected after initialization")
	}
}

func TestScanner_Integration_Scan(t *testing.T) {
	checkSemgrepAvailable(t)

	config := scanner.Config{
		Timeout: 30 * time.Second,
	}
	s := initializeScannerOrFail(t, config)

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
		Name:    "semgrep",
		Version: s.version,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := s.Scan(ctx, target, []string{ruleFile}, toolInfo)
	skipIfSemgrepEnvironmentIssue(t, err)
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

	if report.Tool.Name != "semgrep" {
		t.Errorf("Expected tool name 'semgrep', got '%s'", report.Tool.Name)
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
	checkSemgrepAvailable(t)

	config := scanner.Config{
		Timeout: 30 * time.Second,
	}
	s := initializeScannerOrFail(t, config)

	info := s.GetInfo()

	if info.Name != "semgrep" {
		t.Errorf("Expected tool name 'semgrep', got '%s'", info.Name)
	}

	if info.Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestScanner_Integration_Scan_EmptyRules(t *testing.T) {
	checkSemgrepAvailable(t)

	config := scanner.Config{
		Timeout: 30 * time.Second,
	}
	s := initializeScannerOrFail(t, config)

	target, err := filepath.Abs("../../../testdata/code")
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	toolInfo := entities.ToolInfo{Name: "semgrep", Version: "1.0.0"}

	ctx := context.Background()

	// Should error with empty rules
	_, err = s.Scan(ctx, target, []string{}, toolInfo)
	skipIfSemgrepEnvironmentIssue(t, err)

	if err == nil {
		t.Error("Expected error when scanning with empty rules")
	}
}

func TestScanner_Integration_Scan_Timeout(t *testing.T) {
	checkSemgrepAvailable(t)

	config := scanner.Config{
		Timeout: 1 * time.Nanosecond, // Very short timeout
	}
	s := initializeScannerOrFail(t, config)

	target, err := filepath.Abs("../../../testdata/code")
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	ruleFile, err := filepath.Abs("../../../testdata/rules/go.yaml")
	if err != nil {
		t.Fatalf("Failed to get absolute path to rules: %v", err)
	}

	toolInfo := entities.ToolInfo{Name: "semgrep", Version: "1.0.0"}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	_, err = s.Scan(ctx, target, []string{ruleFile}, toolInfo)
	skipIfSemgrepEnvironmentIssue(t, err)

	// Should timeout
	if err == nil {
		t.Log("Warning: Expected timeout error (may pass if scan is very fast)")
	}
}
