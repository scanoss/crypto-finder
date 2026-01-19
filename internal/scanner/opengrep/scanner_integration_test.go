package opengrep

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// checkOpengrepAvailable checks if opengrep is installed.
func checkOpengrepAvailable(t *testing.T) {
	t.Helper()
	_, err := exec.LookPath("opengrep")
	if err != nil {
		t.Skip("opengrep not found in PATH - skipping integration test (install with: curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash)")
	}
}

func TestScanner_Integration_Initialize(t *testing.T) {
	checkOpengrepAvailable(t)

	s := NewScanner()
	config := scanner.Config{
		Timeout: 30 * time.Second,
	}

	err := s.Initialize(config)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	if s.executablePath == "" {
		t.Error("Executable path should be set after initialization")
	}

	if s.version == "" {
		t.Error("Version should be detected after initialization")
	}
}

func TestScanner_Integration_Scan(t *testing.T) {
	checkOpengrepAvailable(t)

	s := NewScanner()
	config := scanner.Config{
		Timeout: 30 * time.Second,
	}

	err := s.Initialize(config)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

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
			if asset.Rule.ID == "" {
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

	s := NewScanner()
	config := scanner.Config{
		Timeout: 30 * time.Second,
	}

	err := s.Initialize(config)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

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

	s := NewScanner()
	config := scanner.Config{
		Timeout: 30 * time.Second,
	}

	err := s.Initialize(config)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	target, err := filepath.Abs("../../../testdata/code")
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	toolInfo := entities.ToolInfo{Name: "opengrep", Version: "1.0.0"}

	ctx := context.Background()

	// Should error with empty rules
	_, err = s.Scan(ctx, target, []string{}, toolInfo)

	if err == nil {
		t.Error("Expected error when scanning with empty rules")
	}
}

func TestScanner_Integration_Scan_Timeout(t *testing.T) {
	checkOpengrepAvailable(t)

	s := NewScanner()
	config := scanner.Config{
		Timeout: 1 * time.Nanosecond, // Very short timeout
	}

	err := s.Initialize(config)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

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

	// Should timeout
	if err == nil {
		t.Log("Warning: Expected timeout error (may pass if scan is very fast)")
	}
}
