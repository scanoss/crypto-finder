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

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
	scanutil "github.com/scanoss/crypto-finder/internal/scan"
	"github.com/scanoss/crypto-finder/internal/scanner/semgrep"
)

func validateScanFlags(target string) error {
	normalizedLanguages, err := scanutil.ValidateFlags(target, scanutil.ValidationOptions{
		RuleFiles:        scanRules,
		RuleDirs:         scanRuleDirs,
		NoRemoteRules:    scanNoRemoteRules,
		Scanner:          scanScanner,
		AllowedScanners:  AllowedScanners,
		Interfile:        scanInterfile,
		InterfileScanner: semgrep.ScannerName,
		Format:           scanFormat,
		SupportedFormats: SupportedFormats,
		Languages:        scanLanguages,
		ScanDependencies: scanDependencies,
		ExportCallgraph:  scanExportCallgraph,
	})
	if err != nil {
		return err
	}
	scanLanguages = normalizedLanguages
	return nil
}

func TestValidateScanFlags(t *testing.T) {
	// Save original values
	origRules := scanRules
	origRuleDirs := scanRuleDirs
	origNoRemoteRules := scanNoRemoteRules
	origScanner := scanScanner
	origFormat := scanFormat
	origLanguages := scanLanguages
	origInterfile := scanInterfile
	origScanDependencies := scanDependencies
	origScanExportCallgraph := scanExportCallgraph
	origJavaJDKMajor := scanJavaJDKMajor
	origJavaJDKHomes := scanJavaJDKHomes

	defer func() {
		// Restore original values
		scanRules = origRules
		scanRuleDirs = origRuleDirs
		scanNoRemoteRules = origNoRemoteRules
		scanScanner = origScanner
		scanFormat = origFormat
		scanLanguages = origLanguages
		scanInterfile = origInterfile
		scanDependencies = origScanDependencies
		scanExportCallgraph = origScanExportCallgraph
		scanJavaJDKMajor = origJavaJDKMajor
		scanJavaJDKHomes = origJavaJDKHomes
	}()

	t.Run("valid target with rules", func(t *testing.T) {
		tempDir := t.TempDir()
		scanRules = []string{"rule.yaml"}
		scanRuleDirs = []string{}
		scanNoRemoteRules = false
		scanScanner = "opengrep"
		scanFormat = "json"
		scanLanguages = []string{}

		err := validateScanFlags(tempDir)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})

	t.Run("nonexistent target", func(t *testing.T) {
		scanRules = []string{"rule.yaml"}
		scanRuleDirs = []string{}
		scanNoRemoteRules = false
		scanScanner = "opengrep"
		scanFormat = "json"

		err := validateScanFlags("/path/that/does/not/exist")
		if err == nil {
			t.Error("Expected error for nonexistent target")
		}
	})

	t.Run("no rules and no remote rules", func(t *testing.T) {
		tempDir := t.TempDir()
		scanRules = []string{}
		scanRuleDirs = []string{}
		scanNoRemoteRules = true
		scanScanner = "opengrep"
		scanFormat = "json"

		err := validateScanFlags(tempDir)
		if err == nil {
			t.Error("Expected error when no rules specified")
		}
	})

	t.Run("no rules but remote rules enabled", func(t *testing.T) {
		tempDir := t.TempDir()
		scanRules = []string{}
		scanRuleDirs = []string{}
		scanNoRemoteRules = false
		scanScanner = "opengrep"
		scanFormat = "json"

		err := validateScanFlags(tempDir)
		if err != nil {
			t.Errorf("Expected no error with remote rules enabled, got: %v", err)
		}
	})

	t.Run("invalid scanner", func(t *testing.T) {
		tempDir := t.TempDir()
		scanRules = []string{"rule.yaml"}
		scanRuleDirs = []string{}
		scanNoRemoteRules = false
		scanScanner = "invalid-scanner"
		scanFormat = "json"

		err := validateScanFlags(tempDir)
		if err == nil {
			t.Error("Expected error for invalid scanner")
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		tempDir := t.TempDir()
		scanRules = []string{"rule.yaml"}
		scanRuleDirs = []string{}
		scanNoRemoteRules = false
		scanScanner = "opengrep"
		scanFormat = "invalid-format"

		err := validateScanFlags(tempDir)
		if err == nil {
			t.Error("Expected error for invalid format")
		}
	})

	t.Run("language normalization", func(t *testing.T) {
		tempDir := t.TempDir()
		scanRules = []string{"rule.yaml"}
		scanRuleDirs = []string{}
		scanNoRemoteRules = false
		scanScanner = "opengrep"
		scanFormat = "json"
		scanLanguages = []string{"  JAVA  ", "Python", "GO"}

		err := validateScanFlags(tempDir)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}

		// Verify languages were normalized
		expected := []string{"java", "python", "go"}
		for i, lang := range scanLanguages {
			if lang != expected[i] {
				t.Errorf("Language[%d]: expected '%s', got '%s'", i, expected[i], lang)
			}
		}
	})

	t.Run("with rules directory", func(t *testing.T) {
		tempDir := t.TempDir()
		ruleDir := filepath.Join(tempDir, "rules")
		if err := os.MkdirAll(ruleDir, 0o755); err != nil {
			t.Fatalf("Failed to create rules directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(ruleDir, "rule.yaml"), []byte("rules: []\n"), 0o600); err != nil {
			t.Fatalf("Failed to create rule file: %v", err)
		}

		scanRules = []string{}
		scanRuleDirs = []string{ruleDir}
		scanNoRemoteRules = false
		scanScanner = "semgrep"
		scanFormat = "cyclonedx"

		err := validateScanFlags(tempDir)
		if err != nil {
			t.Errorf("Expected no error with rules directory, got: %v", err)
		}
	})

	t.Run("interfile with non-semgrep scanner", func(t *testing.T) {
		tempDir := t.TempDir()
		scanRules = []string{"rule.yaml"}
		scanRuleDirs = []string{}
		scanNoRemoteRules = false
		scanScanner = "opengrep"
		scanFormat = "json"
		scanInterfile = true

		err := validateScanFlags(tempDir)
		if err == nil {
			t.Error("Expected error when --interfile is used with non-semgrep scanner")
		}
	})

	t.Run("interfile with semgrep scanner", func(t *testing.T) {
		tempDir := t.TempDir()
		scanRules = []string{"rule.yaml"}
		scanRuleDirs = []string{}
		scanNoRemoteRules = false
		scanScanner = "semgrep"
		scanFormat = "json"
		scanInterfile = true

		err := validateScanFlags(tempDir)
		if err != nil {
			t.Errorf("Expected no error with --interfile and semgrep scanner, got: %v", err)
		}
	})

	t.Run("export callgraph allowed without dependency scanning", func(t *testing.T) {
		tempDir := t.TempDir()
		scanRules = []string{"rule.yaml"}
		scanRuleDirs = []string{}
		scanNoRemoteRules = false
		scanScanner = "semgrep"
		scanFormat = "json"
		scanDependencies = false
		scanExportCallgraph = filepath.Join(tempDir, "cg.json")

		err := validateScanFlags(tempDir)
		if err != nil {
			t.Errorf("Expected no error when --export-callgraph is used without --scan-dependencies, got: %v", err)
		}
	})
}

func TestApplyTestSkipPatterns(t *testing.T) {
	base := []string{"vendor", "custom/"}

	withTestsExcluded := applyTestSkipPatterns(base, false)
	if !sliceContains(withTestsExcluded, "vendor") || !sliceContains(withTestsExcluded, "src/test/") || !sliceContains(withTestsExcluded, "**/*Test.java") {
		t.Fatalf("applyTestSkipPatterns(false) = %#v, want base + test patterns", withTestsExcluded)
	}

	withTestsIncluded := applyTestSkipPatterns(base, true)
	if sliceContains(withTestsIncluded, "src/test/") || sliceContains(withTestsIncluded, "**/*Test.java") {
		t.Fatalf("applyTestSkipPatterns(true) = %#v, should not append test patterns", withTestsIncluded)
	}
}

func sliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestBuildStandaloneCallGraphResult_GoDirectChain(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte("module example.com/app\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tempDir, "helper"), 0o755); err != nil {
		t.Fatalf("mkdir helper: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(`package main

import "example.com/app/helper"

func main() {
	_ = helper.Encrypt(nil)
}
`), 0o600); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "helper", "helper.go"), []byte(`package helper

import "crypto/aes"

func Encrypt(key []byte) error {
	_, err := aes.NewCipher(key)
	return err
}
`), 0o600); err != nil {
		t.Fatalf("write helper.go: %v", err)
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "helper/helper.go",
			Language: "go",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 6,
				EndLine:   6,
				Match:     "aes.NewCipher(key)",
				Rules:     []entities.RuleInfo{{ID: "go.crypto.aes.newcipher", Message: "AES usage", Severity: "INFO"}},
				Status:    "pending",
				Metadata:  map[string]string{"api": "aes.NewCipher", "algorithmName": "AES"},
				Source:    "direct",
			}},
		}},
	}

	result, err := buildStandaloneCallGraphResult(tempDir, report, nil, javaruntime.Config{}, false)
	if err != nil {
		t.Fatalf("buildStandaloneCallGraphResult: %v", err)
	}

	engine.AssignFindingIDs(report)

	out := filepath.Join(t.TempDir(), "callgraph.json")
	if err := scanutil.ExportCallGraph(out, "json", result); err != nil {
		t.Fatalf("ExportCallGraph: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	var payload struct {
		FindingGraphs []struct {
			FindingID  string `json:"finding_id"`
			CallChains [][]struct {
				FunctionName string `json:"function_name"`
				FilePath     string `json:"file_path"`
				CryptoCall   *struct {
					FunctionName string `json:"function_name"`
				} `json:"crypto_call,omitempty"`
			} `json:"call_chains"`
		} `json:"finding_graphs"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(payload.FindingGraphs) != 1 {
		t.Fatalf("finding_graphs count = %d, want 1", len(payload.FindingGraphs))
	}
	if report.Findings[0].CryptographicAssets[0].FindingID == "" {
		t.Fatal("expected direct finding_id to be assigned")
	}
	if payload.FindingGraphs[0].FindingID != report.Findings[0].CryptographicAssets[0].FindingID {
		t.Fatalf("finding_id mismatch: export=%q report=%q", payload.FindingGraphs[0].FindingID, report.Findings[0].CryptographicAssets[0].FindingID)
	}
	if len(payload.FindingGraphs[0].CallChains) != 1 {
		t.Fatalf("call_chains count = %d, want 1", len(payload.FindingGraphs[0].CallChains))
	}
	chain := payload.FindingGraphs[0].CallChains[0]
	if len(chain) != 2 {
		t.Fatalf("chain length = %d, want 2", len(chain))
	}
	if chain[0].FunctionName != "example.com/app.main" {
		t.Fatalf("chain[0].function_name = %q, want example.com/app.main", chain[0].FunctionName)
	}
	if chain[1].FunctionName != "example.com/app/helper.Encrypt" {
		t.Fatalf("chain[1].function_name = %q, want example.com/app/helper.Encrypt", chain[1].FunctionName)
	}
	if chain[1].CryptoCall == nil || chain[1].CryptoCall.FunctionName != "crypto/aes.NewCipher" {
		t.Fatalf("unexpected crypto_call: %#v", chain[1].CryptoCall)
	}
}

func TestBuildStandaloneCallGraphResult_IncludesGoTestsWhenRequested(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte("module example.com/app\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "main_test.go"), []byte(`package main

import "crypto/aes"

func TestEncrypt() {
	_, _ = aes.NewCipher(nil)
}
`), 0o600); err != nil {
		t.Fatalf("write main_test.go: %v", err)
	}

	report := &entities.InterimReport{
		Version: "1.3",
		Tool:    entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "main_test.go",
			Language: "go",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 6,
				EndLine:   6,
				Match:     "aes.NewCipher(nil)",
				Rules:     []entities.RuleInfo{{ID: "go.crypto.aes.newcipher", Message: "AES usage", Severity: "INFO"}},
				Status:    "pending",
				Metadata:  map[string]string{"api": "aes.NewCipher", "algorithmName": "AES"},
				Source:    "direct",
			}},
		}},
	}

	result, err := buildStandaloneCallGraphResult(tempDir, report, nil, javaruntime.Config{}, true)
	if err != nil {
		t.Fatalf("buildStandaloneCallGraphResult: %v", err)
	}

	if result.CallGraph == nil {
		t.Fatal("expected call graph to be built")
	}
	if _, ok := result.CallGraph.Functions["example.com/app.TestEncrypt"]; !ok {
		t.Fatalf("expected test function to be present in call graph, got keys %#v", result.CallGraph.Functions)
	}
}

func TestScanCommand_DepMaxDepthFlagRemoved(t *testing.T) {
	if scanCmd.Flags().Lookup("dep-max-depth") != nil {
		t.Fatal("expected dep-max-depth flag to be removed")
	}
}

func TestCountFindings(t *testing.T) {
	t.Run("nil report", func(t *testing.T) {
		count := scanutil.CountFindings(nil)
		if count != 0 {
			t.Errorf("Expected count 0 for nil report, got %d", count)
		}
	})

	t.Run("empty report", func(t *testing.T) {
		report := &entities.InterimReport{
			Findings: []entities.Finding{},
		}
		count := scanutil.CountFindings(report)
		if count != 0 {
			t.Errorf("Expected count 0 for empty report, got %d", count)
		}
	})

	t.Run("single finding with one asset", func(t *testing.T) {
		report := &entities.InterimReport{
			Findings: []entities.Finding{
				{
					FilePath: "test.go",
					CryptographicAssets: []entities.CryptographicAsset{
						{
							Rules: []entities.RuleInfo{{ID: "test-rule"}},
						},
					},
				},
			},
		}
		count := scanutil.CountFindings(report)
		if count != 1 {
			t.Errorf("Expected count 1, got %d", count)
		}
	})

	t.Run("multiple findings with multiple assets", func(t *testing.T) {
		report := &entities.InterimReport{
			Findings: []entities.Finding{
				{
					FilePath: "test1.go",
					CryptographicAssets: []entities.CryptographicAsset{
						{Rules: []entities.RuleInfo{{ID: "rule1"}}},
						{Rules: []entities.RuleInfo{{ID: "rule2"}}},
					},
				},
				{
					FilePath: "test2.go",
					CryptographicAssets: []entities.CryptographicAsset{
						{Rules: []entities.RuleInfo{{ID: "rule3"}}},
					},
				},
			},
		}
		count := scanutil.CountFindings(report)
		if count != 3 {
			t.Errorf("Expected count 3, got %d", count)
		}
	})

	t.Run("findings with no assets", func(t *testing.T) {
		report := &entities.InterimReport{
			Findings: []entities.Finding{
				{
					FilePath:            "test.go",
					CryptographicAssets: []entities.CryptographicAsset{},
				},
			},
		}
		count := scanutil.CountFindings(report)
		if count != 0 {
			t.Errorf("Expected count 0 for findings with no assets, got %d", count)
		}
	})
}

func TestAllowedScannersAndFormats(t *testing.T) {
	t.Run("AllowedScanners contains expected values", func(t *testing.T) {
		if len(AllowedScanners) == 0 {
			t.Error("AllowedScanners should not be empty")
		}

		expectedScanners := []string{"opengrep", "semgrep"}
		for _, scanner := range expectedScanners {
			found := false
			for _, allowed := range AllowedScanners {
				if allowed == scanner {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected scanner '%s' not found in AllowedScanners", scanner)
			}
		}
	})

	t.Run("SupportedFormats contains expected values", func(t *testing.T) {
		if len(SupportedFormats) == 0 {
			t.Error("SupportedFormats should not be empty")
		}

		expectedFormats := []string{"json", "cyclonedx"}
		for _, format := range expectedFormats {
			found := false
			for _, supported := range SupportedFormats {
				if supported == format {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected format '%s' not found in SupportedFormats", format)
			}
		}
	})
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string // Expected duration as string (e.g., "24h0m0s")
		expectError bool
	}{
		// Standard Go formats (should pass through to time.ParseDuration)
		{name: "minutes", input: "10m", expected: "10m0s", expectError: false},
		{name: "hours", input: "1h", expected: "1h0m0s", expectError: false},
		{name: "seconds", input: "30s", expected: "30s", expectError: false},
		{name: "combined", input: "1h30m", expected: "1h30m0s", expectError: false},

		// Days format
		{name: "1 day", input: "1d", expected: "24h0m0s", expectError: false},
		{name: "30 days", input: "30d", expected: "720h0m0s", expectError: false},
		{name: "90 days", input: "90d", expected: "2160h0m0s", expectError: false},
		{name: "fractional days", input: "0.5d", expected: "12h0m0s", expectError: false},
		{name: "1.5 days", input: "1.5d", expected: "36h0m0s", expectError: false},

		// Weeks format
		{name: "1 week", input: "1w", expected: "168h0m0s", expectError: false},
		{name: "2 weeks", input: "2w", expected: "336h0m0s", expectError: false},
		{name: "fractional weeks", input: "0.5w", expected: "84h0m0s", expectError: false},

		// Invalid formats
		{name: "invalid - empty", input: "", expected: "", expectError: true},
		{name: "invalid - just letter", input: "d", expected: "", expectError: true},
		{name: "invalid - no number", input: "abcd", expected: "", expectError: true},
		{name: "invalid - invalid unit", input: "10x", expected: "", expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			duration, err := scanutil.ParseDuration(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for input '%s', but got none", tt.input)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for input '%s': %v", tt.input, err)
				return
			}

			if duration.String() != tt.expected {
				t.Errorf("Input '%s': expected %s, got %s", tt.input, tt.expected, duration.String())
			}
		})
	}
}
