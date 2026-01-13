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
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestValidateScanFlags(t *testing.T) {
	// Save original values
	origRules := scanRules
	origRuleDirs := scanRuleDirs
	origNoRemoteRules := scanNoRemoteRules
	origScanner := scanScanner
	origFormat := scanFormat
	origLanguages := scanLanguages

	defer func() {
		// Restore original values
		scanRules = origRules
		scanRuleDirs = origRuleDirs
		scanNoRemoteRules = origNoRemoteRules
		scanScanner = origScanner
		scanFormat = origFormat
		scanLanguages = origLanguages
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
		scanRules = []string{}
		scanRuleDirs = []string{"/rules/dir"}
		scanNoRemoteRules = false
		scanScanner = "semgrep"
		scanFormat = "cyclonedx"

		err := validateScanFlags(tempDir)
		if err != nil {
			t.Errorf("Expected no error with rules directory, got: %v", err)
		}
	})
}

func TestCountFindings(t *testing.T) {
	t.Run("nil report", func(t *testing.T) {
		count := countFindings(nil)
		if count != 0 {
			t.Errorf("Expected count 0 for nil report, got %d", count)
		}
	})

	t.Run("empty report", func(t *testing.T) {
		report := &entities.InterimReport{
			Findings: []entities.Finding{},
		}
		count := countFindings(report)
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
							Rule: entities.RuleInfo{ID: "test-rule"},
						},
					},
				},
			},
		}
		count := countFindings(report)
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
						{Rule: entities.RuleInfo{ID: "rule1"}},
						{Rule: entities.RuleInfo{ID: "rule2"}},
					},
				},
				{
					FilePath: "test2.go",
					CryptographicAssets: []entities.CryptographicAsset{
						{Rule: entities.RuleInfo{ID: "rule3"}},
					},
				},
			},
		}
		count := countFindings(report)
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
		count := countFindings(report)
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
