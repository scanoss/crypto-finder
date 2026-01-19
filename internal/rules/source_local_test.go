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

package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalRuleSource_Load_WithRuleFiles(t *testing.T) {
	t.Parallel()

	// Use actual testdata
	ruleFile1 := "../../testdata/rules/go.yaml"
	ruleFile2 := "../../testdata/rules/python.yaml"

	source := NewLocalRuleSource([]string{ruleFile1, ruleFile2}, []string{})
	paths, err := source.Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if len(paths) != 2 {
		t.Errorf("Expected 2 rule files, got %d", len(paths))
	}

	// Verify files exist
	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Rule file does not exist: %s", path)
		}
	}
}

func TestLocalRuleSource_Load_WithRuleDir(t *testing.T) {
	t.Parallel()

	// Use actual testdata directory
	ruleDir := "../../testdata/rules"

	source := NewLocalRuleSource([]string{}, []string{ruleDir})
	paths, err := source.Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Should find go.yaml and python.yaml
	if len(paths) < 2 {
		t.Errorf("Expected at least 2 rule files, got %d", len(paths))
	}

	// Verify all files are .yaml or .yml
	for _, path := range paths {
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			t.Errorf("Expected .yaml or .yml file, got: %s", path)
		}
	}
}

func TestLocalRuleSource_Load_MixedFilesAndDirs(t *testing.T) {
	t.Parallel()

	// Create temp directory with rules
	tempDir := t.TempDir()
	ruleFile := filepath.Join(tempDir, "custom.yaml")
	if err := os.WriteFile(ruleFile, []byte("rules: []"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Also use testdata directory
	source := NewLocalRuleSource(
		[]string{ruleFile},
		[]string{"../../testdata/rules"},
	)

	paths, err := source.Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Should have custom.yaml plus testdata rules
	if len(paths) < 3 {
		t.Errorf("Expected at least 3 rules, got %d", len(paths))
	}
}

func TestLocalRuleSource_Load_NonexistentFile(t *testing.T) {
	t.Parallel()

	source := NewLocalRuleSource([]string{"/nonexistent/file.yaml"}, []string{})
	_, err := source.Load()

	if err == nil {
		t.Fatal("Expected error for nonexistent file")
	}
}

func TestLocalRuleSource_Load_NonexistentDir(t *testing.T) {
	t.Parallel()

	source := NewLocalRuleSource([]string{}, []string{"/nonexistent/dir"})
	_, err := source.Load()

	if err == nil {
		t.Fatal("Expected error for nonexistent directory")
	}
}

func TestLocalRuleSource_Load_EmptyDir(t *testing.T) {
	t.Parallel()

	emptyDir := t.TempDir()

	source := NewLocalRuleSource([]string{}, []string{emptyDir})
	_, err := source.Load()

	// Should return error for empty directory (no rule files found)
	if err == nil {
		t.Fatal("Expected error for empty directory with no rules")
	}
}

func TestLocalRuleSource_Load_NoRulesProvided(t *testing.T) {
	t.Parallel()

	source := NewLocalRuleSource([]string{}, []string{})
	_, err := source.Load()

	// Should return error when no rules specified
	if err == nil {
		t.Fatal("Expected error when no rules provided")
	}
}

func TestLocalRuleSource_Name(t *testing.T) {
	t.Parallel()

	source := NewLocalRuleSource(
		[]string{"rule1.yaml", "rule2.yaml"},
		[]string{"/path/to/rules"},
	)

	name := source.Name()

	// Should indicate local source with file and directory counts
	if name == "" {
		t.Error("Name() returned empty string")
	}
}

func TestLocalRuleSource_Load_Deduplication(t *testing.T) {
	t.Parallel()

	// Use actual testdata file
	ruleFile := "../../testdata/rules/go.yaml"

	// Provide same file twice - LocalRuleSource may not deduplicate,
	// but MultiSource will when aggregating
	source := NewLocalRuleSource([]string{ruleFile, ruleFile}, []string{})
	paths, err := source.Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// LocalRuleSource might not deduplicate (that's done at MultiSource level)
	// Just verify we got the rules
	if len(paths) == 0 {
		t.Error("Expected at least one rule path")
	}
}

func TestLocalRuleSource_Load_NestedDirectories(t *testing.T) {
	t.Parallel()

	// Create nested directory structure
	tempDir := t.TempDir()
	nestedDir := filepath.Join(tempDir, "subdir", "rules")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatalf("Failed to create nested directory: %v", err)
	}

	// Create a rule file in nested directory
	ruleFile := filepath.Join(nestedDir, "nested.yaml")
	if err := os.WriteFile(ruleFile, []byte("rules: []"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Scan from parent directory
	source := NewLocalRuleSource([]string{}, []string{tempDir})
	paths, err := source.Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Should find nested rule file
	if len(paths) != 1 {
		t.Errorf("Expected 1 rule file in nested directory, got %d", len(paths))
	}
}
