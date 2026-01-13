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

package skip

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewScanossConfigSource(t *testing.T) {
	t.Parallel()

	configPath := "/path/to/scanoss.json"
	source := NewScanossConfigSource(configPath)

	if source == nil {
		t.Fatal("Expected non-nil source")
	}

	if source.configPath != configPath {
		t.Errorf("Expected configPath '%s', got '%s'", configPath, source.configPath)
	}
}

func TestNewScanossConfigSourceFromDir(t *testing.T) {
	t.Parallel()

	dir := "/path/to/project"
	source := NewScanossConfigSourceFromDir(dir)

	if source == nil {
		t.Fatal("Expected non-nil source")
	}

	expectedPath := filepath.Join(dir, "scanoss.json")
	if source.configPath != expectedPath {
		t.Errorf("Expected configPath '%s', got '%s'", expectedPath, source.configPath)
	}
}

func TestScanossConfigSource_Load_FileExists(t *testing.T) {
	t.Parallel()

	// Create temp directory with scanoss.json
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "scanoss.json")

	configContent := `{
		"settings": {
			"skip": {
				"patterns": {
					"scanning": ["node_modules", "*.test.js", "vendor"]
				}
			}
		}
	}`

	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	source := NewScanossConfigSource(configPath)
	patterns, err := source.Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if len(patterns) != 3 {
		t.Fatalf("Expected 3 patterns, got %d", len(patterns))
	}

	expectedPatterns := []string{"node_modules", "*.test.js", "vendor"}
	for i, expected := range expectedPatterns {
		if patterns[i] != expected {
			t.Errorf("Pattern[%d]: expected '%s', got '%s'", i, expected, patterns[i])
		}
	}
}

func TestScanossConfigSource_Load_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	// Use a path that doesn't exist
	configPath := filepath.Join(t.TempDir(), "nonexistent.json")

	source := NewScanossConfigSource(configPath)
	patterns, err := source.Load()
	// Should not return error when file doesn't exist
	if err != nil {
		t.Fatalf("Expected no error for missing file, got: %v", err)
	}

	// Should return empty patterns
	if len(patterns) != 0 {
		t.Errorf("Expected 0 patterns for missing file, got %d", len(patterns))
	}
}

func TestScanossConfigSource_Load_EmptyPatterns(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "scanoss.json")

	configContent := `{
		"settings": {
			"skip": {
				"patterns": {
					"scanning": []
				}
			}
		}
	}`

	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	source := NewScanossConfigSource(configPath)
	patterns, err := source.Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if len(patterns) != 0 {
		t.Errorf("Expected 0 patterns, got %d", len(patterns))
	}
}

func TestScanossConfigSource_Load_InvalidJSON(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "scanoss.json")

	// Write invalid JSON
	invalidJSON := `{"settings": invalid json}`

	if err := os.WriteFile(configPath, []byte(invalidJSON), 0o644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	source := NewScanossConfigSource(configPath)
	_, err := source.Load()

	// Should return error for invalid JSON
	if err == nil {
		t.Fatal("Expected error for invalid JSON")
	}

	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("Expected parse error, got: %v", err)
	}
}

func TestScanossConfigSource_Load_MissingSettings(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "scanoss.json")

	// Valid JSON but missing the settings structure
	configContent := `{
		"other": "data"
	}`

	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	source := NewScanossConfigSource(configPath)
	patterns, err := source.Load()
	// Should not error, just return empty/nil patterns
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// The patterns field will be nil when settings are missing - this is OK
	// Just verify we got a result without error
	_ = patterns
}

func TestScanossConfigSource_Name(t *testing.T) {
	t.Parallel()

	configPath := "/path/to/scanoss.json"
	source := NewScanossConfigSource(configPath)

	name := source.Name()

	if name == "" {
		t.Error("Expected non-empty name")
	}

	if !strings.Contains(name, "scanoss.json") {
		t.Errorf("Expected name to contain 'scanoss.json', got: %s", name)
	}

	if !strings.Contains(name, configPath) {
		t.Errorf("Expected name to contain path '%s', got: %s", configPath, name)
	}
}

func TestScanossConfigSource_Load_ComplexPatterns(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "scanoss.json")

	configContent := `{
		"settings": {
			"skip": {
				"patterns": {
					"scanning": [
						"**/*.min.js",
						"dist/**",
						"build/*",
						".git",
						"*.log"
					]
				}
			}
		}
	}`

	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	source := NewScanossConfigSource(configPath)
	patterns, err := source.Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if len(patterns) != 5 {
		t.Fatalf("Expected 5 patterns, got %d", len(patterns))
	}

	// Verify first and last patterns
	if patterns[0] != "**/*.min.js" {
		t.Errorf("First pattern: expected '**/*.min.js', got '%s'", patterns[0])
	}

	if patterns[4] != "*.log" {
		t.Errorf("Last pattern: expected '*.log', got '%s'", patterns[4])
	}
}
