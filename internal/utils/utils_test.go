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

//revive:disable:var-naming // utils is a conventional package name for shared utilities
package utils

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDeduplicateSliceOfStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "no duplicates",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "with duplicates",
			input:    []string{"a", "b", "a", "c", "b"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "all duplicates",
			input:    []string{"a", "a", "a"},
			expected: []string{"a"},
		},
		{
			name:     "with empty strings",
			input:    []string{"a", "", "b", "", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "only empty strings",
			input:    []string{"", "", ""},
			expected: []string{},
		},
		{
			name:     "mixed duplicates and empty",
			input:    []string{"a", "", "b", "a", "", "c", "b"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "single element",
			input:    []string{"single"},
			expected: []string{"single"},
		},
		{
			name:     "preserves order of first occurrence",
			input:    []string{"z", "a", "m", "a", "z"},
			expected: []string{"z", "a", "m"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := DeduplicateSliceOfStrings(tt.input)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("DeduplicateSliceOfStrings() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestDeduplicateSliceOfStrings_NilInput(t *testing.T) {
	t.Parallel()

	result := DeduplicateSliceOfStrings(nil)

	if result == nil {
		t.Error("Expected non-nil slice, got nil")
	}

	if len(result) != 0 {
		t.Errorf("Expected empty slice, got %v", result)
	}
}

func TestValidateRuleDirNotEmpty(t *testing.T) {
	t.Parallel()

	t.Run("missing directory", func(t *testing.T) {
		err := ValidateRuleDirNotEmpty("/nonexistent/path")
		if err == nil {
			t.Fatal("Expected error for missing directory")
		}
	})

	t.Run("path is file", func(t *testing.T) {
		tempDir := t.TempDir()
		filePath := filepath.Join(tempDir, "rules.txt")
		if err := os.WriteFile(filePath, []byte("data"), 0o600); err != nil {
			t.Fatalf("Failed to write temp file: %v", err)
		}

		err := ValidateRuleDirNotEmpty(filePath)
		if err == nil {
			t.Fatal("Expected error for non-directory path")
		}
	})

	t.Run("no rule files", func(t *testing.T) {
		tempDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tempDir, "notes.txt"), []byte("data"), 0o600); err != nil {
			t.Fatalf("Failed to write temp file: %v", err)
		}

		err := ValidateRuleDirNotEmpty(tempDir)
		if err == nil {
			t.Fatal("Expected error for missing rule files")
		}
	})

	t.Run("rule files present", func(t *testing.T) {
		tempDir := t.TempDir()
		rulesPath := filepath.Join(tempDir, "rules", "rule.yml")
		if err := os.MkdirAll(filepath.Dir(rulesPath), 0o755); err != nil {
			t.Fatalf("Failed to create rules dir: %v", err)
		}
		if err := os.WriteFile(rulesPath, []byte("rules: []\n"), 0o600); err != nil {
			t.Fatalf("Failed to write rule file: %v", err)
		}

		if err := ValidateRuleDirNotEmpty(tempDir); err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
	})

	t.Run("walk error", func(t *testing.T) {
		tempDir := t.TempDir()

		// Create a symlink loop to trigger a walk error deterministically
		link1 := filepath.Join(tempDir, "link1")
		link2 := filepath.Join(tempDir, "link2")

		// Create symlinks that point to each other (infinite loop)
		if err := os.Symlink(link2, link1); err != nil {
			t.Fatalf("Failed to create symlink: %v", err)
		}
		if err := os.Symlink(link1, link2); err != nil {
			t.Fatalf("Failed to create symlink: %v", err)
		}

		// ValidateRuleDirNotEmpty will encounter an error when walking the symlink loop
		err := ValidateRuleDirNotEmpty(tempDir)
		if err == nil {
			t.Fatal("Expected error when walking directory with symlink loop")
		}
	})
}
