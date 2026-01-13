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

package utils //nolint:revive // utils is a conventional package name for shared utilities

import (
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
