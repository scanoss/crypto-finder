package utils

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
