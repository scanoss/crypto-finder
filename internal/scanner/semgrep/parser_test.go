package semgrep

import (
	"encoding/json"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestParseSemgrepOutput_WithArrayTypeError(t *testing.T) {
	// Test parsing a Semgrep error with an array-type field (like PartialParsing errors)
	jsonData := `{
		"results": [],
		"errors": [
			{
				"code": 3,
				"level": "warn",
				"type": [
					"PartialParsing",
					[
						{
							"path": "/test/file.c",
							"start": {"line": 144, "col": 1, "offset": 0},
							"end": {"line": 144, "col": 64, "offset": 63}
						}
					]
				],
				"message": "Syntax error at line /test/file.c:144",
				"path": "/test/file.c",
				"spans": [
					{
						"file": "/test/file.c",
						"start": {"line": 144, "col": 1, "offset": 0},
						"end": {"line": 144, "col": 64, "offset": 63}
					}
				]
			}
		]
	}`

	output, err := parseSemgrepOutput([]byte(jsonData))
	if err != nil {
		t.Fatalf("Failed to parse Semgrep output: %v", err)
	}

	if len(output.Errors) != 1 {
		t.Fatalf("Expected 1 error, got %d", len(output.Errors))
	}

	semgrepErr := output.Errors[0]

	// Verify the error fields
	if semgrepErr.Code != 3 {
		t.Errorf("Expected code 3, got %d", semgrepErr.Code)
	}

	if semgrepErr.Level != "warn" {
		t.Errorf("Expected level 'warn', got '%s'", semgrepErr.Level)
	}

	if semgrepErr.Message != "Syntax error at line /test/file.c:144" {
		t.Errorf("Expected specific message, got '%s'", semgrepErr.Message)
	}

	if semgrepErr.Path != "/test/file.c" {
		t.Errorf("Expected path '/test/file.c', got '%s'", semgrepErr.Path)
	}

	if len(semgrepErr.Spans) != 1 {
		t.Errorf("Expected 1 span, got %d", len(semgrepErr.Spans))
	}

	// Verify we can extract the type correctly
	errType := getErrorType(semgrepErr.Type)
	if errType != "PartialParsing" {
		t.Errorf("Expected type 'PartialParsing', got '%s'", errType)
	}
}

func TestParseSemgrepOutput_WithStringTypeError(t *testing.T) {
	// Test parsing a Semgrep error with a simple string type
	jsonData := `{
		"results": [],
		"errors": [
			{
				"type": "error",
				"level": "error",
				"message": "Some error message",
				"path": "/test/file.go"
			}
		]
	}`

	output, err := parseSemgrepOutput([]byte(jsonData))
	if err != nil {
		t.Fatalf("Failed to parse Semgrep output: %v", err)
	}

	if len(output.Errors) != 1 {
		t.Fatalf("Expected 1 error, got %d", len(output.Errors))
	}

	semgrepErr := output.Errors[0]

	// Verify we can extract the type correctly
	errType := getErrorType(semgrepErr.Type)
	if errType != "error" {
		t.Errorf("Expected type 'error', got '%s'", errType)
	}
}

func TestGetErrorType(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{
			name:     "String type",
			input:    "error",
			expected: "error",
		},
		{
			name:     "Array type with string first",
			input:    []interface{}{"PartialParsing", []interface{}{}},
			expected: "PartialParsing",
		},
		{
			name:     "Nil type",
			input:    nil,
			expected: "",
		},
		{
			name:     "Empty array",
			input:    []interface{}{},
			expected: "",
		},
		{
			name:     "Array with non-string first element",
			input:    []interface{}{123, "test"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getErrorType(tt.input)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestUnmarshalSemgrepError(t *testing.T) {
	// Test that we can unmarshal the complex error structure
	jsonData := `{
		"code": 3,
		"level": "warn",
		"type": ["PartialParsing", [{"path": "/test/file.c"}]],
		"message": "Test message",
		"path": "/test/file.c",
		"spans": [
			{
				"file": "/test/file.c",
				"start": {"line": 1, "col": 1, "offset": 0},
				"end": {"line": 1, "col": 10, "offset": 9}
			}
		]
	}`

	var err entities.SemgrepError
	if unmarshalErr := json.Unmarshal([]byte(jsonData), &err); unmarshalErr != nil {
		t.Fatalf("Failed to unmarshal: %v", unmarshalErr)
	}

	if err.Code != 3 {
		t.Errorf("Expected code 3, got %d", err.Code)
	}

	if err.Level != "warn" {
		t.Errorf("Expected level 'warn', got '%s'", err.Level)
	}

	// Verify Type is set (should be an array)
	if err.Type == nil {
		t.Error("Expected Type to be set, got nil")
	}

	if len(err.Spans) != 1 {
		t.Errorf("Expected 1 span, got %d", len(err.Spans))
	}

	if err.Spans[0].File != "/test/file.c" {
		t.Errorf("Expected file '/test/file.c', got '%s'", err.Spans[0].File)
	}
}
