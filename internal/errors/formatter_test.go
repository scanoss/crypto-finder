package clierrors

import (
	"errors"
	"strings"
	"testing"
)

func TestFormatError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		operation    string
		err          error
		wantNil      bool
		wantContains []string
	}{
		{
			name:      "nil error",
			operation: "reading file",
			err:       nil,
			wantNil:   true,
		},
		{
			name:         "simple error",
			operation:    "connecting to server",
			err:          errors.New("connection refused"),
			wantContains: []string{"error during", "connecting to server", "connection refused"},
		},
		{
			name:         "wrapped error",
			operation:    "parsing config",
			err:          errors.New("invalid JSON"),
			wantContains: []string{"error during", "parsing config", "invalid JSON"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatError(tt.operation, tt.err)

			if tt.wantNil {
				if result != nil {
					t.Errorf("Expected nil error, got: %v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Expected non-nil error")
			}

			errStr := result.Error()
			for _, want := range tt.wantContains {
				if !strings.Contains(errStr, want) {
					t.Errorf("Error message should contain '%s', got: %s", want, errStr)
				}
			}
		})
	}
}

func TestFormatScannerError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		scannerName  string
		err          error
		wantNil      bool
		wantContains []string
	}{
		{
			name:        "nil error",
			scannerName: "semgrep",
			err:         nil,
			wantNil:     true,
		},
		{
			name:         "scanner not found",
			scannerName:  "semgrep",
			err:          errors.New("executable not found in PATH"),
			wantContains: []string{"scanner", "semgrep", "error", "executable not found"},
		},
		{
			name:         "scanner execution error",
			scannerName:  "opengrep",
			err:          errors.New("exit code 1"),
			wantContains: []string{"scanner", "opengrep", "error", "exit code 1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatScannerError(tt.scannerName, tt.err)

			if tt.wantNil {
				if result != nil {
					t.Errorf("Expected nil error, got: %v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Expected non-nil error")
			}

			errStr := result.Error()
			for _, want := range tt.wantContains {
				if !strings.Contains(errStr, want) {
					t.Errorf("Error message should contain '%s', got: %s", want, errStr)
				}
			}
		})
	}
}

func TestFormatValidationError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		flag         string
		message      string
		suggestion   string
		wantContains []string
	}{
		{
			name:       "with suggestion",
			flag:       "--rules",
			message:    "no rule files specified",
			suggestion: "use --rules <file> or --rules-dir <dir>",
			wantContains: []string{
				"validation error",
				"--rules",
				"no rule files specified",
				"suggestion",
				"use --rules <file>",
			},
		},
		{
			name:       "without suggestion",
			flag:       "--output",
			message:    "invalid format",
			suggestion: "",
			wantContains: []string{
				"validation error",
				"--output",
				"invalid format",
			},
		},
		{
			name:       "complex flag",
			flag:       "--api-key",
			message:    "API key is required",
			suggestion: "set SCANOSS_API_KEY environment variable",
			wantContains: []string{
				"validation error",
				"--api-key",
				"API key is required",
				"suggestion",
				"SCANOSS_API_KEY",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatValidationError(tt.flag, tt.message, tt.suggestion)

			if result == nil {
				t.Fatal("Expected non-nil error")
			}

			errStr := result.Error()
			for _, want := range tt.wantContains {
				if !strings.Contains(errStr, want) {
					t.Errorf("Error message should contain '%s', got: %s", want, errStr)
				}
			}

			// Verify suggestion is NOT present when empty
			if tt.suggestion == "" && strings.Contains(errStr, "suggestion") {
				t.Errorf("Error should not contain 'suggestion' when suggestion is empty, got: %s", errStr)
			}
		})
	}
}

func TestFormatMultiError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		context      string
		errors       []error
		wantNil      bool
		wantSingle   bool
		wantContains []string
	}{
		{
			name:    "empty errors",
			context: "validation",
			errors:  []error{},
			wantNil: true,
		},
		{
			name:         "single error",
			context:      "validation",
			errors:       []error{errors.New("file not found")},
			wantSingle:   true,
			wantContains: []string{"file not found"},
		},
		{
			name:    "multiple errors",
			context: "rule validation",
			errors: []error{
				errors.New("file not found: rule1.yaml"),
				errors.New("file not found: rule2.yaml"),
			},
			wantContains: []string{
				"multiple errors",
				"rule validation",
				"rule1.yaml",
				"rule2.yaml",
				"-", // bullet points
			},
		},
		{
			name:    "three errors",
			context: "scanning",
			errors: []error{
				errors.New("error 1"),
				errors.New("error 2"),
				errors.New("error 3"),
			},
			wantContains: []string{
				"multiple errors",
				"scanning",
				"error 1",
				"error 2",
				"error 3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatMultiError(tt.context, tt.errors)

			if tt.wantNil {
				if result != nil {
					t.Errorf("Expected nil error, got: %v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Expected non-nil error")
			}

			errStr := result.Error()

			// Check for single error - should NOT contain "multiple errors"
			if tt.wantSingle {
				if strings.Contains(errStr, "multiple") {
					t.Errorf("Single error should not contain 'multiple', got: %s", errStr)
				}
			}

			for _, want := range tt.wantContains {
				if !strings.Contains(errStr, want) {
					t.Errorf("Error message should contain '%s', got: %s", want, errStr)
				}
			}
		})
	}
}

func TestWrapWithSuggestion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		err          error
		suggestion   string
		wantNil      bool
		wantOriginal bool
		wantContains []string
	}{
		{
			name:       "nil error",
			err:        nil,
			suggestion: "install something",
			wantNil:    true,
		},
		{
			name:         "empty suggestion",
			err:          errors.New("some error"),
			suggestion:   "",
			wantOriginal: true,
			wantContains: []string{"some error"},
		},
		{
			name:       "with suggestion",
			err:        errors.New("semgrep not found in PATH"),
			suggestion: "install semgrep: pip install semgrep",
			wantContains: []string{
				"semgrep not found in PATH",
				"suggestion",
				"install semgrep",
				"pip install semgrep",
			},
		},
		{
			name:       "complex suggestion",
			err:        errors.New("connection failed"),
			suggestion: "check network settings or try again later",
			wantContains: []string{
				"connection failed",
				"suggestion",
				"check network settings",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WrapWithSuggestion(tt.err, tt.suggestion)

			if tt.wantNil {
				if result != nil {
					t.Errorf("Expected nil error, got: %v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Expected non-nil error")
			}

			errStr := result.Error()

			// Check if we got the original error back (no wrapping)
			if tt.wantOriginal {
				if !errors.Is(tt.err, result) {
					t.Error("Expected original error to be returned unchanged")
				}
				if strings.Contains(errStr, "suggestion") {
					t.Errorf("Original error should not contain 'suggestion', got: %s", errStr)
				}
				return
			}

			for _, want := range tt.wantContains {
				if !strings.Contains(errStr, want) {
					t.Errorf("Error message should contain '%s', got: %s", want, errStr)
				}
			}
		})
	}
}
