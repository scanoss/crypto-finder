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

// Package clierrors provides utilities for formatting error messages in the CLI.
// It helps create consistent, user-friendly error output with context and suggestions.
package clierrors

import (
	"fmt"
	"strings"
)

// FormatError wraps an error with operation context for better CLI output.
//
// Example:
//
//	err := fmt.Errorf("connection refused")
//	formatted := FormatError("connecting to server", err)
//	// Output: "Error during connecting to server: connection refused"
func FormatError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("error during %s: %w", operation, err)
}

// FormatScannerError adds scanner context to an error message.
//
// Example:
//
//	err := fmt.Errorf("executable not found in PATH")
//	formatted := FormatScannerError("semgrep", err)
//	// Output: "Scanner 'semgrep' error: executable not found in PATH"
func FormatScannerError(scannerName string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("scanner '%s' error: %w", scannerName, err)
}

// FormatValidationError creates a validation error with a suggestion.
//
// Example:
//
//	err := FormatValidationError("--rules", "no rule files specified", "use --rules <file> or --rules-dir <dir>")
//	// Output: "Validation error for --rules: no rule files specified. Suggestion: use --rules <file> or --rules-dir <dir>"
func FormatValidationError(flag, message, suggestion string) error {
	if suggestion != "" {
		return fmt.Errorf("validation error for %s: %s (suggestion: %s)", flag, message, suggestion)
	}
	return fmt.Errorf("validation error for %s: %s", flag, message)
}

// FormatMultiError combines multiple errors into a single formatted error.
//
// Example:
//
//	errors := []error{
//	    fmt.Errorf("file not found: rule1.yaml"),
//	    fmt.Errorf("file not found: rule2.yaml"),
//	}
//	err := FormatMultiError("rule validation", errors)
//	// Output: "Multiple errors during rule validation:
//	//   - file not found: rule1.yaml
//	//   - file not found: rule2.yaml"
func FormatMultiError(context string, errors []error) error {
	if len(errors) == 0 {
		return nil
	}

	if len(errors) == 1 {
		return errors[0]
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("multiple errors during %s:\n", context))
	for i, err := range errors {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(fmt.Sprintf("  - %v", err))
	}

	return fmt.Errorf("%s", sb.String())
}

// WrapWithSuggestion wraps an error with a helpful suggestion.
//
// Example:
//
//	err := fmt.Errorf("semgrep not found in PATH")
//	wrapped := WrapWithSuggestion(err, "install semgrep: pip install semgrep")
//	// Output: "semgrep not found in PATH (suggestion: install semgrep: pip install semgrep)"
func WrapWithSuggestion(err error, suggestion string) error {
	if err == nil {
		return nil
	}
	if suggestion == "" {
		return err
	}
	return fmt.Errorf("%w (suggestion: %s)", err, suggestion)
}
