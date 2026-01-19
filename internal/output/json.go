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

// Package output handles formatting and writing scan results to various output formats
// including JSON, SARIF, and HTML.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// JSONWriter implements the Writer interface for JSON output format.
// It produces pretty-printed JSON with 2-space indentation.
type JSONWriter struct {
	// PrettyPrint enables indented formatting. Default: true
	PrettyPrint bool

	// Indent specifies the indentation string. Default: "  " (2 spaces)
	Indent string
}

// NewJSONWriter creates a new JSON writer with default settings.
func NewJSONWriter() *JSONWriter {
	return &JSONWriter{
		PrettyPrint: true,
		Indent:      "  ", // 2 spaces
	}
}

// NewCompactJSONWriter creates a new JSON writer without pretty-printing.
func NewCompactJSONWriter() *JSONWriter {
	return &JSONWriter{
		PrettyPrint: false,
	}
}

// Write writes the interim report to JSON format.
//
// Destination handling:
//   - "" (empty) or "-": Write to stdout
//   - file path: Write to file with permissions 0644 (rw-r--r--)
//
// If writing to a file:
//   - File will be overwritten if it exists
//   - Parent directory must exist (returns error otherwise)
func (w *JSONWriter) Write(report *entities.InterimReport, destination string) error {
	// Validate report
	if report == nil {
		return fmt.Errorf("report cannot be nil")
	}

	// Marshal to JSON
	var data []byte
	var err error
	if w.PrettyPrint {
		data, err = json.MarshalIndent(report, "", w.Indent)
	} else {
		data, err = json.Marshal(report)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal report to JSON: %w", err)
	}

	// Determine output destination
	//nolint:nestif // Separate stdout and file paths are inherently nested
	if destination == "" || destination == "-" {
		// Write to stdout
		if _, err := os.Stdout.Write(data); err != nil {
			return fmt.Errorf("failed to write to stdout: %w", err)
		}
		// Add newline for better terminal output
		if _, err := os.Stdout.WriteString("\n"); err != nil {
			return fmt.Errorf("failed to write newline to stdout: %w", err)
		}
	} else {
		// Write to file
		// Convert to absolute path
		absPath, err := filepath.Abs(destination)
		if err != nil {
			return fmt.Errorf("failed to resolve destination path: %w", err)
		}

		// Check parent directory exists
		parentDir := filepath.Dir(absPath)
		if _, err := os.Stat(parentDir); os.IsNotExist(err) {
			return fmt.Errorf("parent directory does not exist: %s", parentDir)
		}

		// Write to file
		// 0o600 = rw------- (owner can read/write only)
		if err := os.WriteFile(absPath, data, 0o600); err != nil {
			return fmt.Errorf("failed to write JSON file: %w", err)
		}
	}

	return nil
}
