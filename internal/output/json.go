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
	"io"
	"os"
	"path/filepath"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
	"github.com/scanoss/crypto-finder/internal/utils"
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

// WriteResolved serializes the resolved type-state.
func (w *JSONWriter) WriteResolved(report *oid.ResolvedReport, destination string) error {
	// Validate report
	if report == nil {
		return fmt.Errorf("output: report cannot be nil")
	}
	// Determine output destination
	//nolint:nestif // Separate stdout and file paths are inherently nested
	if destination == "" || destination == "-" {
		if err := w.writeResolvedJSON(report, os.Stdout); err != nil {
			return fmt.Errorf("output: failed to write JSON to stdout: %w", err)
		}
		// Add newline for better terminal output
		if _, err := os.Stdout.WriteString("\n"); err != nil {
			return fmt.Errorf("output: failed to write newline to stdout: %w", err)
		}
	} else {
		// Write to file
		// Convert to absolute path
		absPath, err := filepath.Abs(destination)
		if err != nil {
			return fmt.Errorf("output: failed to resolve destination path: %w", err)
		}

		if err := utils.WriteFileAtomic(absPath, 0o600, func(file *os.File) error {
			return w.writeResolvedJSON(report, file)
		}); err != nil {
			return fmt.Errorf("output: failed to write JSON file: %w", err)
		}
	}

	return nil
}

func (w *JSONWriter) writeResolvedJSON(report *oid.ResolvedReport, dst io.Writer) error {
	payload := *report
	if payload.Findings == nil {
		payload.Findings = []entities.Finding{}
	}

	enc := json.NewEncoder(dst)
	enc.SetEscapeHTML(false)
	if w.PrettyPrint {
		enc.SetIndent("", w.Indent)
	}
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("output: failed to encode JSON: %w", err)
	}
	return nil
}
