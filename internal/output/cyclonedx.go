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

// Package output handles formatting and writing scan results to various output formats.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/converter"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// CycloneDXWriter implements the Writer interface for CycloneDX CBOM format.
// It converts interim format to CycloneDX 1.6 CBOM and validates the output.
type CycloneDXWriter struct {
	// PrettyPrint enables indented formatting. Default: true
	PrettyPrint bool

	// Indent specifies the indentation string. Default: "  " (2 spaces)
	Indent string

	// Converter transforms interim to CycloneDX format
	converter *converter.Converter
}

// NewCycloneDXWriter creates a new CycloneDX writer with default settings.
func NewCycloneDXWriter() *CycloneDXWriter {
	return &CycloneDXWriter{
		PrettyPrint: true,
		Indent:      "  ", // 2 spaces
		converter:   converter.NewConverter(),
	}
}

// Write converts the interim report to CycloneDX CBOM format and writes it.
//
// The conversion process:
// 1. Transforms interim format to CycloneDX 1.6 BOM
// 2. Applies strict mapping (skips incomplete assets)
// 3. Validates against CycloneDX 1.6 schema
// 4. Writes to destination (stdout or file)
//
// Destination handling:
//   - "" (empty) or "-": Write to stdout
//   - file path: Write to file with permissions 0600 (rw-------)
//
// If writing to a file:
//   - File will be overwritten if it exists
//   - Parent directory must exist (returns error otherwise)
func (w *CycloneDXWriter) Write(report *entities.InterimReport, destination string) error {
	// Validate report
	if report == nil {
		return fmt.Errorf("report cannot be nil")
	}

	log.Info().Msg("Converting interim format to CycloneDX CBOM")

	// Convert interim report to CycloneDX BOM
	bom, err := w.converter.Convert(report)
	if err != nil {
		return fmt.Errorf("conversion to CycloneDX failed: %w", err)
	}

	log.Info().
		Int("components", componentCount(bom)).
		Msg("CycloneDX BOM generated successfully")

	// Marshal to JSON
	var data []byte
	if w.PrettyPrint {
		data, err = json.MarshalIndent(bom, "", w.Indent)
	} else {
		data, err = json.Marshal(bom)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal BOM to JSON: %w", err)
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
			return fmt.Errorf("failed to write CycloneDX file: %w", err)
		}

		log.Info().Str("file", absPath).Msg("CycloneDX CBOM written successfully")
	}

	return nil
}

// componentCount returns the number of components in the BOM.
func componentCount(bom any) int {
	// Type assertion to get components
	type bomWithComponents interface {
		GetComponents() any
	}

	if b, ok := bom.(bomWithComponents); ok {
		if components := b.GetComponents(); components != nil {
			// Try to get length
			switch c := components.(type) {
			case []any:
				return len(c)
			default:
				return 0
			}
		}
	}

	return 0
}
