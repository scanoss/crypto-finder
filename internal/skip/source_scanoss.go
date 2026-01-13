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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ScanossConfigSource loads skip patterns from a scanoss.json configuration file.
// This source implements the settings.skip.patterns.scanning field.
type ScanossConfigSource struct {
	configPath string
}

// scanossConfig represents the minimal structure we need from scanoss.json
// to extract skip patterns.
type scanossConfig struct {
	Settings struct {
		Skip struct {
			Patterns struct {
				Scanning []string `json:"scanning"`
			} `json:"patterns"`
		} `json:"skip"`
	} `json:"settings"`
}

// NewScanossConfigSource creates a new source that loads patterns from a scanoss.json file.
//
// Parameters:
//   - configPath: Path to the scanoss.json file
//
// Returns:
//   - *ScanossConfigSource: Source configured to load from the specified file
func NewScanossConfigSource(configPath string) *ScanossConfigSource {
	return &ScanossConfigSource{
		configPath: configPath,
	}
}

// NewScanossConfigSourceFromDir creates a new source that loads from scanoss.json in a directory.
// This is a convenience constructor that builds the path to scanoss.json.
//
// Parameters:
//   - dir: Directory containing scanoss.json
//
// Returns:
//   - *ScanossConfigSource: Source configured to load from dir/scanoss.json
func NewScanossConfigSourceFromDir(dir string) *ScanossConfigSource {
	return &ScanossConfigSource{
		configPath: filepath.Join(dir, "scanoss.json"),
	}
}

// Load retrieves skip patterns from the scanoss.json file.
// Returns an empty slice if the file doesn't exist (not an error).
// Returns an error if the file exists but cannot be read or parsed.
//
// Returns:
//   - []string: Skip patterns from settings.skip.patterns.scanning
//   - error: Error if file exists but cannot be read/parsed
func (s *ScanossConfigSource) Load() ([]string, error) {
	// Check if config file exists
	if _, err := os.Stat(s.configPath); os.IsNotExist(err) {
		// File doesn't exist - return empty patterns (not an error)
		return []string{}, nil
	}

	// Read config file
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read scanoss.json: %w", err)
	}

	// Parse JSON
	var config scanossConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse scanoss.json: %w", err)
	}

	return config.Settings.Skip.Patterns.Scanning, nil
}

// Name returns a descriptive name for this pattern source.
func (s *ScanossConfigSource) Name() string {
	return fmt.Sprintf("scanoss.json(%s)", s.configPath)
}
