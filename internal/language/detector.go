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

// Package language provides automatic programming language detection for source code.
// It uses go-enry to accurately identify languages in target directories.
package language

// Detector analyzes source code to automatically detect programming languages
// present in the target directory.
type Detector interface {
	// Detect analyzes the target directory and returns detected languages.
	// Returns language names in lowercase (e.g., "java", "python", "go").
	//
	// The detector recursively scans all files in the target path,
	// excluding directories based on configured skip patterns.
	// Skip patterns follow gitignore syntax and can be configured via scanoss.json.
	//
	// Parameters:
	//   - targetPath: Absolute or relative path to the directory to analyze
	//
	// Returns:
	//   - []string: Slice of detected language names (lowercase, deduplicated)
	//   - error: Error if path doesn't exist or cannot be read
	Detect(targetPath string) ([]string, error)
}
