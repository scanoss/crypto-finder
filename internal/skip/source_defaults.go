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

// DefaultSkippedDirs contains commonly excluded directories across projects.
var DefaultSkippedDirs = []string{
	"nbproject",
	"nbbuild",
	"nbdist",
	"__pycache__",
	"venv",
	"_yardoc",
	"eggs",
	"wheels",
	"htmlcov",
	"__pypackages__",
	"example",
	"examples",
	"docs",
	"doc",
	"node_modules",
	"dist",
	"build",
	"target",
	"vendor",
}

// DefaultsSource provides the built-in default skip patterns.
// These patterns represent commonly excluded directories across projects.
type DefaultsSource struct{}

// NewDefaultsSource creates a new source that returns the built-in default patterns.
//
// Returns:
//   - *DefaultsSource: Source providing default skip patterns
func NewDefaultsSource() *DefaultsSource {
	return &DefaultsSource{}
}

// Load returns the default excluded directory patterns.
// This source never fails - it always returns the built-in defaults.
//
// Returns:
//   - []string: Default skip patterns
//   - error: Always nil (included for interface compatibility)
func (d *DefaultsSource) Load() ([]string, error) {
	return DefaultSkippedDirs, nil
}

// Name returns a descriptive name for this pattern source.
func (d *DefaultsSource) Name() string {
	return "defaults"
}
