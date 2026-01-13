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

package output

import (
	"github.com/scanoss/crypto-finder/internal/entities"
)

// Writer defines the interface for formatting and writing scan results
// to various output formats.
//
// Implementations exist for:
//   - JSON (default format)
type Writer interface {
	// Write formats and writes the report to the specified destination.
	//
	// The destination parameter determines where output is written:
	//   - "" (empty string): Write to stdout
	//   - "-": Write to stdout (Unix convention)
	//   - file path: Write to the specified file
	//
	// Parameters:
	//   - report: The scan results to write
	//   - destination: Output location (empty/"" for stdout, or file path)
	//
	// Returns an error if writing fails.
	Write(report *entities.InterimReport, destination string) error
}
