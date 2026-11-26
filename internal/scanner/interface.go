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

// Package scanner provides the core abstraction for cryptographic scanner implementations.
// It defines the Scanner interface that every detector implements (today the
// cards scanner), along with configuration and metadata types.
//
//revive:disable:var-naming // scanner is a domain package name and intentionally matches CLI/config terminology.
package scanner

import (
	"context"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// Scanner defines the contract a detector implements, providing a unified
// interface for running detection over a target.
//
// Each scanner implementation is responsible for:
//   - Validating that its configuration is usable
//   - Detecting cryptographic usage in the target with the given rules
//   - Reporting it in the standardized interim format
//
// Example usage:
//
//	s := cards.NewScannerFactory(opts)()
//	if err := s.Initialize(ctx, scanner.Config{Timeout: 10 * time.Minute}); err != nil {
//	    log.Fatal(err)
//	}
//	report, err := s.Scan(ctx, "/path/to/code", []string{"./rules"}, toolInfo)
type Scanner interface {
	// Initialize validates the scanner is properly configured.
	// ctx cancels initialization work.
	// This method should be called once before any scanning operations.
	// Concurrent initialization of a shared scanner is not supported.
	// Built-in scanners copy mutable configuration values during initialization.
	//
	// It verifies that the scanner's options and the configuration parameters
	// are valid.
	//
	// Returns an error if initialization fails.
	Initialize(ctx context.Context, config Config) error

	// Scan runs the scanner against the target with given rule paths.
	// Returns an interim format report containing all findings.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout control
	//   - target: Path to the directory or file to scan
	//   - rulePaths: Paths to rule files or directories containing rules
	//   - toolInfo: Information about the crypto-finder tool (name and version)
	//
	// The report is in the standardized interim format, which includes
	// cryptographic assets and metadata.
	//
	// Returns an error if the scan fails.
	Scan(ctx context.Context, target string, rulePaths []string, toolInfo entities.ToolInfo) (*entities.InterimReport, error)

	// GetInfo returns metadata about this scanner implementation.
	// This includes the scanner's name, version, and description.
	//
	// This method can be called before Initialize() to query scanner capabilities.
	GetInfo() Info
}

// Config holds the configuration parameters for initializing a scanner.
type Config struct {
	// Timeout specifies the maximum duration for a scan operation.
	Timeout time.Duration

	// SkipPatterns contains gitignore-style patterns for files/directories to exclude.
	SkipPatterns []string

	// DisableDedup when true, disables per-line deduplication of cryptographic assets.
	// By default (false), assets detected at the same location are merged.
	DisableDedup bool
}

// Info contains metadata about a scanner implementation.
// This information is used for reporting, debugging, and determining scanner capabilities.
type Info struct {
	// Name is the unique identifier for the scanner.
	// Example: "cards"
	Name string

	// Version is the version of the scanner implementation.
	Version string

	// Description provides a brief explanation of what the scanner detects.
	// Example: "Card lookup over call-graph call sites"
	Description string
}
