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

// Package version provides version information for the crypto-finder tool.
// This package is separate to avoid circular dependencies between cli and engine packages.
package version

var (
	// ToolName is the name of the tool.
	ToolName = "crypto-finder"
	// Version is the application version (set by build flags).
	Version = "dev"
	// GitCommit is the git commit hash (set by build flags).
	GitCommit = "unknown"
	// BuildDate is the build timestamp (set by build flags).
	BuildDate = "unknown"
)
