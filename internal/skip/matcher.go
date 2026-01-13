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

// Package skip provides utilities for determining which files and directories should be excluded from scanning.
package skip

// SkipMatcher is an interface that defines a matcher for skipping files and directories.
//
//nolint:revive // SkipMatcher name is intentional for clarity and consistency with package API
type SkipMatcher interface {
	// ShouldSkip returns true if the given path should be skipped.
	ShouldSkip(path string, isDir bool) bool
}
