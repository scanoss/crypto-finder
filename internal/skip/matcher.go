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

import (
	"path/filepath"
	"strings"
)

// SkipMatcher is an interface that defines a matcher for skipping files and directories.
//
//nolint:revive // SkipMatcher name is intentional for clarity and consistency with package API
type SkipMatcher interface {
	// ShouldSkip returns true if the given path should be skipped.
	ShouldSkip(path string, isDir bool) bool
}

// rootedSkipMatcher is a SkipMatcher that needs the real path beside the
// root-relative one: sourceMatcher reads a file's header to spot generated
// stubs and keeps protobuf runtimes by where they are installed.
type rootedSkipMatcher interface {
	shouldSkipRelative(path, rel string, isDir bool) bool
}

// ShouldSkipUnder reports whether path, reached by walking root, should be
// skipped. Patterns see only the part of path below root, so a root that sits
// under a directory the patterns name (an npm package in node_modules, a
// virtualenv named venv, a checkout under /ci/build) keeps its files, while
// the same name inside root is still skipped. A path outside root, or any
// path when root is empty, is matched whole, as ShouldSkip matches it.
func ShouldSkipUnder(m SkipMatcher, root, path string, isDir bool) bool {
	rel, err := filepath.Rel(root, path)
	if root == "" || err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return m.ShouldSkip(filepath.ToSlash(path), isDir)
	}
	rel = filepath.ToSlash(rel)
	if rooted, ok := m.(rootedSkipMatcher); ok {
		return rooted.shouldSkipRelative(filepath.ToSlash(path), rel, isDir)
	}
	return m.ShouldSkip(rel, isDir)
}
