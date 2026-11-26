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

package dependency

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ListsFile reports whether files, a dependency's Files, include path, an
// absolute clean path below the dependency's Dir. Nil files include every
// path.
func ListsFile(files []string, path string) bool {
	if files == nil {
		return true
	}
	_, found := slices.BinarySearch(files, path)
	return found
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// projectDir is the directory whose contents are the project's own code when
// targetDir is resolved: the scan root holding it, else targetDir itself.
func projectDir(targetDir, scanRoot string) string {
	if scanRoot != "" && isWithin(targetDir, scanRoot) {
		return scanRoot
	}
	return targetDir
}

// isWithin reports whether path is root or lies below it, both made
// absolute with symbolic links resolved.
func isWithin(path, root string) bool {
	rel, err := filepath.Rel(absoluteScanRoot(root), absoluteScanRoot(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
