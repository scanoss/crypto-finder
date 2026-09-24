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

//revive:disable:var-naming // scanner is a domain package name and intentionally matches CLI/config terminology.
package scanner

import (
	"context"
	"path/filepath"
	"runtime"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// DetectionScope limits which files under a directory target the scanner
// reads for findings. It narrows detection only: call-graph construction and
// dependency root discovery never consult it, so findings in scoped files keep
// the reachability they have in a full scan. It is handed to one ScanScoped
// call rather than carried in Config, so the dependency scans that reuse a
// root scan's options can never inherit it.
//
// A nil *DetectionScope scans the whole target. A non-nil scope with no Paths
// scans nothing.
type DetectionScope struct {
	// Paths are regular files relative to the scan target. The scanner still
	// applies the scan's skip patterns to them.
	Paths []string
}

// ScopedScanner is implemented by scanners that can limit detection to a
// DetectionScope with the same file selection a whole-target scan applies.
type ScopedScanner interface {
	ScanScoped(ctx context.Context, target string, scope *DetectionScope, rulePaths []string, toolInfo entities.ToolInfo) (*entities.InterimReport, error)
}

// maxTargetArgBytes bounds the bytes of explicit target paths passed to one
// scanner process, well under the platform command-line limit (32 KiB on
// Windows, a few MiB elsewhere) once rule and exclude arguments are added.
var maxTargetArgBytes = func() int {
	if runtime.GOOS == "windows" {
		return 16 << 10
	}
	return 512 << 10
}()

// TargetBatches returns the scanner target arguments for each process to run.
// Without a scope it is one invocation over target. With a scope, the scoped
// files are joined onto target, so result paths have the same form a full
// directory walk produces, and split so no invocation exceeds the
// command-line budget. An empty scope yields no invocations.
func TargetBatches(target string, scope *DetectionScope) [][]string {
	if scope == nil {
		return [][]string{{target}}
	}
	var batches [][]string
	var current []string
	size := 0
	for _, rel := range scope.Paths {
		path := filepath.Join(target, rel)
		if len(current) > 0 && size+len(path)+1 > maxTargetArgBytes {
			batches = append(batches, current)
			current, size = nil, 0
		}
		current = append(current, path)
		size += len(path) + 1
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches
}
