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
	"os"
	"path/filepath"
	"runtime"
	"strings"

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
	return RootTargetBatches([]Root{{Dir: target, Scope: scope}})
}

// Root is one directory a BatchScanner scans. A nil Scope scans every file
// under Dir; a non-nil one only its files, as ScanScoped does.
type Root struct {
	Dir   string
	Scope *DetectionScope
}

// Disjoint reports whether no file a scan of a reads is one a scan of b
// reads. Roots whose directories do not nest are disjoint. A root holding
// the other's directory (or repeating it) must be scoped and name none of
// the other's files: Python distributions installed into one namespace
// directory, or one rooted at site-packages beside the packages below it.
// One process can scan disjoint roots, and each result names a file of
// exactly one of them.
func Disjoint(a, b Root) bool {
	return avoids(a, b) && avoids(b, a)
}

// avoids reports whether holder, when its directory holds other's, scans
// none of other's files.
func avoids(holder, other Root) bool {
	holderDir, otherDir := filepath.Clean(holder.Dir), filepath.Clean(other.Dir)
	if !holdsPath(holderDir, otherDir) {
		return true
	}
	if holder.Scope == nil {
		return false
	}
	var named map[string]bool
	if other.Scope != nil {
		named = make(map[string]bool, len(other.Scope.Paths))
		for _, rel := range other.Scope.Paths {
			named[filepath.Join(otherDir, rel)] = true
		}
	}
	for _, rel := range holder.Scope.Paths {
		path := filepath.Join(holderDir, rel)
		if (other.Scope == nil && holdsPath(otherDir, path)) || named[path] {
			return false
		}
	}
	return true
}

// holdsPath reports whether path is dir or lies below it.
func holdsPath(dir, path string) bool {
	return strings.HasPrefix(path, dir) && (len(path) == len(dir) || os.IsPathSeparator(path[len(dir)]))
}

// RootTargetBatches is TargetBatches over several roots: each unscoped root
// is one target, each scoped one its files joined onto Dir, all split so no
// invocation exceeds the command-line budget.
func RootTargetBatches(roots []Root) [][]string {
	var batches [][]string
	var current []string
	size := 0
	add := func(path string) {
		if len(current) > 0 && size+len(path)+1 > maxTargetArgBytes {
			batches = append(batches, current)
			current, size = nil, 0
		}
		current = append(current, path)
		size += len(path) + 1
	}
	for _, root := range roots {
		if root.Scope == nil {
			add(root.Dir)
			continue
		}
		for _, rel := range root.Scope.Paths {
			add(filepath.Join(root.Dir, rel))
		}
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches
}
