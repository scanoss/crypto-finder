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

package prefilter

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxTreeFileBytes is the largest file the tree walk reads: the scanner's
// default target size limit, above which OpenGrep skips a file.
const maxTreeFileBytes = 1_000_000

// treeAnalyzers maps a file name suffix to the OpenGrep analyzers that read
// such a file.
var treeAnalyzers = map[string][]string{
	".go":   {analyzerGo},
	".java": {analyzerJava},
	".py":   {analyzerPython},
	".pyi":  {analyzerPython},
	".js":   {analyzerJS},
	".jsx":  {analyzerJS},
	".mjs":  {analyzerJS},
	".cjs":  {analyzerJS},
	".ts":   {analyzerTS},
	".tsx":  {analyzerTS},
	".mts":  {analyzerTS},
	".cts":  {analyzerTS},
	".rs":   {analyzerRust},
	".c":    {analyzerC},
	".h":    {analyzerC},
	".cc":   {analyzerCpp},
	".cpp":  {analyzerCpp},
	".cxx":  {analyzerCpp},
	".hpp":  {analyzerCpp},
	".hh":   {analyzerCpp},
	".hxx":  {analyzerCpp},
	".cs":   {analyzerCSharp},
	".rb":   {analyzerRuby},
}

// treeSkippedDirs are directory names the walk never enters: dependency
// copies, build output and virtual environments.
var treeSkippedDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"target":       true,
	"build":        true,
	"dist":         true,
	"__pycache__":  true,
	".venv":        true,
	"venv":         true,
}

// EvidenceFromTree reads the sources below root (or root itself when it is
// a file) into evidence. skip, when set, is asked for every directory and
// file, with the path as the walk names it below root. The walk selects by
// file name suffix alone, so it reads at least every file the scanner
// enumerates: extra evidence only keeps more rules.
func EvidenceFromTree(root string, skip func(path string, isDir bool) bool) (*Evidence, error) {
	ev := NewEvidence()
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("prefilter: stat %s: %w", root, err)
	}
	if !info.IsDir() {
		ev.addTreeFile(root, info.Size())
		return ev, nil
	}
	walk := treeWalk{ev: ev, root: root, skip: skip}
	if err := filepath.WalkDir(root, walk.visit); err != nil {
		return nil, fmt.Errorf("prefilter: walk %s: %w", root, err)
	}
	return ev, nil
}

type treeWalk struct {
	ev   *Evidence
	root string
	skip func(path string, isDir bool) bool
}

// visit reads one entry of the walk. An unreadable entry below the root is
// one the scanner skips too.
func (w *treeWalk) visit(path string, entry fs.DirEntry, walkErr error) error {
	if walkErr != nil {
		if path == w.root {
			return walkErr
		}
		return nil
	}
	if entry.IsDir() {
		if (path != w.root && treeSkippedDirs[entry.Name()]) || w.skipped(path, true) {
			return filepath.SkipDir
		}
		return nil
	}
	if !entry.Type().IsRegular() || treeAnalyzers[strings.ToLower(filepath.Ext(path))] == nil || w.skipped(path, false) {
		return nil
	}
	if info, err := entry.Info(); err == nil {
		w.ev.addTreeFile(path, info.Size())
	}
	return nil
}

func (w *treeWalk) skipped(path string, isDir bool) bool {
	return w.skip != nil && w.skip(path, isDir)
}

func (ev *Evidence) addTreeFile(path string, size int64) {
	analyzers := treeAnalyzers[strings.ToLower(filepath.Ext(path))]
	if analyzers == nil || size > maxTreeFileBytes {
		return
	}
	content, err := os.ReadFile(path) // #nosec G304 -- a source file below the scan target.
	if err != nil {
		return
	}
	ev.AddFile(analyzers, content)
}
