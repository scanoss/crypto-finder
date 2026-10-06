// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// exportArtifacts locates files in the artifacts a scan covers: the project,
// and each dependency's source directory.
//
// A finding's path is relative to the root of the artifact it was found in, so
// the file it names is that root joined with the path. Matching a finding to
// call-graph files by path suffix instead lets it bind to another artifact's
// file at the same relative path, or to a longer path ending the same way.
type exportArtifacts struct {
	projectRoot string
	// dependencies is ordered longest Dir first, so the first root containing
	// a path is its innermost one.
	dependencies []exportDependencyRoot
	// dependencyByDir lists dependencies per Dir. Python distributions
	// installed into one namespace directory share it, each owning its Files.
	dependencyByDir map[string][]*exportDependencyRoot
	// dependencyByVersion is the first of dependencies per module@version.
	dependencyByVersion map[string]*exportDependencyRoot
	// cwd resolves relative paths, so a graph built from absolute directories
	// still matches a project given as a relative target. Empty leaves
	// relative paths relative.
	cwd string
}

func newExportArtifacts(result *engine.DepScanResult) exportArtifacts {
	artifacts := exportArtifacts{
		projectRoot:         filepath.Clean(result.ProjectRoot),
		dependencyByDir:     make(map[string][]*exportDependencyRoot),
		dependencyByVersion: make(map[string]*exportDependencyRoot),
	}
	if cwd, err := os.Getwd(); err == nil {
		artifacts.cwd = cwd
	}
	for _, dep := range result.Dependencies {
		if dep.Dir == "" {
			continue
		}
		artifacts.dependencies = append(artifacts.dependencies, exportDependencyRoot{
			Module:  dep.Module,
			Version: dep.Version,
			Dir:     filepath.Clean(dep.Dir),
			Files:   dep.Files,
		})
	}
	sort.SliceStable(artifacts.dependencies, func(i, j int) bool {
		return len(artifacts.dependencies[i].Dir) > len(artifacts.dependencies[j].Dir)
	})
	for i := range artifacts.dependencies {
		dep := &artifacts.dependencies[i]
		artifacts.dependencyByDir[dep.Dir] = append(artifacts.dependencyByDir[dep.Dir], dep)
		key := dependencyVersionKey(dep.Module, dep.Version)
		if _, ok := artifacts.dependencyByVersion[key]; !ok {
			artifacts.dependencyByVersion[key] = dep
		}
	}
	return artifacts
}

func dependencyVersionKey(module, version string) string {
	return module + "@" + version
}

// dependencyForPath returns the innermost dependency root containing the
// cleaned path, and among roots sharing a Dir the first that owns it. It
// walks the path's ancestors instead of trying every root, so a lookup costs
// the path's depth, not the number of dependencies.
func (a *exportArtifacts) dependencyForPath(path string) *exportDependencyRoot {
	for dir := path; ; {
		for _, dep := range a.dependencyByDir[dir] {
			if _, ok := relativeToRoot(dep.Dir, path); ok && dependency.ListsFile(dep.Files, a.absPath(path)) {
				return dep
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// findingFile returns the file a finding names: its path under the root of
// the dependency its asset belongs to, or under the project root. A
// dependency without a source directory has no files.
func (a *exportArtifacts) findingFile(findingPath string, depInfo *entities.DependencyInfo) (string, bool) {
	if findingPath == "" {
		return "", false
	}
	path := filepath.FromSlash(findingPath)
	if !filepath.IsAbs(path) {
		root := a.projectRoot
		if depInfo != nil && depInfo.Module != "" {
			dep := a.dependencyByVersion[dependencyVersionKey(depInfo.Module, depInfo.Version)]
			if dep == nil {
				return "", false
			}
			root = dep.Dir
		}
		path = filepath.Join(root, path)
	}
	return a.absPath(path), true
}

func (a *exportArtifacts) absPath(path string) string {
	if filepath.IsAbs(path) || a.cwd == "" {
		return filepath.Clean(path)
	}
	return filepath.Join(a.cwd, path)
}

// functionFileIndex groups functions by the file that declares them.
type functionFileIndex struct {
	byFile map[string][]*callgraph.FunctionDecl
}

func newFunctionFileIndex(artifacts *exportArtifacts, functions map[string]*callgraph.FunctionDecl) *functionFileIndex {
	idx := &functionFileIndex{byFile: make(map[string][]*callgraph.FunctionDecl)}
	for _, fn := range functions {
		if fn == nil || fn.FilePath == "" {
			continue
		}
		file := artifacts.absPath(fn.FilePath)
		idx.byFile[file] = append(idx.byFile[file], fn)
	}
	return idx
}

// containing returns the innermost function of file whose span holds the
// position (line, col). Spans nest (a synthetic <clinit> may cover the whole
// class around the real method, a JS callback sits inside its caller), so the
// tightest span wins, with the function key as a deterministic tie-break.
//
// Containment is column-aware: a function that starts later on the finding's
// own line, as the arrow function passed to `generateKeyPair(..., (e) => {`,
// does not hold a finding that starts before it. A zero col, or a function
// whose parser records no columns, is judged by lines alone, which is the
// behavior for every line a single function covers.
func (idx *functionFileIndex) containing(file string, line, col int) *callgraph.FunctionDecl {
	var best *callgraph.FunctionDecl
	for _, fn := range idx.byFile[file] {
		if !spanHolds(fn, line, col) {
			continue
		}
		if best == nil || tighterSpan(fn, best) {
			best = fn
		}
	}
	return best
}

func spanHolds(fn *callgraph.FunctionDecl, line, col int) bool {
	if line < fn.StartLine || line > fn.EndLine {
		return false
	}
	if col <= 0 {
		return true
	}
	if line == fn.StartLine && fn.StartCol > 0 && col < fn.StartCol {
		return false
	}
	if line == fn.EndLine && fn.EndCol > 0 && col >= fn.EndCol {
		return false
	}
	return true
}

// tighterSpan reports whether a is nested inside b: fewer lines, else later
// start, else (on equal spans) first by function key, so the choice is stable
// across map iteration orders.
func tighterSpan(a, b *callgraph.FunctionDecl) bool {
	spanA := a.EndLine - a.StartLine
	spanB := b.EndLine - b.StartLine
	if spanA != spanB {
		return spanA < spanB
	}
	if a.StartLine != b.StartLine {
		return a.StartLine > b.StartLine
	}
	if a.StartCol != b.StartCol {
		return a.StartCol > b.StartCol
	}
	return a.ID.String() < b.ID.String()
}
