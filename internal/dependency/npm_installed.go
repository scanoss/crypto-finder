// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"os"
	"path/filepath"
	"strings"
)

// maxNodeModulesDepth bounds how many nested node_modules levels the index
// follows below the project's.
const maxNodeModulesDepth = 6

// indexInstalledNpm maps each package installed under nodeModules, by
// "name@version" as its own package.json states them, to its resolved directory:
// the packages of nodeModules and of the node_modules nested in them (npm,
// yarn), and the virtual store of pnpm (.pnpm), whose entries are symbolic
// links. The shallowest copy of a package wins. A project that was never
// installed has an empty index.
func indexInstalledNpm(nodeModules string) map[string]string {
	index := map[string]string{}
	indexNodeModules(nodeModules, index, map[string]bool{}, 0)
	return index
}

func indexNodeModules(dir string, index map[string]string, seen map[string]bool, depth int) {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || seen[resolved] || depth > maxNodeModulesDepth {
		return
	}
	seen[resolved] = true
	entries, err := os.ReadDir(resolved)
	if err != nil {
		return
	}
	var nested []string
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case name == ".pnpm":
			for _, virtual := range readDirEntries(filepath.Join(resolved, name)) {
				nested = append(nested, filepath.Join(resolved, name, virtual.Name(), "node_modules"))
			}
		case strings.HasPrefix(name, "."):
		case strings.HasPrefix(name, "@"):
			for _, member := range readDirEntries(filepath.Join(resolved, name)) {
				nested = append(nested, indexInstalledPackage(filepath.Join(resolved, name, member.Name()), index)...)
			}
		default:
			nested = append(nested, indexInstalledPackage(filepath.Join(resolved, name), index)...)
		}
	}
	for _, next := range nested {
		indexNodeModules(next, index, seen, depth+1)
	}
}

// indexInstalledPackage records the package in dir, following a symbolic
// link, and returns its own node_modules directory to index next.
func indexInstalledPackage(dir string, index map[string]string) []string {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || !isDir(resolved) {
		return nil
	}
	if name, version := readPackageNameVersion(filepath.Join(resolved, "package.json")); name != "" && version != "" {
		key := Ref{Module: name, Version: version}.Key()
		if _, ok := index[key]; !ok {
			index[key] = resolved
		}
	}
	return []string{filepath.Join(resolved, "node_modules")}
}

// readDirEntries lists dir; an unreadable one has no entries.
func readDirEntries(dir string) []os.DirEntry {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	return entries
}
