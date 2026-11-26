// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"os"
	"path/filepath"
)

// GoModuleDir is a required module's source directory.
type GoModuleDir struct {
	Module string
	Dir    string
}

// GoSourceModules are the source directories of the modules the go.mod at
// targetDir requires, or the go.mod files below it when it has none, after
// replace directives: a module version the module cache holds, or a local
// replacement directory. A module neither provides is left out.
func GoSourceModules(targetDir string, skipPatterns []string) []GoModuleDir {
	dirs := []string{absoluteScanRoot(targetDir)}
	if discovery := ResolutionRoots(targetDir, ecosystemGo, skipPatterns); discovery.Searched {
		dirs = dirs[:0]
		for _, root := range discovery.Roots {
			dirs = append(dirs, root.Dir)
		}
	}
	r := NewGoResolver()
	seen := map[string]bool{}
	var out []GoModuleDir
	add := func(module, dir string) {
		if dir == "" || seen[module+"\x00"+dir] {
			return
		}
		seen[module+"\x00"+dir] = true
		out = append(out, GoModuleDir{Module: module, Dir: dir})
	}
	for _, dir := range dirs {
		mod, err := readGoMod(filepath.Join(dir, goModManifest))
		if err != nil {
			continue
		}
		for _, req := range mod.requires {
			ref, ok := mod.replaced(req.ref)
			if !ok {
				add(req.ref.Module, goLocalReplacement(dir, mod, req.ref))
				continue
			}
			add(req.ref.Module, r.cacheDir(ref))
		}
	}
	return out
}

// goLocalReplacement is the directory a local replace directive points ref at.
func goLocalReplacement(modDir string, mod *goModFile, ref Ref) string {
	to, hit := mod.replaces[ref.Module+"@"+ref.Version]
	if !hit {
		to = mod.replaces[ref.Module]
	}
	dir := to.Module
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(modDir, dir)
	}
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		return dir
	}
	return ""
}
