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

package engine

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// storeComponents name directories that hold installed packages, one
// directory per package version, written by a package manager from the
// published artifact: npm's node_modules and Python's site-packages and
// dist-packages.
var storeComponents = []string{"node_modules", "site-packages", "dist-packages"}

// cacheRoot is what a dependency's findings-cache identity keeps of dir,
// the dependency's source directory (dependencyCacheIdentity.Root). When s
// scans roots through relative paths and dir lies in a store of published
// package versions, it is dir's place in that store, which every host and
// home extracting the same version shares: "sources:" or "gomodcache:" or
// "cargo-registry:" or "cargo-git:" and the path below the store, or the
// path from the first storeComponents component on. Otherwise it is dir.
//
// A root-relative scan finds the same and reports the same root-relative
// paths wherever dir lies, so dir matters only as a proxy for the source's
// content. Module@version names the content of a published version, but
// not of a local directory standing for one (a Go replace directive with a
// path, a path dependency), whose content can differ between two
// directories, so those stay keyed by where they are. The place in the
// store still tells apart two versions standing for one module@version, as
// a Go replace directive naming another module does.
func cacheRoot(s scanner.Scanner, dir string) string {
	relative, ok := s.(scanner.RootRelativeScanner)
	if !ok || !relative.ScansRootRelative() {
		return dir
	}
	if place, ok := storePlace(dir); ok {
		return place
	}
	return dir
}

// cacheCWD is what a dependency's findings-cache identity keeps of cwd,
// crypto-finder's working directory. A scanner that scans roots through
// relative paths runs in the root, not in cwd: cwd then reaches its results
// only through rule ids, which the CLI prefixes with a rule file's
// directory relative to its working directory when the file lies below it
// (opengrep's configPrefix), and crypto-finder reports those ids as the CLI
// run in cwd would. So cwd is keyed when a rule path lies below it or holds
// it, and for every other scanner.
func cacheCWD(s scanner.Scanner, cwd string, rulePaths []string) string {
	relative, ok := s.(scanner.RootRelativeScanner)
	if !ok || !relative.ScansRootRelative() {
		return cwd
	}
	for _, rulePath := range rulePaths {
		abs, err := filepath.Abs(rulePath)
		if err != nil {
			return cwd
		}
		for _, dir := range withResolved(cwd) {
			for _, path := range withResolved(abs) {
				if nested(dir, path) {
					return cwd
				}
			}
		}
	}
	return ""
}

// withResolved is path, and path with its symlinks resolved when that
// differs.
func withResolved(path string) []string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil && resolved != path {
		return []string{path, resolved}
	}
	return []string{path}
}

// nested reports whether a and b are one directory or one lies below the
// other.
func nested(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	_, below1 := below(a, b)
	_, below2 := below(b, a)
	return below1 || below2
}

// rootRelativeReport reports whether every file report names is relative
// to the scanned root and lies below it: what a cache entry serving
// dependencies extracted elsewhere may hold.
func rootRelativeReport(report *entities.InterimReport) bool {
	if report == nil {
		return true
	}
	for i := range report.Findings {
		if report.Findings[i].FilePath == "" {
			return false
		}
		path := filepath.ToSlash(filepath.Clean(report.Findings[i].FilePath))
		if filepath.IsAbs(report.Findings[i].FilePath) || strings.HasPrefix(path, "/") || path == ".." || strings.HasPrefix(path, "../") {
			return false
		}
	}
	return true
}

// rootAnchoredPatterns returns patterns with the ones anchored at dir, an
// absolute path below it, named relative to it behind "$ROOT/".
func rootAnchoredPatterns(patterns []string, dir string) []string {
	base := filepath.ToSlash(filepath.Clean(dir)) + "/"
	out := make([]string, len(patterns))
	for i, pattern := range patterns {
		out[i] = pattern
		if rest, ok := strings.CutPrefix(pattern, base); ok {
			out[i] = "$ROOT/" + rest
		}
	}
	return out
}

// storePlace returns dir's place in the store of published package
// versions that holds it, and whether one does.
func storePlace(dir string) (string, bool) {
	if dir == "" || !filepath.IsAbs(dir) {
		return "", false
	}
	dir = filepath.Clean(dir)
	parts := strings.Split(filepath.ToSlash(dir), "/")
	for i, part := range parts {
		if slices.Contains(storeComponents, part) {
			return strings.Join(parts[i:], "/"), true
		}
	}
	for _, store := range packageStores() {
		for _, base := range withResolved(store.dir) {
			for _, path := range withResolved(dir) {
				if rel, ok := below(base, path); ok {
					return store.name + ":" + filepath.ToSlash(rel), true
				}
			}
		}
	}
	return "", false
}

// packageStore is a store directory and the name its places carry.
type packageStore struct {
	name, dir string
}

// packageStores lists the store directories of the current environment.
func packageStores() []packageStore {
	var stores []packageStore
	if dir, err := dependency.SourceCacheDir(); err == nil {
		stores = append(stores, packageStore{"sources", dir})
	}
	home, homeErr := os.UserHomeDir()
	switch {
	case os.Getenv("GOMODCACHE") != "":
		stores = append(stores, packageStore{"gomodcache", os.Getenv("GOMODCACHE")})
	case os.Getenv("GOPATH") != "":
		stores = append(stores, packageStore{"gomodcache", filepath.Join(filepath.SplitList(os.Getenv("GOPATH"))[0], "pkg", "mod")})
	case homeErr == nil:
		stores = append(stores, packageStore{"gomodcache", filepath.Join(home, "go", "pkg", "mod")})
	}
	cargo := os.Getenv("CARGO_HOME")
	if cargo == "" && homeErr == nil {
		cargo = filepath.Join(home, ".cargo")
	}
	if cargo != "" {
		stores = append(stores,
			packageStore{"cargo-registry", filepath.Join(cargo, "registry", "src")},
			packageStore{"cargo-git", filepath.Join(cargo, "git", "checkouts")})
	}
	kept := stores[:0]
	for _, store := range stores {
		if filepath.IsAbs(store.dir) {
			kept = append(kept, packageStore{store.name, filepath.Clean(store.dir)})
		}
	}
	return kept
}

// below returns path relative to dir when it lies strictly below it.
func below(dir, path string) (string, bool) {
	rel, err := filepath.Rel(dir, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return rel, true
}
