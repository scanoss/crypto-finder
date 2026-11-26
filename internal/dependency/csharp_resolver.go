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
	"context"
	"encoding/json"
	"encoding/xml"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CSharpResolver resolves a .NET project's dependencies from the files that
// carry a resolved version: the NuGet lock file, the restore's asset file,
// and the packages.config of a .NET Framework project. A `PackageReference`
// of a project file states a minimum (`Version="1.2.3"` is `[1.2.3, )`), not
// a version, so it is not read: mining the wrong version of a package is
// worse than mining none.
//
// A NuGet package ships assemblies, not source, so a dependency rarely has a
// directory to scan. It is reported all the same, with its coordinate, so the
// scan can say which packages it could not read rather than omit them.
type CSharpResolver struct {
	packagesDir string
}

// NewCSharpResolver returns a resolver that reads a project's resolved
// versions and looks for each package in the local NuGet cache.
func NewCSharpResolver() *CSharpResolver {
	return &CSharpResolver{packagesDir: nugetPackagesDir()}
}

// The C# ecosystem, as the call graph and the resolvers name it.
const ecosystemCSharp = "csharp"

// Ecosystem implements Resolver.
func (r *CSharpResolver) Ecosystem() string { return ecosystemCSharp }

// The files a resolved version is read from, in the order they are read: the
// lock file a project opts into, the asset file every restore writes, and the
// package list of a .NET Framework project.
const (
	csharpLockFile     = "packages.lock.json"
	csharpAssetsFile   = "project.assets.json"
	csharpPackagesFile = "packages.config"
)

// CanResolve implements Resolver: a project with a file that carries resolved
// versions.
func (r *CSharpResolver) CanResolve(targetDir string) bool {
	for _, path := range csharpVersionFiles(targetDir) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// csharpVersionFiles are the files of a project directory that carry resolved
// versions, in read order.
func csharpVersionFiles(targetDir string) []string {
	return []string{
		filepath.Join(targetDir, csharpLockFile),
		filepath.Join(targetDir, "obj", csharpAssetsFile),
		filepath.Join(targetDir, csharpPackagesFile),
	}
}

// Resolve implements Resolver.
func (r *CSharpResolver) Resolve(_ context.Context, targetDir string) (*ResolveResult, error) {
	packages, err := csharpResolvedPackages(targetDir)
	if err != nil {
		return nil, err
	}
	result := &ResolveResult{RootModule: filepath.Base(targetDir)}
	for _, p := range packages {
		dep := Dependency{Module: p.id, Version: p.version}
		if dir := r.sourceDir(p.id, p.version); dir != "" {
			dep.Dir = dir
		}
		result.Dependencies = append(result.Dependencies, dep)
	}
	return result, nil
}

// sourceDir is where a package's source sits in the local NuGet cache, or ""
// when the package is absent or ships assemblies only, which is the common
// case: a package that carries no source is still reported.
func (r *CSharpResolver) sourceDir(id, version string) string {
	if r.packagesDir == "" {
		return ""
	}
	dir := filepath.Join(r.packagesDir, strings.ToLower(id), strings.ToLower(version))
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return ""
	}
	if !csharpHoldsSource(dir) {
		return ""
	}
	return dir
}

// csharpHoldsSource reports a directory with a C# source file under it.
func csharpHoldsSource(dir string) bool {
	found := false
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return fs.SkipDir // an unreadable directory holds nothing to find
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".cs") {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return err == nil && found
}

// nugetPackagesDir is the local package cache: NUGET_PACKAGES, else the
// default under the user's home.
func nugetPackagesDir() string {
	if dir := os.Getenv("NUGET_PACKAGES"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".nuget", "packages")
}

// csharpPackage is one resolved package of a project.
type csharpPackage struct{ id, version string }

// csharpResolvedPackages reads a project's resolved packages from the first
// file that carries them, and merges the packages.config of a .NET Framework
// project beside them.
func csharpResolvedPackages(targetDir string) ([]csharpPackage, error) {
	seen := map[string]bool{}
	var out []csharpPackage
	add := func(packages []csharpPackage) {
		for _, p := range packages {
			key := strings.ToLower(p.id) + "@" + p.version
			if p.id == "" || p.version == "" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, p)
		}
	}
	if packages, err := parseNuGetLock(filepath.Join(targetDir, csharpLockFile)); err == nil {
		add(packages)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if packages, err := parseNuGetAssets(filepath.Join(targetDir, "obj", csharpAssetsFile)); err == nil {
		add(packages)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if packages, err := parsePackagesConfig(filepath.Join(targetDir, csharpPackagesFile)); err == nil {
		add(packages)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].id != out[j].id {
			return out[i].id < out[j].id
		}
		return out[i].version < out[j].version
	})
	return out, nil
}

// nugetLock is packages.lock.json: per target framework, each package with
// the version it resolved to. A project entry (`"type": "Project"`) is the
// solution's own code, which the scan already reads, and carries no version.
type nugetLock struct {
	Dependencies map[string]map[string]struct {
		Type     string `json:"type"`
		Resolved string `json:"resolved"`
	} `json:"dependencies"`
}

func parseNuGetLock(path string) ([]csharpPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock nugetLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var out []csharpPackage
	for _, framework := range lock.Dependencies {
		for id, entry := range framework {
			if strings.EqualFold(entry.Type, "Project") {
				continue
			}
			out = append(out, csharpPackage{id: id, version: entry.Resolved})
		}
	}
	return out, nil
}

// nugetAssets is obj/project.assets.json, which every restore writes: its
// libraries are keyed `<id>/<version>`, and only those of type `package` come
// from a feed.
type nugetAssets struct {
	Libraries map[string]struct {
		Type string `json:"type"`
	} `json:"libraries"`
}

func parseNuGetAssets(path string) ([]csharpPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var assets nugetAssets
	if err := json.Unmarshal(data, &assets); err != nil {
		return nil, err
	}
	var out []csharpPackage
	for key, library := range assets.Libraries {
		if !strings.EqualFold(library.Type, "package") {
			continue
		}
		id, version, ok := strings.Cut(key, "/")
		if !ok {
			continue
		}
		out = append(out, csharpPackage{id: id, version: version})
	}
	return out, nil
}

// packagesConfig is the package list of a .NET Framework project, which
// writes an exact version per package.
type packagesConfig struct {
	Packages []struct {
		ID      string `xml:"id,attr"`
		Version string `xml:"version,attr"`
	} `xml:"package"`
}

func parsePackagesConfig(path string) ([]csharpPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config packagesConfig
	if err := xml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	out := make([]csharpPackage, 0, len(config.Packages))
	for _, p := range config.Packages {
		out = append(out, csharpPackage{id: p.ID, version: p.Version})
	}
	return out, nil
}
