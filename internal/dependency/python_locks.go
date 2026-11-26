// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/scanoss/reach/purl"

	"github.com/scanoss/crypto-finder/internal/utils"
)

// pdm.lock and pylock.toml are not read by scanoss.go's resolver; these are
// small parsers of the fields the closure needs.

// readPdmLock reads pdm.lock (lock_version 4): every [[package]] at its
// version, an entry with extras merged into the plain one, its PEP 508
// dependencies resolved to every locked version of the name (the union of
// marker branches), and its groups: a package only development groups
// ([tool.pdm.dev-dependencies], [dependency-groups]) need is dev; "default"
// and the optional-dependencies extras are runtime. The direct requirements
// are pyproject.toml's.
func readPdmLock(dir string) (*pyGraph, error) { //nolint:gocognit,gocyclo // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	data, err := os.ReadFile(filepath.Join(dir, "pdm.lock"))
	if err != nil {
		return nil, err
	}
	var lock struct {
		Metadata struct {
			LockVersion string `toml:"lock_version"`
		} `toml:"metadata"`
		Package []struct {
			Name         string   `toml:"name"`
			Version      string   `toml:"version"`
			Extras       []string `toml:"extras"`
			Groups       []string `toml:"groups"`
			Marker       string   `toml:"marker"`
			Dependencies []string `toml:"dependencies"`
			Path         string   `toml:"path"`
			Editable     bool     `toml:"editable"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("pdm.lock: %w", err)
	}
	if major, _, _ := strings.Cut(lock.Metadata.LockVersion, "."); major != "4" {
		return nil, fmt.Errorf("pdm.lock: unsupported lock_version %q", lock.Metadata.LockVersion)
	}
	g := newPyGraph("pdm.lock")
	devGroups := pyDevGroups(dir)
	keys := make([]string, len(lock.Package))
	runtime := map[string]bool{}
	for i, p := range lock.Package {
		if p.Path != "" || p.Editable || p.Version == "" {
			continue
		}
		n := g.add(purl.PyPIName(p.Name), p.Version)
		keys[i] = n.ref.Key()
		for _, extra := range p.Extras {
			n.extras = addSorted(n.extras, purl.PyPIName(extra))
		}
		n.markers = addSorted(n.markers, p.Marker)
		if len(p.Groups) == 0 || slices.ContainsFunc(p.Groups, func(group string) bool { return !devGroups[group] }) {
			runtime[keys[i]] = true
		}
	}
	for key, n := range g.nodes {
		n.dev = !runtime[key]
	}
	for i, p := range lock.Package {
		if keys[i] == "" {
			continue
		}
		for _, raw := range p.Dependencies {
			if req, ok := parsePyRequirement(raw); ok {
				g.requireName(keys[i], req, req.Marker)
			}
		}
	}
	declarePyproject(g, dir)
	return g, nil
}

// pylockNames lists dir's PEP 751 lock files: pylock.toml, else every
// pylock.<name>.toml (their union).
func pylockNames(dir string) []string {
	if fileExists(filepath.Join(dir, "pylock.toml")) {
		return []string{"pylock.toml"}
	}
	matches := utils.Lenient(filepath.Glob(filepath.Join(dir, "pylock.*.toml")))
	var out []string
	for _, m := range matches {
		if fileExists(m) {
			out = append(out, filepath.Base(m))
		}
	}
	slices.Sort(out)
	return out
}

// readPylock reads PEP 751 lock files (lock-version 1.x): every package with
// a version, its marker kept as its own (a marker can also name dependency
// groups or extras: the union keeps them all), and the dependencies a
// package records, which identify a package by name and optionally version.
// A package without a version (a directory, a VCS checkout) is not a pinned
// distribution. The direct requirements are pyproject.toml's.
func readPylock(dir string, names []string) (*pyGraph, error) { //nolint:gocognit // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	type pylockRef struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
	}
	type pylockPackage struct {
		Name         string      `toml:"name"`
		Version      string      `toml:"version"`
		Marker       string      `toml:"marker"`
		Dependencies []pylockRef `toml:"dependencies"`
	}
	g := newPyGraph(strings.Join(names, ","))
	var packages []pylockPackage
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		var lock struct {
			LockVersion string          `toml:"lock-version"`
			Packages    []pylockPackage `toml:"packages"`
		}
		if err := toml.Unmarshal(data, &lock); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if major, _, _ := strings.Cut(lock.LockVersion, "."); major != "1" {
			return nil, fmt.Errorf("%s: unsupported lock-version %q", name, lock.LockVersion)
		}
		packages = append(packages, lock.Packages...)
	}
	for _, p := range packages {
		if p.Version != "" {
			n := g.add(purl.PyPIName(p.Name), p.Version)
			n.markers = addSorted(n.markers, p.Marker)
		}
	}
	for _, p := range packages {
		if p.Version == "" {
			continue
		}
		from := Ref{Module: purl.PyPIName(p.Name), Version: p.Version}.Key()
		for _, d := range p.Dependencies {
			name := purl.PyPIName(d.Name)
			for _, to := range g.named(name) {
				if d.Version == "" || g.nodes[to].ref.Version == d.Version {
					g.link(from, to, "")
				}
			}
		}
	}
	declarePyproject(g, dir)
	return g, nil
}

// declarePyproject declares the requirements dir's manifests declare as the
// application's, for a lock that does not record them.
func declarePyproject(g *pyGraph, dir string) {
	for _, d := range declaredPyRequirements(dir) {
		g.requireName("", d.req, d.req.Marker)
	}
}

// pyDevGroups names the development dependency groups dir's pyproject.toml
// declares: PEP 735 [dependency-groups] and PDM's [tool.pdm.dev-dependencies].
func pyDevGroups(dir string) map[string]bool {
	groups := map[string]bool{}
	data, err := os.ReadFile(filepath.Join(dir, "pyproject.toml"))
	if err != nil {
		return groups
	}
	var py struct {
		DependencyGroups map[string]any `toml:"dependency-groups"`
		Tool             struct {
			Pdm struct {
				DevDependencies map[string]any `toml:"dev-dependencies"`
			} `toml:"pdm"`
		} `toml:"tool"`
	}
	if toml.Unmarshal(data, &py) != nil {
		return groups
	}
	for name := range py.DependencyGroups {
		groups[name] = true
	}
	for name := range py.Tool.Pdm.DevDependencies {
		groups[name] = true
	}
	return groups
}
