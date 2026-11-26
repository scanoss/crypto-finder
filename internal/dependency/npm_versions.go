// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// An npm lock routinely holds one package at several versions (a hoisted copy
// and copies nested under the packages that need another). The reachability
// request takes one version per package URL, so the closure keeps the version
// a bare require of the package from the project resolves to, and lists the
// others in ResolveResult.OtherVersions.

// npmHoistedVersions maps each package to the version the lock installs at
// the top level of node_modules (package-lock.json, npm-shrinkwrap.json of
// lockfileVersion 2 and 3: the "node_modules/<name>" package path). It is nil
// for any other lock, whose preference comes from the graph.
func npmHoistedVersions(dir, lock string) map[string]string {
	if lock != "package-lock.json" && lock != "npm-shrinkwrap.json" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(dir, lock)) // #nosec G304 -- the scan target's own lock file.
	if err != nil {
		return nil
	}
	var parsed struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if json.Unmarshal(data, &parsed) != nil {
		return nil
	}
	out := map[string]string{}
	for path, entry := range parsed.Packages {
		name, ok := strings.CutPrefix(path, "node_modules/")
		if ok && entry.Version != "" && !strings.Contains(name, "node_modules/") {
			out[name] = entry.Version
		}
	}
	return out
}

// npmPreferred reports whether a is the version of a package to keep over b:
// the hoisted one; else one a manifest declares directly; else the one more
// packages depend on; else the higher semantic version, never the later string.
func (c *npmCollector) npmPreferred(a, b Ref) bool {
	if hoisted, ok := c.hoisted[a.Module]; ok && (a.Version == hoisted) != (b.Version == hoisted) {
		return a.Version == hoisted
	}
	if c.directRef[a] != c.directRef[b] {
		return c.directRef[a]
	}
	if c.incoming[a] != c.incoming[b] {
		return c.incoming[a] > c.incoming[b]
	}
	return npmVersionLess(b.Version, a.Version)
}

// npmVersionLess orders versions as semver; one that is not semver sorts below
// one that is, and two that are not compare as text.
func npmVersionLess(a, b string) bool {
	va, errA := semver.NewVersion(a)
	vb, errB := semver.NewVersion(b)
	switch {
	case errA == nil && errB == nil:
		return va.LessThan(vb)
	case errA == nil:
		return false
	case errB == nil:
		return true
	}
	return a < b
}

// chooseVersions keeps one version of each package: it removes the others
// from c.kept, lists them in the result, and returns where an edge to one of
// them now points.
func (c *npmCollector) chooseVersions() map[Ref]Ref {
	byModule := map[string][]Ref{}
	for ref := range c.kept {
		byModule[ref.Module] = append(byModule[ref.Module], ref)
	}
	redirect := map[Ref]Ref{}
	for _, refs := range byModule {
		if len(refs) < 2 {
			continue
		}
		sort.Slice(refs, func(i, j int) bool { return c.npmPreferred(refs[i], refs[j]) })
		for _, other := range refs[1:] {
			delete(c.kept, other)
			redirect[other] = refs[0]
			c.result.OtherVersions = append(c.result.OtherVersions, Dependency{Module: other.Module, Version: other.Version})
		}
	}
	sort.Slice(c.result.OtherVersions, func(i, j int) bool {
		a, b := c.result.OtherVersions[i], c.result.OtherVersions[j]
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		return npmVersionLess(a.Version, b.Version)
	})
	return redirect
}

// KeepOneNpmVersionAcrossRoots keeps one version of each npm package in a
// result merged from several roots (a monorepo with a lock per service), as
// each root's resolver already does within its lock: a version some root
// installed is requested, else the highest semver; the others are listed in
// OtherVersions, and an edge to one of them points at the kept version.
func KeepOneNpmVersionAcrossRoots(result *ResolveResult) {
	byModule := map[string][]Dependency{}
	for _, dep := range result.Dependencies {
		byModule[dep.Module] = append(byModule[dep.Module], dep)
	}
	redirect := map[Ref]Ref{}
	kept := result.Dependencies[:0]
	for _, dep := range result.Dependencies {
		versions := byModule[dep.Module]
		best := versions[0]
		for _, v := range versions[1:] {
			if npmAcrossRootsPreferred(v, best) {
				best = v
			}
		}
		if dep.Version == best.Version {
			// Several roots may lock the same version; keep the copy a root
			// installed (Dir set), which offline mining reads.
			if i := slices.IndexFunc(kept, func(k Dependency) bool { return k.Module == dep.Module && k.Version == dep.Version }); i < 0 {
				kept = append(kept, dep)
			} else if kept[i].Dir == "" && dep.Dir != "" {
				kept[i] = dep
			}
			continue
		}
		other := Ref{Module: dep.Module, Version: dep.Version}
		if _, done := redirect[other]; !done {
			redirect[other] = Ref{Module: best.Module, Version: best.Version}
			result.OtherVersions = append(result.OtherVersions, Dependency{Module: dep.Module, Version: dep.Version})
		}
	}
	result.Dependencies = kept
	droppedEdges := map[Ref][]Ref{}
	for other := range redirect {
		droppedEdges[other] = result.VersionedGraph[other.Key()]
	}
	if len(redirect) > 0 {
		redirectVersionedGraph(result.VersionedGraph, redirect)
		redirectVersionedGraph(result.OmittedEdges, redirect)
	}
	result.OtherVersions = npmOtherVersions(result.OtherVersions, kept)
	npmDropUnderOtherVersions(result, droppedEdges)
	// Each root listed what only its own dropped versions required: once
	// across roots, and never a package another root's lock requests.
	result.UnderOtherVersions = npmOtherVersions(result.UnderOtherVersions, result.Dependencies)
}

// npmIncoming is the set of refs some edge of graph points at.
func npmIncoming(graph map[string][]Ref) map[Ref]bool {
	incoming := map[Ref]bool{}
	for _, children := range graph {
		for _, child := range children {
			incoming[child] = true
		}
	}
	return incoming
}

// npmDropUnderOtherVersions moves out of Dependencies each package that a
// dropped version required (droppedEdges: the edges of the versions dropped)
// and that no requested package and no declaration of the project leads to
// any more, and then the packages only those required, in turn. A package no
// dropped version required stays, whatever the graph holds.
func npmDropUnderOtherVersions(result *ResolveResult, droppedEdges map[Ref][]Ref) {
	direct := map[string]bool{}
	for _, module := range result.DirectDependencies {
		direct[module] = true
	}
	candidates := map[Ref]bool{}
	for _, children := range droppedEdges {
		for _, child := range children {
			candidates[child] = true
		}
	}
	for len(candidates) > 0 {
		incoming := npmIncoming(result.VersionedGraph)
		next := map[Ref]bool{}
		kept := result.Dependencies[:0]
		for _, dep := range result.Dependencies {
			ref := Ref{Module: dep.Module, Version: dep.Version}
			if !candidates[ref] || direct[dep.Module] || incoming[ref] {
				kept = append(kept, dep)
				continue
			}
			result.UnderOtherVersions = append(result.UnderOtherVersions, Dependency{Module: dep.Module, Version: dep.Version})
			for _, child := range result.VersionedGraph[ref.Key()] {
				next[child] = true
			}
			delete(result.VersionedGraph, ref.Key())
		}
		result.Dependencies = kept
		candidates = next
	}
	sort.Slice(result.UnderOtherVersions, func(i, j int) bool {
		a, b := result.UnderOtherVersions[i], result.UnderOtherVersions[j]
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		return npmVersionLess(a.Version, b.Version)
	})
}

// npmAcrossRootsPreferred reports whether a is preferred over b across roots:
// a version some root installed (which offline mining reads), else the
// higher semver.
func npmAcrossRootsPreferred(a, b Dependency) bool {
	if (a.Dir != "") != (b.Dir != "") {
		return a.Dir != ""
	}
	return npmVersionLess(b.Version, a.Version)
}

// npmOtherVersions is every version listed as another (by a root's lock or
// across roots) that is not a version finally requested, once each, in
// module and semver order.
func npmOtherVersions(others, kept []Dependency) []Dependency {
	requested := map[Ref]bool{}
	for _, dep := range kept {
		requested[Ref{Module: dep.Module, Version: dep.Version}] = true
	}
	seen := map[Ref]bool{}
	var out []Dependency
	for _, dep := range others {
		ref := Ref{Module: dep.Module, Version: dep.Version}
		if requested[ref] || seen[ref] {
			continue
		}
		seen[ref] = true
		out = append(out, Dependency{Module: dep.Module, Version: dep.Version})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		return npmVersionLess(a.Version, b.Version)
	})
	return out
}

// redirectVersionedGraph points each edge to a dropped version at the kept
// one, drops the dropped version's own entry, and removes duplicate and self edges.
func redirectVersionedGraph(graph map[string][]Ref, redirect map[Ref]Ref) {
	for from, children := range graph {
		parent := refOfKey(from)
		if _, dropped := redirect[parent]; dropped {
			delete(graph, from)
			continue
		}
		var out []Ref
		for _, child := range children {
			if to, ok := redirect[child]; ok {
				child = to
			}
			if child != parent && !slices.Contains(out, child) {
				out = append(out, child)
			}
		}
		graph[from] = out
	}
}
