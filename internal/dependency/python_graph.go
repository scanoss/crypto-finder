// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"slices"
	"sort"
)

// pyGraph is a Python closure as one input describes it: distributions at
// pinned versions, the requirements between them with their markers, and the
// application's own requirements when the input knows them. Every Python
// input (a lock file, an installed environment, declared requirements) is
// read into one, and toResult turns it into a ResolveResult.
type pyGraph struct {
	source string
	nodes  map[string]*pyNode
	links  map[string][]pyLink
	// declared holds the application's requirements; directKnown says the
	// input knows them (an empty list then means no dependency).
	declared    []pyLink
	directKnown bool
	unpinned    []UnpinnedDependency
}

type pyNode struct {
	ref Ref
	// markers are the entry's own markers (uv resolution-markers, a
	// Pipfile.lock or pylock marker).
	markers []string
	extras  []string
	// dev marks a distribution only development requirements bring in.
	dev   bool
	dir   string
	files []string
}

// pyLink is a requirement resolved to a node, with its marker as written.
type pyLink struct {
	to     string
	marker string
}

func newPyGraph(source string) *pyGraph {
	return &pyGraph{source: source, nodes: map[string]*pyNode{}, links: map[string][]pyLink{}}
}

// add returns the node of name at version, adding it when new. name must be
// PEP 503 normalised; the version is kept as written.
func (g *pyGraph) add(name, version string) *pyNode {
	ref := Ref{Module: name, Version: version}
	key := ref.Key()
	if n, ok := g.nodes[key]; ok {
		return n
	}
	n := &pyNode{ref: ref}
	g.nodes[key] = n
	return n
}

// named returns the keys of the nodes of name, sorted.
func (g *pyGraph) named(name string) []string {
	var keys []string
	for key, n := range g.nodes {
		if n.ref.Module == name {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func (g *pyGraph) link(from, to, marker string) {
	if from == to || slices.Contains(g.links[from], pyLink{to, marker}) {
		return
	}
	g.links[from] = append(g.links[from], pyLink{to, marker})
}

func (g *pyGraph) declare(to, marker string) {
	g.directKnown = true
	if !slices.Contains(g.declared, pyLink{to, marker}) {
		g.declared = append(g.declared, pyLink{to, marker})
	}
}

// requireName links from (or declares, for from "") every node of req's
// name, the union of the versions a lock pins it at, and enables req's
// extras on them.
func (g *pyGraph) requireName(from string, req pyRequirement, marker string) {
	for _, key := range g.named(req.Name) {
		g.nodes[key].extras = addSorted(g.nodes[key].extras, req.Extras...)
		if from == "" {
			g.declare(key, marker)
		} else {
			g.link(from, key, marker)
		}
	}
}

// trimToDeclared keeps only the nodes the declared requirements reach.
func (g *pyGraph) trimToDeclared() {
	reached := map[string]bool{}
	var walk func(key string)
	walk = func(key string) {
		if reached[key] {
			return
		}
		reached[key] = true
		for _, l := range g.links[key] {
			walk(l.to)
		}
	}
	for _, l := range g.declared {
		walk(l.to)
	}
	for key := range g.nodes {
		if !reached[key] {
			delete(g.nodes, key)
			delete(g.links, key)
		}
	}
}

// toResult builds the ResolveResult: every distribution that is not dev-only,
// the requirement edges between them (Graph by name, VersionedGraph by
// name@version), the declared ones as DirectDependencies, and each
// dependency's markers (see Dependency.Markers). When the application's
// requirements are known every dependency gets a Graph entry, so Paths can
// tell a transitive one from a direct one even without edges.
func (g *pyGraph) toResult() *ResolveResult { //nolint:gocognit,gocyclo // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	kept := func(key string) bool { n, ok := g.nodes[key]; return ok && !n.dev }
	incoming := map[string][]string{}
	unconditional := map[string]bool{}
	note := func(l pyLink) {
		if l.marker == "" {
			unconditional[l.to] = true
		}
		incoming[l.to] = addSorted(incoming[l.to], l.marker)
	}
	result := &ResolveResult{
		Source:         g.source,
		Graph:          map[string][]string{},
		VersionedGraph: map[string][]Ref{},
		Unpinned:       g.unpinned,
	}
	keys := make([]string, 0, len(g.nodes))
	for key := range g.nodes {
		if kept(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		n := g.nodes[key]
		for _, l := range g.links[key] {
			if !kept(l.to) {
				continue
			}
			note(l)
			child := g.nodes[l.to].ref
			if !slices.Contains(result.Graph[n.ref.Module], child.Module) {
				result.Graph[n.ref.Module] = append(result.Graph[n.ref.Module], child.Module)
			}
			if !slices.Contains(result.VersionedGraph[key], child) {
				result.VersionedGraph[key] = append(result.VersionedGraph[key], child)
			}
		}
	}
	for _, l := range g.declared {
		if kept(l.to) {
			note(l)
			result.DirectDependencies = addSorted(result.DirectDependencies, g.nodes[l.to].ref.Module)
		}
	}
	for _, key := range keys {
		n := g.nodes[key]
		markers := slices.Clone(n.markers)
		if len(markers) == 0 && !unconditional[key] {
			markers = incoming[key]
		}
		result.Dependencies = append(result.Dependencies, Dependency{
			Module:  n.ref.Module,
			Version: n.ref.Version,
			Dir:     n.dir,
			Files:   n.files,
			Markers: markers,
			Extras:  n.extras,
		})
		if _, ok := result.Graph[n.ref.Module]; !ok && g.directKnown {
			result.Graph[n.ref.Module] = []string{}
		}
	}
	for _, children := range result.Graph {
		sort.Strings(children)
	}
	for _, children := range result.VersionedGraph {
		sort.Slice(children, func(i, j int) bool { return children[i].Key() < children[j].Key() })
	}
	return result
}
