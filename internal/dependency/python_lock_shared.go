// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
	"github.com/pelletier/go-toml/v2"
	"github.com/scanoss/reach/purl"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"

	"github.com/scanoss/crypto-finder/internal/utils"
)

// uv.lock, poetry.lock and Pipfile.lock are read by scanoss.go's resolver,
// which SharedGraphs also reads for the dependency paths: it gives the
// pinned members, the requirement edges (none for Pipfile.lock), which
// members are direct and which only dev dependencies reach. It takes every
// marker branch and every extra already (the owner's union policy) but drops
// the markers and extras themselves, so pyLockNotes reads them from the same
// file.

// pyLockNote is a requirement as a lock writes it, for its marker and extras.
type pyLockNote struct {
	name, version, marker string
	extras                []string
}

// pyLockNotes is what the scanoss.go graph leaves out of a lock.
type pyLockNotes struct {
	// requires maps a package's name@version to its requirements; the
	// application's own (uv's editable or virtual project) are under "".
	requires map[string][]pyLockNote
	// markers and extras are per name@version: the entry's own markers and
	// the extras the lock resolves for it.
	markers, extras map[string][]string
	// devOnly names packages a lock lists for development only
	// (Pipfile.lock's develop section), which scanoss.go cannot tell apart
	// without edges.
	devOnly map[string]bool
}

func newPyLockNotes() *pyLockNotes {
	return &pyLockNotes{
		requires: map[string][]pyLockNote{},
		markers:  map[string][]string{},
		extras:   map[string][]string{},
		devOnly:  map[string]bool{},
	}
}

// readSharedPyLock reads dir/name with scanoss.go's resolver into a pyGraph,
// with the markers and extras of the same file. A file the resolver cannot
// read is an error: a lock that exists decides the closure.
func readSharedPyLock(ctx context.Context, dir, name string) (*pyGraph, error) {
	graph, err := readLockfile(ctx, dir, name)
	if err != nil {
		return nil, err
	}
	for _, root := range graph.Roots {
		if root.Status == resolve.StatusUnknown {
			return nil, fmt.Errorf("%s: %s %s", name, root.Reason, root.Detail)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	notes := newPyLockNotes()
	switch name {
	case "uv.lock":
		err = notes.readUv(data)
	case "poetry.lock":
		err = notes.readPoetry(data)
	case "Pipfile.lock":
		err = notes.readPipfile(data)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	notes.readApplication(dir)
	return sharedPyGraph(name, graph, notes), nil
}

// sharedPyGraph is the scanoss.go graph as a pyGraph: the members of every
// root (a uv workspace has several), dev when every root that holds one
// reaches it only through dev dependencies, direct when a root declares it as
// a runtime dependency.
func sharedPyGraph(source string, graph resolve.Graph, notes *pyLockNotes) *pyGraph { //nolint:gocognit,gocyclo // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	g := newPyGraph(source)
	keys := map[resolve.NodeID]string{}
	for _, node := range graph.Nodes {
		p, err := packageurl.FromString(node.PURL)
		if err != nil || p.Name == "" || node.Local {
			continue
		}
		n := g.add(purl.PyPIName(p.Name), node.Version)
		keys[node.ID] = n.ref.Key()
		n.markers = addSorted(n.markers, notes.markers[n.ref.Key()]...)
		n.extras = addSorted(n.extras, notes.extras[n.ref.Key()]...)
	}
	runtime := map[string]bool{}
	for _, root := range graph.Roots {
		for _, m := range root.Members {
			if key, ok := keys[m.ID]; ok && !m.Dev {
				runtime[key] = true
			}
		}
	}
	for key, n := range g.nodes {
		n.dev = !runtime[key] || notes.devOnly[n.ref.Module]
	}
	for _, root := range graph.Roots {
		if root.Reason != resolve.ReasonManifestMissing && root.Reason != resolve.ReasonManifestMalformed {
			g.directKnown = true
		}
		for _, m := range root.Members {
			if key, ok := keys[m.ID]; ok && m.Direct && !m.Dev {
				for _, marker := range notes.markersFor("", g.nodes[key]) {
					g.declare(key, marker)
				}
			}
		}
		for _, e := range root.Edges {
			from, fromOK := keys[e.From]
			to, toOK := keys[e.To]
			if fromOK && toOK {
				for _, marker := range notes.markersFor(from, g.nodes[to]) {
					g.link(from, to, marker)
				}
			}
		}
	}
	return g
}

// markersFor returns the markers of from's requirements on to, and enables
// their extras on to. With no note, the requirement is unconditional.
func (n *pyLockNotes) markersFor(from string, to *pyNode) []string {
	var markers []string
	found := false
	for _, note := range n.requires[from] {
		if note.name != to.ref.Module || (note.version != "" && note.version != to.ref.Version) {
			continue
		}
		found = true
		markers = append(markers, note.marker)
		to.extras = addSorted(to.extras, note.extras...)
	}
	if !found {
		return []string{""}
	}
	return markers
}

func (n *pyLockNotes) note(from string, notes ...pyLockNote) {
	n.requires[from] = append(n.requires[from], notes...)
}

// readApplication notes the application's requirements as its manifests
// declare them (pyproject.toml, Pipfile), for the markers and extras of the
// direct dependencies. uv's lock already noted its project's.
func (n *pyLockNotes) readApplication(dir string) {
	if _, ok := n.requires[""]; ok {
		return
	}
	for _, d := range declaredPyRequirements(dir) {
		n.note("", pyLockNote{name: d.req.Name, marker: d.req.Marker, extras: d.req.Extras})
	}
}

type uvLockDep struct {
	Name    string   `toml:"name"`
	Version string   `toml:"version"`
	Marker  string   `toml:"marker"`
	Extra   []string `toml:"extra"`
}

func (d uvLockDep) note(extra string) pyLockNote {
	extras := make([]string, 0, len(d.Extra))
	for _, e := range d.Extra {
		extras = append(extras, purl.PyPIName(e))
	}
	return pyLockNote{name: purl.PyPIName(d.Name), version: d.Version, marker: pyExtraMarker(extra, d.Marker), extras: extras}
}

// readUv notes uv.lock's markers: per dependency (marker, extra), per
// optional dependency (as extra == "<name>"), and per package
// (resolution-markers, written when uv locks a name at several versions).
// An editable or virtual package is the project or a workspace member:
// its requirements are the application's.
func (n *pyLockNotes) readUv(data []byte) error {
	var lock struct {
		Package []struct {
			Name              string   `toml:"name"`
			Version           string   `toml:"version"`
			ResolutionMarkers []string `toml:"resolution-markers"`
			Source            struct {
				Editable string `toml:"editable"`
				Virtual  string `toml:"virtual"`
			} `toml:"source"`
			Dependencies         []uvLockDep            `toml:"dependencies"`
			OptionalDependencies map[string][]uvLockDep `toml:"optional-dependencies"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		return err
	}
	for _, p := range lock.Package {
		key := Ref{Module: purl.PyPIName(p.Name), Version: p.Version}.Key()
		if p.Source.Editable != "" || p.Source.Virtual != "" {
			key = ""
		}
		for _, d := range p.Dependencies {
			n.note(key, d.note(""))
		}
		for _, extra := range slices.Sorted(maps.Keys(p.OptionalDependencies)) {
			if key != "" {
				n.extras[key] = addSorted(n.extras[key], purl.PyPIName(extra))
			}
			for _, d := range p.OptionalDependencies[extra] {
				n.note(key, d.note(extra))
			}
		}
		if key != "" {
			n.markers[key] = addSorted(n.markers[key], p.ResolutionMarkers...)
		}
	}
	return nil
}

// readPoetry notes poetry.lock's markers: a dependency is a version string,
// a table (version, markers, extras), or an array of tables for different
// markers; a package can carry its own markers (lock format 2.1).
func (n *pyLockNotes) readPoetry(data []byte) error {
	var lock struct {
		Package []struct {
			Name         string         `toml:"name"`
			Version      string         `toml:"version"`
			Markers      any            `toml:"markers"`
			Dependencies map[string]any `toml:"dependencies"`
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		return err
	}
	for _, p := range lock.Package {
		key := Ref{Module: purl.PyPIName(p.Name), Version: p.Version}.Key()
		if marker, ok := p.Markers.(string); ok {
			n.markers[key] = addSorted(n.markers[key], marker)
		}
		for _, dep := range slices.Sorted(maps.Keys(p.Dependencies)) {
			for _, t := range poetryDependencyTables(p.Dependencies[dep]) {
				marker := utils.AsOr[string](t["markers"])
				n.note(key, pyLockNote{name: purl.PyPIName(dep), marker: marker, extras: poetryExtras(t["extras"])})
			}
		}
	}
	return nil
}

// poetryDependencyTables returns a Poetry dependency value as tables: a
// version string is a table with no markers.
func poetryDependencyTables(v any) []map[string]any {
	switch v := v.(type) {
	case map[string]any:
		return []map[string]any{v}
	case []any:
		var out []map[string]any
		for _, item := range v {
			if t, ok := item.(map[string]any); ok {
				out = append(out, t)
			}
		}
		return out
	}
	return []map[string]any{{}}
}

func poetryExtras(v any) []string {
	items := utils.AsOr[[]any](v)
	var out []string
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = addSorted(out, purl.PyPIName(s))
		}
	}
	return out
}

// readPipfile notes Pipfile.lock's per-package markers and extras, and the
// packages only its develop section lists.
func (n *pyLockNotes) readPipfile(data []byte) error {
	type entry struct {
		Version string   `json:"version"`
		Markers string   `json:"markers"`
		Extras  []string `json:"extras"`
	}
	var lock struct {
		Default map[string]entry `json:"default"`
		Develop map[string]entry `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return err
	}
	runtime := map[string]bool{}
	for name, e := range lock.Default {
		runtime[purl.PyPIName(name)] = true
		key := Ref{Module: purl.PyPIName(name), Version: strings.TrimLeft(e.Version, "=")}.Key()
		n.markers[key] = addSorted(n.markers[key], e.Markers)
		for _, extra := range e.Extras {
			n.extras[key] = addSorted(n.extras[key], purl.PyPIName(extra))
		}
	}
	for name := range lock.Develop {
		if !runtime[purl.PyPIName(name)] {
			n.devOnly[purl.PyPIName(name)] = true
		}
	}
	return nil
}
