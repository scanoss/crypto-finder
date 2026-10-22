// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"context"
	"os"
	"path/filepath"

	packageurl "github.com/package-url/packageurl-go"
	"github.com/rs/zerolog/log"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/lockfile"
	"github.com/scanoss/scanoss.go/pkg/dependencies/resolve/toolchain"

	"github.com/scanoss/crypto-finder/pkg/purl"
)

// graphInput is one file a resolution root directory may hold, and how the
// shared resolver reads it into a graph.
type graphInput struct {
	name string
	read func(ctx context.Context, dir, name string) (resolve.Graph, error)
}

func readLockfile(_ context.Context, dir, name string) (resolve.Graph, error) {
	return lockfile.ParseFS(os.DirFS(dir), name, lockfile.DefaultLimits())
}

func readToolchain(ctx context.Context, dir, name string) (resolve.Graph, error) {
	return toolchain.Resolve(ctx, dir, name, toolchain.Options{})
}

// graphInputs lists, per ecosystem, the files the shared resolver reads in a
// resolution root directory.
var graphInputs = map[string][]graphInput{
	"go":   {{"go.mod", readToolchain}},
	"java": {{"pom.xml", readToolchain}, {"gradle.lockfile", readLockfile}},
	"node": {
		{"package-lock.json", readLockfile},
		{"npm-shrinkwrap.json", readLockfile},
		{"yarn.lock", readLockfile},
		{"pnpm-lock.yaml", readLockfile},
	},
	"rust":   {{"Cargo.lock", readLockfile}},
	"python": {{"poetry.lock", readLockfile}, {"uv.lock", readLockfile}, {"Pipfile.lock", readLockfile}},
}

// SharedGraphs builds the dependency graphs of dirs with scanoss.go's
// resolver, the one SCANOSS's other tools derive dependency relationships
// from. It reads each of the ecosystem's inputs that sits directly in a dir.
// It never fails: a file the resolver cannot read yields no graph or an
// unknown root, which ResolvedPaths does not use.
func SharedGraphs(ctx context.Context, dirs []string, ecosystem string) []resolve.Graph {
	var graphs []resolve.Graph
	for _, dir := range dirs {
		for _, input := range graphInputs[ecosystem] {
			info, err := os.Stat(filepath.Join(dir, input.name))
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			graph, err := input.read(ctx, dir, input.name)
			if err != nil {
				log.Debug().Err(err).Str("dir", dir).Str("file", input.name).Msg("Shared dependency resolver could not read the file")
				continue
			}
			for i := range graph.Roots {
				root := &graph.Roots[i]
				log.Debug().
					Str("dir", dir).
					Str("manifest", root.Manifest).
					Str("status", string(root.Status)).
					Str("reason", string(root.Reason)).
					Msg("Shared dependency graph root")
			}
			graphs = append(graphs, graph)
		}
	}
	return graphs
}

// applicationNode stands for the project in the shared graph adjacency. Module
// keys never hold a NUL byte, so it cannot collide with one.
const applicationNode = "\x00application"

// ResolvedPaths returns the dependency paths of result, keyed like Paths,
// derived from the shared graphs. A module the usable shared graphs do not
// know at all takes its Paths entry instead; one they know but do not connect
// to the application has no path. With no usable root, it is Paths.
//
// A root is usable unless it is unknown or knows its members but not its
// edges (edges_unknown). The application reaches each root's direct members.
// A local node is the project's own package and joins the application, unless
// result resolves it as a dependency (a Go directory replace, say), which
// keeps it on the paths. parsed is read as Paths reads it: by module@version,
// or by module for a module the shared graphs hold at one version.
func ResolvedPaths(graphs []resolve.Graph, result *ResolveResult, ecosystem string, parsed map[string]bool) map[string]Path {
	legacy := Paths(result, parsed)
	shared := newSharedAdjacency(graphs, result, ecosystem)
	if !shared.usable {
		return legacy
	}
	paths := shared.paths(parsed)
	for key, path := range legacy {
		if len(path.Steps) == 0 || shared.known[path.Steps[len(path.Steps)-1].Module] {
			continue
		}
		if _, ok := paths[key]; !ok {
			paths[key] = path
		}
	}
	return paths
}

// sharedAdjacency is the usable roots of the shared graphs merged into one
// graph over module@version keys, rooted at applicationNode.
type sharedAdjacency struct {
	usable bool
	graph  map[string][]string
	refs   map[string]Ref
	// known holds every module a usable root lists as a member.
	known map[string]bool
	// versions counts the distinct versions of each known module.
	versions map[string]int
}

func newSharedAdjacency(graphs []resolve.Graph, result *ResolveResult, ecosystem string) sharedAdjacency {
	adjacency := sharedAdjacency{
		graph:    make(map[string][]string),
		refs:     make(map[string]Ref),
		known:    make(map[string]bool),
		versions: make(map[string]int),
	}
	names := dependencyNames(result, ecosystem)
	for _, graph := range graphs {
		keys := make(map[resolve.NodeID]string, len(graph.Nodes))
		for _, node := range graph.Nodes {
			if key, ref, ok := nodeKey(node, names); ok {
				keys[node.ID] = key
				if key != applicationNode {
					adjacency.refs[key] = ref
				}
			}
		}
		for i := range graph.Roots {
			adjacency.addRoot(&graph.Roots[i], keys)
		}
	}
	for _, ref := range adjacency.refs {
		if adjacency.known[ref.Module] {
			adjacency.versions[ref.Module]++
		}
	}
	return adjacency
}

func (s *sharedAdjacency) addRoot(root *resolve.Root, keys map[resolve.NodeID]string) {
	if root.Status == resolve.StatusUnknown || root.Reason == resolve.ReasonEdgesUnknown {
		return
	}
	s.usable = true
	for _, member := range root.Members {
		key, ok := keys[member.ID]
		if !ok || key == applicationNode {
			continue
		}
		s.known[s.refs[key].Module] = true
		if member.Direct {
			s.graph[applicationNode] = append(s.graph[applicationNode], key)
		}
	}
	for _, edge := range root.Edges {
		from, fromOK := keys[edge.From]
		to, toOK := keys[edge.To]
		if fromOK && toOK {
			s.graph[from] = append(s.graph[from], to)
		}
	}
}

func (s sharedAdjacency) paths(parsed map[string]bool) map[string]Path {
	through := make(map[string]bool, len(s.refs))
	for key, ref := range s.refs {
		through[key] = parsed[key] || (s.versions[ref.Module] == 1 && parsed[ref.Module])
	}
	application := map[string]bool{applicationNode: true}
	viaSource := shortestRoutes(s.graph, application, nil, through)
	anyRoute := shortestRoutes(s.graph, application, nil, nil)
	steps := func(route []string) []PathStep {
		out := make([]PathStep, len(route))
		for i, key := range route {
			out[i] = PathStep{Module: s.refs[key].Module, Version: s.refs[key].Version, WithoutSource: !through[key]}
		}
		return out
	}
	paths := make(map[string]Path, len(anyRoute))
	for key, route := range anyRoute {
		path := Path{Steps: steps(route), WithoutSource: true}
		if clean, ok := viaSource[key]; ok {
			path = Path{Steps: steps(clean)}
		}
		paths[key] = path
		if module := s.refs[key].Module; s.versions[module] == 1 {
			paths[module] = path
		}
	}
	return paths
}

// dependencyNames maps the package URL identity of each resolved dependency
// to its module, so a shared graph node takes crypto-finder's spelling of the
// name (pip names, for one, are not normalized here).
func dependencyNames(result *ResolveResult, ecosystem string) map[string]string {
	names := make(map[string]string)
	if result == nil {
		return names
	}
	for _, dep := range result.Dependencies {
		if identity, ok := purl.Identity(purl.Dependency(ecosystem, dep.Module, "")); ok {
			names[identity] = dep.Module
		}
	}
	return names
}

// nodeKey names a shared graph node: its module@version key, or
// applicationNode for a local node that is not a resolved dependency. It
// reports false for a node it cannot name.
func nodeKey(node resolve.Node, names map[string]string) (string, Ref, bool) {
	module := ""
	if identity, ok := purl.Identity(node.PURL); ok {
		module = names[identity]
	}
	if module == "" && node.Local {
		return applicationNode, Ref{}, true
	}
	if module == "" {
		module = moduleFromPURL(node.PURL)
	}
	if module == "" {
		return "", Ref{}, false
	}
	ref := Ref{Module: module, Version: node.Version}
	return ref.Key(), ref, true
}

// moduleFromPURL spells a package URL's name the way crypto-finder names a
// module of its ecosystem.
func moduleFromPURL(raw string) string {
	p, err := packageurl.FromString(raw)
	if err != nil || p.Name == "" {
		return ""
	}
	if p.Namespace == "" {
		return p.Name
	}
	switch p.Type {
	case packageurl.TypeMaven:
		return p.Namespace + ":" + p.Name
	case packageurl.TypeGolang, packageurl.TypeNPM:
		return p.Namespace + "/" + p.Name
	}
	return p.Name
}
