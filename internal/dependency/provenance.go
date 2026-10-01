// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"sort"
	"strings"
)

// Path is how the application reaches one dependency in the resolved
// dependency graph.
type Path struct {
	// Steps runs from a direct dependency of the application to the
	// dependency itself, both included. The application is not listed. A
	// direct dependency has a one-step path.
	Steps []PathStep
	// WithoutSource is set when every route from the application to the
	// dependency goes through a dependency that joined the call graph without
	// source code (types only, or not at all). Its code holds no call edges,
	// so no call chain can cross it.
	WithoutSource bool
}

// PathStep is one dependency on a Path.
type PathStep struct {
	Module string
	// Version is the step's resolved version when the path was computed on
	// versioned nodes (see Paths); empty otherwise.
	Version string
	// WithoutSource marks a dependency whose source was not parsed into the
	// call graph.
	WithoutSource bool
}

// Paths returns, per dependency module of the resolved graph, the shortest
// route from the application to it. A route through dependencies whose source
// was parsed (parsed[module]) is preferred over a shorter one that is not;
// when there is none, the shortest route is returned with WithoutSource set.
// Ties break on module name, so the result is deterministic.
//
// The graph names a dependency by module, but npm can resolve one module at
// two versions, and each copy has its own dependents and dependencies. A path
// computed by module would then name a route that exists for the other copy, or
// call a dependency direct that only a nested copy reaches. When the result
// resolves some module at more than one version:
//
//   - with a VersionedGraph, the whole computation runs on module@version nodes
//     and the paths are keyed by that coordinate (Ref.Key), parsed read the same
//     way;
//   - without one, the modules with several versions get no path, and neither
//     does a dependency whose route crosses one, since the graph cannot say which
//     copy the route runs through.
//
// Otherwise paths are keyed by module and PathStep.Version is empty.
//
// The application is the root module and the workspace members. When the
// graph holds neither, its nodes nothing depends on are the application,
// except those that are themselves resolved dependencies, which are the
// direct dependencies. A dependency the graph does not connect to the
// application has no entry. Returns nil when the result has no graph.
func Paths(result *ResolveResult, parsed map[string]bool) map[string]Path {
	if result == nil || len(result.Graph) == 0 {
		return nil
	}
	ambiguous := multiVersionModules(result.Dependencies)
	if len(ambiguous) > 0 && len(result.VersionedGraph) > 0 {
		return versionedPaths(result, parsed)
	}
	application, direct := graphApplication(result)
	viaSource := shortestRoutes(result.Graph, application, direct, parsed)
	anyRoute := shortestRoutes(result.Graph, application, direct, nil)
	paths := make(map[string]Path, len(anyRoute))
	for module, route := range anyRoute {
		if crossesAny(module, route, ambiguous) {
			continue
		}
		if clean, ok := viaSource[module]; ok {
			paths[module] = Path{Steps: pathSteps(clean, parsed)}
			continue
		}
		paths[module] = Path{Steps: pathSteps(route, parsed), WithoutSource: true}
	}
	return paths
}

// multiVersionModules returns the modules the result resolves at more than one
// version.
func multiVersionModules(deps []Dependency) map[string]bool {
	versions := make(map[string]string, len(deps))
	multiple := make(map[string]bool)
	for _, dep := range deps {
		if seen, ok := versions[dep.Module]; ok && seen != dep.Version {
			multiple[dep.Module] = true
		}
		versions[dep.Module] = dep.Version
	}
	return multiple
}

// crossesAny reports whether module or a step of its route is in set.
func crossesAny(module string, route []string, set map[string]bool) bool {
	if set[module] {
		return true
	}
	for _, step := range route {
		if set[step] {
			return true
		}
	}
	return false
}

func pathSteps(route []string, parsed map[string]bool) []PathStep {
	steps := make([]PathStep, len(route))
	for i, module := range route {
		steps[i] = PathStep{Module: module, WithoutSource: !parsed[module]}
	}
	return steps
}

// versionedPaths is Paths on module@version nodes, for a result that resolves
// a module at several versions. parsed is read by the same coordinate.
func versionedPaths(result *ResolveResult, parsed map[string]bool) map[string]Path {
	graph := make(map[string][]string, len(result.VersionedGraph))
	refs := make(map[string]Ref)
	for _, dep := range result.Dependencies {
		ref := Ref{Module: dep.Module, Version: dep.Version}
		refs[ref.Key()] = ref
	}
	for parent, children := range result.VersionedGraph {
		for _, child := range children {
			graph[parent] = append(graph[parent], child.Key())
			if _, known := refs[child.Key()]; !known {
				refs[child.Key()] = child
			}
		}
	}
	application, direct := versionedApplication(result, graph)
	through := make(map[string]bool, len(refs))
	for key := range refs {
		through[key] = parsed[key]
	}
	viaSource := shortestRoutes(graph, application, direct, through)
	anyRoute := shortestRoutes(graph, application, direct, nil)
	steps := func(route []string) []PathStep {
		out := make([]PathStep, len(route))
		for i, key := range route {
			out[i] = PathStep{Module: refs[key].Module, Version: refs[key].Version, WithoutSource: !through[key]}
		}
		return out
	}
	paths := make(map[string]Path, len(anyRoute))
	for key, route := range anyRoute {
		if clean, ok := viaSource[key]; ok {
			paths[key] = Path{Steps: steps(clean)}
			continue
		}
		paths[key] = Path{Steps: steps(route), WithoutSource: true}
	}
	return paths
}

// withoutVersion strips a trailing @version from a node key. A scoped npm
// module's leading @ is not a version separator.
func withoutVersion(key string) string {
	if i := strings.LastIndex(key, "@"); i > 0 {
		return key[:i]
	}
	return key
}

// versionedApplication is graphApplication on module@version nodes: the nodes
// of the root module and the workspace members, or, when the graph names
// neither, the nodes nothing depends on, those that are resolved dependencies
// being the direct dependencies.
func versionedApplication(result *ResolveResult, graph map[string][]string) (application map[string]bool, direct []string) {
	names := make(map[string]bool)
	if result.RootModule != "" {
		names[result.RootModule] = true
	}
	for _, member := range result.WorkspaceMembers {
		if member.Name != "" {
			names[member.Name] = true
		}
	}
	application = make(map[string]bool)
	for parent := range graph {
		if names[parent] || names[withoutVersion(parent)] {
			application[parent] = true
		}
	}
	if len(application) > 0 {
		return application, nil
	}
	dependencies := make(map[string]bool, len(result.Dependencies))
	for _, dep := range result.Dependencies {
		dependencies[Ref{Module: dep.Module, Version: dep.Version}.Key()] = true
	}
	children := make(map[string]bool)
	for _, values := range graph {
		for _, child := range values {
			children[child] = true
		}
	}
	for parent := range graph {
		switch {
		case children[parent]:
		case dependencies[parent]:
			direct = append(direct, parent)
		default:
			application[parent] = true
		}
	}
	sort.Strings(direct)
	return application, direct
}

// graphApplication splits the graph's starting nodes into the application,
// whose children are the direct dependencies, and direct dependencies found
// as graph sources when the graph does not name the application.
func graphApplication(result *ResolveResult) (application map[string]bool, direct []string) {
	application = make(map[string]bool)
	if result.RootModule != "" {
		application[result.RootModule] = true
	}
	for _, member := range result.WorkspaceMembers {
		if member.Name != "" {
			application[member.Name] = true
		}
	}
	for module := range application {
		if _, ok := result.Graph[module]; ok {
			return application, nil
		}
	}
	dependencies := make(map[string]bool, len(result.Dependencies))
	for _, dep := range result.Dependencies {
		dependencies[dep.Module] = true
	}
	children := make(map[string]bool)
	for _, values := range result.Graph {
		for _, child := range values {
			children[child] = true
		}
	}
	for module := range result.Graph {
		switch {
		case children[module]:
		case dependencies[module]:
			direct = append(direct, module)
		default:
			application[module] = true
		}
	}
	sort.Strings(direct)
	return application, direct
}

// shortestRoutes is a breadth-first walk from the application. With through
// set, it never continues past a module through does not hold: such a module
// is reached, but nothing is reached through it.
func shortestRoutes(graph map[string][]string, application map[string]bool, direct []string, through map[string]bool) map[string][]string {
	routes := make(map[string][]string)
	var queue []string
	visit := func(module string, parent []string) {
		if application[module] {
			return
		}
		if _, seen := routes[module]; seen {
			return
		}
		route := make([]string, len(parent)+1)
		copy(route, parent)
		route[len(parent)] = module
		routes[module] = route
		queue = append(queue, module)
	}
	for _, module := range sortedModules(application) {
		for _, child := range sortedCopy(graph[module]) {
			visit(child, nil)
		}
	}
	for _, module := range direct {
		visit(module, nil)
	}
	for len(queue) > 0 {
		module := queue[0]
		queue = queue[1:]
		if through != nil && !through[module] {
			continue
		}
		for _, child := range sortedCopy(graph[module]) {
			visit(child, routes[module])
		}
	}
	return routes
}

func sortedModules(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
