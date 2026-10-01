// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import "sort"

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
// The application is the root module and the workspace members. When the
// graph holds neither, its nodes nothing depends on are the application,
// except those that are themselves resolved dependencies, which are the
// direct dependencies. A dependency the graph does not connect to the
// application has no entry. Returns nil when the result has no graph.
func Paths(result *ResolveResult, parsed map[string]bool) map[string]Path {
	if result == nil || len(result.Graph) == 0 {
		return nil
	}
	application, direct := graphApplication(result)
	viaSource := shortestRoutes(result.Graph, application, direct, parsed)
	anyRoute := shortestRoutes(result.Graph, application, direct, nil)
	paths := make(map[string]Path, len(anyRoute))
	for module, route := range anyRoute {
		if clean, ok := viaSource[module]; ok {
			paths[module] = Path{Steps: pathSteps(clean, parsed)}
			continue
		}
		paths[module] = Path{Steps: pathSteps(route, parsed), WithoutSource: true}
	}
	return paths
}

func pathSteps(route []string, parsed map[string]bool) []PathStep {
	steps := make([]PathStep, len(route))
	for i, module := range route {
		steps[i] = PathStep{Module: module, WithoutSource: !parsed[module]}
	}
	return steps
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
