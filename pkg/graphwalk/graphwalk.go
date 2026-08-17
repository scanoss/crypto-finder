// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package graphwalk holds the backward reachability traversal shared by
// crypto-finder's two reachability paths: the live exporter, which walks the
// in-memory call graph built from source, and the stitcher, which walks an
// adjacency assembled from stored graph fragments.
//
// Those two carry different node identities — a parsed FunctionID on one side, a
// (component, signature) pair on the other — and pkg/graphfrag is deliberately
// kept from importing the scanner, so historically each side grew its own copy of
// the same walk. The copies then had to be kept in step by hand: both sort
// callers identically for no reason other than to collapse re-convergent paths to
// the same representative, and a parity package plus a diamond fixture exist to
// catch them drifting apart.
//
// This package removes the reason for the copies. The traversal is generic over
// the node type; each caller supplies its own adjacency and its own notion of
// where a chain ends, and materializes the result into its own frame type. What
// stays identical — visit order, depth accounting, component collapsing, route
// counting — is written once.
//
// The four operations, in the order they are used:
//
//	Reach     which nodes reach the target, and how far away each one is
//	Condense  collapse cycles so the route set is finite (Tarjan)
//	Count     how many routes there are, without building any
//	Routes    build up to a budget of them
//
// Counting before building is the point: a caller that truncates can then say how
// much it left out instead of dropping the remainder silently.
package graphwalk

import "sort"

// Options describes the graph and where a walk should stop.
type Options[T comparable] struct {
	// Callers returns the nodes that call n. The walk never mutates the result.
	Callers func(n T) []T

	// Less orders nodes. Every iteration that could otherwise depend on Go map
	// ordering is sorted through it, so results are reproducible and — where two
	// callers walk equivalent graphs — identical between them.
	Less func(a, b T) bool

	// IsBoundary reports whether a chain ends at n. A boundary node is collected
	// as a terminal and is NOT expanded further: reaching it answers the
	// question, and its own callers belong to a different question. The target
	// is never treated as a boundary.
	IsBoundary func(n T) bool

	// RootIsTerminal makes a node with no callers a terminal. Scanning a library
	// on its own wants this — a graph root is the library's public surface. A
	// scan that knows which code is the consumer's does not: a root that is not
	// consumer code means nothing consumer-side reaches the target.
	RootIsTerminal bool

	// MaxDepth bounds the number of frames a route may have (the target counts
	// as one). Zero means unbounded.
	MaxDepth int
}

// Reachable is the set of nodes that reach a target.
type Reachable[T comparable] struct {
	// Target is the node the walk started from.
	Target T
	// Depth is the minimum number of calls from each node to the target; the
	// target itself is 0. Membership doubles as the visited set.
	Depth map[T]int
	// Terminal marks the nodes where a chain ends.
	Terminal map[T]bool
	// Callers is the adjacency induced on Depth's keys. Terminals carry no
	// entry: a chain stops there.
	Callers map[T][]T
}

// Reach walks callers breadth-first from target and records every node that
// reaches it with that node's minimum distance.
//
// Each node is visited once, which makes this O(V+E). That costs nothing here
// because the answer is a SET: re-convergence loses paths, not members. A walk
// that collected paths under the same rule would lose the second branch into any
// shared caller — which is exactly the defect this package exists to avoid
// repeating.
func Reach[T comparable](target T, opts Options[T]) Reachable[T] {
	out := Reachable[T]{
		Target:   target,
		Depth:    map[T]int{target: 0},
		Terminal: map[T]bool{},
		Callers:  map[T][]T{},
	}

	queue := []T{target}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		depth := out.Depth[current]

		if current != target && opts.IsBoundary != nil && opts.IsBoundary(current) {
			out.Terminal[current] = true
			continue
		}

		callers := opts.Callers(current)
		if len(callers) == 0 {
			if opts.RootIsTerminal && current != target {
				out.Terminal[current] = true
			}
			continue
		}

		// depth counts calls; a route's frame count is depth+1. Do not grow past
		// MaxDepth frames.
		if opts.MaxDepth > 0 && depth+2 > opts.MaxDepth {
			continue
		}

		sorted := append([]T(nil), callers...)
		sortNodes(sorted, opts.Less)
		for _, caller := range sorted {
			out.Callers[current] = append(out.Callers[current], caller)
			if _, seen := out.Depth[caller]; seen {
				continue
			}
			out.Depth[caller] = depth + 1
			queue = append(queue, caller)
		}
	}

	// Drop edges to nodes the walk never admitted, so Callers is exactly the
	// adjacency induced on Depth.
	for node, callers := range out.Callers {
		kept := callers[:0]
		for _, caller := range callers {
			if _, ok := out.Depth[caller]; ok {
				kept = append(kept, caller)
			}
		}
		out.Callers[node] = kept
	}
	return out
}

// Condensed is the reachable subgraph with every cycle collapsed to one node.
type Condensed[T comparable] struct {
	// Comp maps a node to its component id; Members is the inverse, each list
	// sorted through Options.Less.
	Comp    map[T]int
	Members [][]T
	// DAG is the component adjacency. Acyclic by construction: a cycle between
	// two components would mean they reach each other, which makes them one.
	DAG map[int][]int
	// Edge records one representative concrete edge per component edge, so a
	// component-level route can be expanded back to real nodes.
	Edge map[ComponentEdge][2]T
}

// ComponentEdge identifies an edge of the condensed DAG.
type ComponentEdge struct {
	From, To int
}

// Condense groups the reachable subgraph into strongly connected components and
// builds the DAG over them.
//
// Cycles are why an uncondensed route set has no useful bound: a cluster of
// mutually recursive functions can be traversed in every internal order, and
// every order counts as a distinct route while describing the same trip. Whether
// two nodes belong to the same component is a property of the graph, not of the
// traversal, so callers walking equivalent graphs condense identically without
// having to agree on anything first.
func Condense[T comparable](r Reachable[T], less func(a, b T) bool) Condensed[T] {
	out := Condensed[T]{
		Comp: make(map[T]int, len(r.Depth)),
		DAG:  map[int][]int{},
		Edge: map[ComponentEdge][2]T{},
	}

	nodes := make([]T, 0, len(r.Depth))
	for node := range r.Depth {
		nodes = append(nodes, node)
	}
	sortNodes(nodes, less)

	tarjan(nodes, r.Callers, less, &out)

	seen := map[ComponentEdge]bool{}
	for _, node := range nodes {
		for _, caller := range r.Callers[node] {
			edge := ComponentEdge{From: out.Comp[node], To: out.Comp[caller]}
			if edge.From == edge.To || seen[edge] {
				continue
			}
			seen[edge] = true
			out.DAG[edge.From] = append(out.DAG[edge.From], edge.To)
			// nodes is sorted and Reach sorted each caller list, so the first
			// concrete edge seen for a component edge is a deterministic
			// representative.
			out.Edge[edge] = [2]T{node, caller}
		}
	}
	for from := range out.DAG {
		sort.Ints(out.DAG[from])
	}
	return out
}

// tarjan assigns every node a component id, iteratively so depth cannot overflow
// the goroutine stack.
//
// index is the order a node was discovered; low is the oldest node it can climb
// back to. When they are equal nothing below the node reaches above it, so it is
// the first-discovered member of its component and everything stacked on top of
// it belongs there too.
func tarjan[T comparable](nodes []T, callers map[T][]T, less func(a, b T) bool, out *Condensed[T]) {
	index := make(map[T]int, len(nodes))
	low := make(map[T]int, len(nodes))
	onStack := make(map[T]bool, len(nodes))

	var stack []T
	counter := 0

	type frame struct {
		node T
		next int
	}

	for _, root := range nodes {
		if _, visited := index[root]; visited {
			continue
		}
		index[root] = counter
		low[root] = counter
		counter++
		stack = append(stack, root)
		onStack[root] = true

		work := []frame{{node: root}}
		for len(work) > 0 {
			top := &work[len(work)-1]
			v := top.node
			adj := callers[v]

			descended := false
			for top.next < len(adj) {
				w := adj[top.next]
				top.next++
				if _, visited := index[w]; !visited {
					index[w] = counter
					low[w] = counter
					counter++
					stack = append(stack, w)
					onStack[w] = true
					work = append(work, frame{node: w})
					descended = true
					break
				}
				// Only a node still on the stack is part of an open cycle. One
				// already assigned to a component must be ignored, or v would be
				// folded into a component it merely points at.
				if onStack[w] && index[w] < low[v] {
					low[v] = index[w]
				}
			}
			if descended {
				continue
			}

			if low[v] == index[v] {
				id := len(out.Members)
				var group []T
				for {
					w := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[w] = false
					out.Comp[w] = id
					group = append(group, w)
					if w == v {
						break
					}
				}
				sortNodes(group, less)
				out.Members = append(out.Members, group)
			}

			work = work[:len(work)-1]
			if len(work) > 0 {
				parent := work[len(work)-1].node
				if low[v] < low[parent] {
					low[parent] = low[v]
				}
			}
		}
	}
}

// Count returns how many (component route, terminal) pairs lead from the target
// to a terminal, without building any of them.
//
// One pass in reverse topological order, so a caller always knows the exact total
// before deciding how many to build.
func Count[T comparable](r Reachable[T], c Condensed[T]) int {
	order := topoFromTarget(r, c)
	routes := make(map[int]int, len(order))
	for i := len(order) - 1; i >= 0; i-- {
		comp := order[i]
		n := 0
		for _, member := range c.Members[comp] {
			if r.Terminal[member] {
				n++
			}
		}
		for _, next := range c.DAG[comp] {
			n += routes[next]
		}
		routes[comp] = n
	}
	return routes[c.Comp[r.Target]]
}

// Routes builds up to max concrete routes, each ordered from the target outward
// to a terminal. A max of 0 means unbounded.
//
// Inside a component the shortest hop sequence is used: a component is a cycle,
// so every internal order describes the same trip through it, and the shortest is
// the readable representative. Condensed.Members keeps the full membership for a
// caller that wants to show what was collapsed.
func Routes[T comparable](r Reachable[T], c Condensed[T], max int) [][]T {
	var out [][]T
	start := c.Comp[r.Target]

	var walk func(route []int) bool
	walk = func(route []int) bool {
		current := route[len(route)-1]

		for _, member := range c.Members[current] {
			if !r.Terminal[member] {
				continue
			}
			if concrete, ok := expandRoute(r, c, route, member); ok {
				out = append(out, concrete)
				if max > 0 && len(out) >= max {
					return false
				}
			}
		}

		for _, next := range c.DAG[current] {
			// Copy: sibling branches must not share a backing array with the
			// route handed to a deeper call.
			extended := make([]int, len(route)+1)
			copy(extended, route)
			extended[len(route)] = next
			if !walk(extended) {
				return false
			}
		}
		return true
	}
	walk([]int{start})
	return out
}

// expandRoute turns a component route into concrete nodes, target first.
func expandRoute[T comparable](r Reachable[T], c Condensed[T], route []int, terminal T) ([]T, bool) {
	nodes := []T{r.Target}
	current := r.Target

	for i := 0; i+1 < len(route); i++ {
		rep, ok := c.Edge[ComponentEdge{From: route[i], To: route[i+1]}]
		if !ok {
			return nil, false
		}
		inside := withinComponent(r, c, current, rep[0], route[i])
		if inside == nil {
			return nil, false
		}
		nodes = append(nodes, inside...)
		nodes = append(nodes, rep[1])
		current = rep[1]
	}

	inside := withinComponent(r, c, current, terminal, route[len(route)-1])
	if inside == nil {
		return nil, false
	}
	return append(nodes, inside...), true
}

// withinComponent returns the hops after from up to and including to, using only
// edges inside the component. Empty (non-nil) when from == to; nil when no
// internal path exists.
func withinComponent[T comparable](r Reachable[T], c Condensed[T], from, to T, comp int) []T {
	if from == to {
		return []T{}
	}

	prev := map[T]T{}
	visited := map[T]bool{from: true}
	queue := []T{from}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, caller := range r.Callers[current] {
			if c.Comp[caller] != comp || visited[caller] {
				continue
			}
			visited[caller] = true
			prev[caller] = current
			if caller == to {
				var reversed []T
				for at := to; at != from; at = prev[at] {
					reversed = append(reversed, at)
				}
				for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
					reversed[i], reversed[j] = reversed[j], reversed[i]
				}
				return reversed
			}
			queue = append(queue, caller)
		}
	}
	return nil
}

// topoFromTarget returns the components reachable from the target's component in
// topological order.
func topoFromTarget[T comparable](r Reachable[T], c Condensed[T]) []int {
	start := c.Comp[r.Target]

	reachable := map[int]bool{start: true}
	queue := []int{start}
	for len(queue) > 0 {
		comp := queue[0]
		queue = queue[1:]
		for _, next := range c.DAG[comp] {
			if !reachable[next] {
				reachable[next] = true
				queue = append(queue, next)
			}
		}
	}

	indegree := make(map[int]int, len(reachable))
	for comp := range reachable {
		indegree[comp] += 0
		for _, next := range c.DAG[comp] {
			indegree[next]++
		}
	}

	ready := make([]int, 0, len(indegree))
	for comp, degree := range indegree {
		if degree == 0 {
			ready = append(ready, comp)
		}
	}
	sort.Ints(ready)

	order := make([]int, 0, len(indegree))
	for len(ready) > 0 {
		comp := ready[0]
		ready = ready[1:]
		order = append(order, comp)
		for _, next := range c.DAG[comp] {
			indegree[next]--
			if indegree[next] == 0 {
				ready = append(ready, next)
				sort.Ints(ready)
			}
		}
	}
	return order
}

func sortNodes[T comparable](nodes []T, less func(a, b T) bool) {
	if less == nil {
		return
	}
	sort.SliceStable(nodes, func(i, j int) bool { return less(nodes[i], nodes[j]) })
}
