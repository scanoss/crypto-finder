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
	// Step is the next node on one minimum-length route from a node to the
	// target: the callee it calls. The target carries no entry. Following Step
	// names ONE route of Depth length — the walk still admits each node once, so
	// this is not the route set and cannot be used to enumerate it. Naming the
	// route the recorded Depth already measures is the whole purpose.
	Step map[T]T
}

// Route returns one minimum-length route from `from` to the target, in
// caller-to-callee order and inclusive of both ends. It is nil when `from` did
// not reach the target, and its length is always Depth[from]+1.
func (r Reachable[T]) Route(from T) []T {
	if _, ok := r.Depth[from]; !ok {
		return nil
	}
	route := []T{from}
	current := from
	for current != r.Target {
		step, ok := r.Step[current]
		if !ok {
			return nil
		}
		current = step
		route = append(route, current)
	}
	return route
}

// Reach walks callers breadth-first from target and records every node that
// reaches it with that node's minimum distance.
//
// Each node is visited once, which makes this O(V+E). That costs nothing here
// because the answer is a SET: re-convergence loses paths, not members. A walk
// that collected paths under the same rule would lose the second branch into any
// shared caller — which is exactly the defect this package exists to avoid
// repeating.
//
// Reachable.Step therefore names one route per node and never the route set: the
// branch a shared caller loses is a route this walk was never entitled to report.
// Callers that need the route set condense first and go through Routes.
func Reach[T comparable](target T, opts Options[T]) Reachable[T] {
	out := Reachable[T]{
		Target:   target,
		Depth:    map[T]int{target: 0},
		Terminal: map[T]bool{},
		Callers:  map[T][]T{},
		Step:     map[T]T{},
	}

	queue := []T{target}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		queue = out.visit(current, target, queue, opts)
	}

	out.pruneToVisited()
	return out
}

// visit classifies one dequeued node and returns the queue with any newly
// discovered callers appended.
func (r *Reachable[T]) visit(current, target T, queue []T, opts Options[T]) []T {
	if current != target && opts.IsBoundary != nil && opts.IsBoundary(current) {
		r.Terminal[current] = true
		return queue
	}

	callers := opts.Callers(current)
	if len(callers) == 0 {
		// A node with no callers. On the mine path that is the library's public
		// API and so a terminal; with consumer code known it means nothing
		// consumer-side reaches the target, and the branch is simply dropped.
		if opts.RootIsTerminal && current != target {
			r.Terminal[current] = true
		}
		return queue
	}

	depth := r.Depth[current]
	// depth counts calls; a route's frame count is depth+1. Do not grow past
	// MaxDepth frames.
	if opts.MaxDepth > 0 && depth+2 > opts.MaxDepth {
		return queue
	}
	return r.enqueueCallers(current, callers, depth, queue, opts.Less)
}

// enqueueCallers records the induced edges out of current and queues the callers
// it had not seen before.
func (r *Reachable[T]) enqueueCallers(current T, callers []T, depth int, queue []T, less func(a, b T) bool) []T {
	sorted := append([]T(nil), callers...)
	sortNodes(sorted, less)
	for _, caller := range sorted {
		r.Callers[current] = append(r.Callers[current], caller)
		if _, seen := r.Depth[caller]; seen {
			continue
		}
		r.Depth[caller] = depth + 1
		r.Step[caller] = current
		queue = append(queue, caller)
	}
	return queue
}

// pruneToVisited drops edges to nodes the walk never admitted (depth-capped), so
// Callers is exactly the adjacency induced on Depth.
func (r *Reachable[T]) pruneToVisited() {
	for node, callers := range r.Callers {
		kept := callers[:0]
		for _, caller := range callers {
			if _, ok := r.Depth[caller]; ok {
				kept = append(kept, caller)
			}
		}
		r.Callers[node] = kept
	}
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
	st := &tarjanState[T]{
		index:   make(map[T]int, len(nodes)),
		low:     make(map[T]int, len(nodes)),
		onStack: make(map[T]bool, len(nodes)),
		callers: callers,
		less:    less,
		out:     out,
	}
	for _, root := range nodes {
		if _, visited := st.index[root]; visited {
			continue
		}
		st.run(root)
	}
}

// tarjanState is one traversal's bookkeeping.
type tarjanState[T comparable] struct {
	index   map[T]int
	low     map[T]int
	onStack map[T]bool
	stack   []T
	counter int
	callers map[T][]T
	less    func(a, b T) bool
	out     *Condensed[T]
}

// tarjanFrame is one entry of the explicit DFS stack: the node being expanded and
// how far through its callers the expansion got.
type tarjanFrame[T comparable] struct {
	node T
	next int
}

// run expands one DFS tree, rooted at root.
func (s *tarjanState[T]) run(root T) {
	s.discover(root)
	work := []tarjanFrame[T]{{node: root}}
	for len(work) > 0 {
		if s.descend(&work) {
			continue
		}
		v := work[len(work)-1].node
		if s.low[v] == s.index[v] {
			s.popComponent(v)
		}
		work = work[:len(work)-1]
		if len(work) > 0 {
			s.liftParent(work[len(work)-1].node, v)
		}
	}
}

// discover numbers a node and pushes it on the component stack.
func (s *tarjanState[T]) discover(node T) {
	s.index[node] = s.counter
	s.low[node] = s.counter
	s.counter++
	s.stack = append(s.stack, node)
	s.onStack[node] = true
}

// descend advances the top frame through its callers. It reports true when it
// stepped into an undiscovered caller, meaning the caller must be expanded before
// the current node can be finished.
func (s *tarjanState[T]) descend(work *[]tarjanFrame[T]) bool {
	top := &(*work)[len(*work)-1]
	v := top.node
	adj := s.callers[v]
	for top.next < len(adj) {
		w := adj[top.next]
		top.next++
		if _, visited := s.index[w]; !visited {
			s.discover(w)
			*work = append(*work, tarjanFrame[T]{node: w})
			return true
		}
		// Only a node still on the stack is part of an open cycle. One already
		// assigned to a component must be ignored, or v would be folded into a
		// component it merely points at.
		if s.onStack[w] && s.index[w] < s.low[v] {
			s.low[v] = s.index[w]
		}
	}
	return false
}

// popComponent closes the component rooted at v: v plus everything stacked above.
func (s *tarjanState[T]) popComponent(v T) {
	id := len(s.out.Members)
	var group []T
	for {
		w := s.stack[len(s.stack)-1]
		s.stack = s.stack[:len(s.stack)-1]
		s.onStack[w] = false
		s.out.Comp[w] = id
		group = append(group, w)
		if w == v {
			break
		}
	}
	sortNodes(group, s.less)
	s.out.Members = append(s.out.Members, group)
}

// liftParent propagates a finished child's reach up to its parent: whatever the
// child can climb back to, the parent can too.
func (s *tarjanState[T]) liftParent(parent, child T) {
	if s.low[child] < s.low[parent] {
		s.low[parent] = s.low[child]
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

// Routes builds up to budget concrete routes, each ordered from the target
// outward to a terminal. A budget of 0 means unbounded.
//
// Inside a component the shortest hop sequence is used: a component is a cycle,
// so every internal order describes the same trip through it, and the shortest is
// the readable representative. Condensed.Members keeps the full membership for a
// caller that wants to show what was collapsed.
func Routes[T comparable](r Reachable[T], c Condensed[T], budget int) [][]T {
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
				if budget > 0 && len(out) >= budget {
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
