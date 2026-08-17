package callgraph

import (
	"sort"

	"github.com/rs/zerolog/log"
)

// condensed.go implements backward tracing over the SCC-CONDENSED reverse graph
// (issue #249).
//
// TraceBackLimited answers "is this crypto reachable" with one representative
// chain per traversal, because its graph-global frontier set enqueues each
// function at most once and chains are only COLLECTED at a user boundary. When
// two library APIs converge on the same user function, the first branch to
// arrive claims that user node and the other branch never produces a chain — so
// a user call that genuinely triggers the crypto disappears from the exported
// surface (measured on the jedis redis-demo: jedis.set on line 83 is dropped,
// jedis.get on line 84 survives).
//
// Enumerating every path instead is not an option: the reverse-reachable
// subgraph is cyclic, so the path set is unbounded, and bounded to depth 32 the
// jedis case alone has 5.4e23 walks (bcprov peaks at 2.5e69). Almost all of that
// count is a single strongly connected cluster — a retry/reconnect loop — being
// traversed in every possible internal order, which carries no information a
// reader can act on.
//
// Condensing every strongly connected component into one node removes exactly
// that redundancy and nothing else: the result is a DAG, so the path set becomes
// finite and countable in O(V+E). Measured: jedis 5.4e23 -> 6 paths;
// bcprov-jdk18on@1.84 2.5e69 -> 7.4M worst case, with 83.5% of its 2472
// findings at or under 128 condensed paths.
//
// Because the count is computed BEFORE enumeration, a truncated result reports
// the exact total instead of silently dropping the remainder — the silent drop
// being the actual defect behind #249.

// condensedTrace is the per-target state of one condensed backward trace.
// Everything is keyed by FunctionID.String() and every iteration order is
// sorted, so the result does not depend on Go map ordering.
type condensedTrace struct {
	tracer    *Tracer
	targetKey string

	// depth is the minimum number of reverse hops from the target, and doubles
	// as the visited set of the reverse-reachable subgraph.
	depth map[string]int
	// terminal marks nodes where a chain is complete: a user-package function
	// when userPackages is set, or a graph root on the mine path.
	terminal map[string]bool
	// revAdj is the reverse adjacency (callee -> callers) restricted to the
	// reachable set. Terminals carry no outgoing edges: a chain stops there,
	// mirroring TraceBackLimited's user-boundary stop.
	revAdj map[string][]string

	// comp maps a function to its SCC id; members is the inverse.
	comp    map[string]int
	members [][]string

	// dag is the condensed adjacency, and repEdge records one representative
	// concrete edge per condensed edge so a condensed route can be expanded
	// back into a real function chain.
	dag     map[int][]int
	repEdge map[condensedEdge][2]string
}

type condensedEdge struct {
	from, to int
}

// TraceBackCondensed walks callers of target over the SCC-condensed reverse
// graph and returns one chain per (condensed route, terminal) pair, ordered
// entry -> target like TraceBackLimited.
//
// total is the exact number of such pairs, computed before enumeration, so it is
// accurate even when maxChains truncates the returned slice. truncated reports
// whether len(chains) < total. A maxChains of 0 means unlimited.
func (t *Tracer) TraceBackCondensed(
	target FunctionID,
	userPackages map[string]bool,
	maxDepth, maxChains int,
) (chains []CallChain, total int, truncated bool) {
	targetKey := target.String()
	if _, exists := t.graph.Functions[targetKey]; !exists {
		log.Debug().Str("target", targetKey).Msg("Target function not found in call graph")
		return nil, 0, false
	}

	ct := &condensedTrace{tracer: t, targetKey: targetKey}
	ct.reach(userPackages, maxDepth)
	if len(ct.terminal) == 0 {
		// Nothing user code (or no graph root) reaches this function: same
		// answer TraceBackLimited gives by returning no chains.
		return nil, 0, false
	}
	ct.condense()

	order := ct.topoFromTarget()
	routes := ct.countRoutes(order)
	total = routes[ct.comp[targetKey]]

	chains = ct.enumerate(maxChains)
	return chains, total, len(chains) < total
}

// reach walks callers breadth-first from the target, recording the minimum hop
// distance of every function that reaches it and which of those are terminals.
// Each function is visited once, so this is O(V+E) — the same bound
// TraceBackLimited relies on, and the reason the frontier can stay global here:
// a SET of reaching functions loses nothing to re-convergence, only a set of
// PATHS does.
func (ct *condensedTrace) reach(userPackages map[string]bool, maxDepth int) {
	t := ct.tracer
	ct.depth = map[string]int{ct.targetKey: 0}
	ct.terminal = map[string]bool{}
	ct.revAdj = map[string][]string{}

	queue := []string{ct.targetKey}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		d := ct.depth[cur]

		callers := t.graph.Callers[cur]

		// A user-package function is where a chain ends. Mirrors
		// shouldStopAtUserBoundary: the target itself never counts, so a crypto
		// call inside user code still traces out to its own callers.
		if cur != ct.targetKey && userPackages != nil {
			if decl, ok := t.graph.Functions[cur]; ok &&
				isUserPackage(decl.ID.Package, userPackages, t.pkgSep) {
				ct.terminal[cur] = true
				continue
			}
		}

		if len(callers) == 0 {
			// A graph root. On the mine path (userPackages nil) that is the
			// library's public API and the most valuable entry point there is.
			// With user packages known, a root that is not user code means the
			// chain never reaches user code, which TraceBackLimited drops.
			if userPackages == nil && cur != ct.targetKey {
				ct.terminal[cur] = true
			}
			continue
		}

		// Chain length is hops+1; do not grow past maxDepth, matching
		// TraceBackLimited's silent drop of over-long chains.
		if maxDepth > 0 && d+2 > maxDepth {
			continue
		}

		sorted := append([]string(nil), callers...)
		sort.Strings(sorted)
		for _, callerKey := range sorted {
			if _, exists := t.graph.Functions[callerKey]; !exists {
				continue
			}
			ct.revAdj[cur] = append(ct.revAdj[cur], callerKey)
			if _, seen := ct.depth[callerKey]; seen {
				continue
			}
			ct.depth[callerKey] = d + 1
			queue = append(queue, callerKey)
		}
	}

	// Drop edges to functions the traversal never admitted (depth-capped), so
	// revAdj is exactly the induced subgraph on the reachable set.
	for node, callers := range ct.revAdj {
		kept := callers[:0]
		for _, c := range callers {
			if _, ok := ct.depth[c]; ok {
				kept = append(kept, c)
			}
		}
		ct.revAdj[node] = kept
	}
}

// condense runs Tarjan over the reachable subgraph and builds the condensed DAG.
//
// The set of SCCs is a property of the graph, not of the traversal order, so
// live and served paths condense identically without having to agree on a
// caller ordering first.
func (ct *condensedTrace) condense() {
	ct.tarjan()

	ct.dag = map[int][]int{}
	ct.repEdge = map[condensedEdge][2]string{}
	seen := map[condensedEdge]bool{}

	nodes := make([]string, 0, len(ct.depth))
	for node := range ct.depth {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)

	for _, node := range nodes {
		for _, caller := range ct.revAdj[node] {
			from, to := ct.comp[node], ct.comp[caller]
			if from == to {
				continue
			}
			edge := condensedEdge{from: from, to: to}
			if !seen[edge] {
				seen[edge] = true
				ct.dag[from] = append(ct.dag[from], to)
				// nodes is sorted and callers were sorted in reach, so the
				// first concrete edge found for a condensed edge is a
				// deterministic representative.
				ct.repEdge[edge] = [2]string{node, caller}
			}
		}
	}
	for from := range ct.dag {
		sort.Ints(ct.dag[from])
	}
}

// tarjan assigns every reachable function an SCC id, iteratively so a deep
// graph cannot overflow the goroutine stack.
func (ct *condensedTrace) tarjan() {
	const unvisited = -1

	index := make(map[string]int, len(ct.depth))
	low := make(map[string]int, len(ct.depth))
	onStack := make(map[string]bool, len(ct.depth))
	ct.comp = make(map[string]int, len(ct.depth))

	var stack []string
	counter := 0

	roots := make([]string, 0, len(ct.depth))
	for node := range ct.depth {
		roots = append(roots, node)
	}
	sort.Strings(roots)

	type frame struct {
		node string
		next int
	}

	for _, root := range roots {
		if _, ok := index[root]; ok {
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
			callers := ct.revAdj[v]

			descended := false
			for top.next < len(callers) {
				w := callers[top.next]
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
				// Only a node still on the stack is part of an open cycle; one
				// already assigned to a component must be ignored, or v would
				// be folded into a component it merely points at.
				if onStack[w] && index[w] < low[v] {
					low[v] = index[w]
				}
			}
			if descended {
				continue
			}

			if low[v] == index[v] {
				// v is the first-discovered member of its component, so its
				// component is v plus everything stacked above it.
				id := len(ct.members)
				var group []string
				for {
					w := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[w] = false
					ct.comp[w] = id
					group = append(group, w)
					if w == v {
						break
					}
				}
				sort.Strings(group)
				ct.members = append(ct.members, group)
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

// topoFromTarget returns the components reachable from the target's component in
// topological order (Kahn over the induced sub-DAG).
func (ct *condensedTrace) topoFromTarget() []int {
	start := ct.comp[ct.targetKey]

	reachable := map[int]bool{start: true}
	queue := []int{start}
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		for _, next := range ct.dag[c] {
			if !reachable[next] {
				reachable[next] = true
				queue = append(queue, next)
			}
		}
	}

	indeg := map[int]int{}
	for c := range reachable {
		indeg[c] += 0
		for _, next := range ct.dag[c] {
			indeg[next]++
		}
	}

	ready := make([]int, 0, len(indeg))
	for c, d := range indeg {
		if d == 0 {
			ready = append(ready, c)
		}
	}
	sort.Ints(ready)

	order := make([]int, 0, len(indeg))
	for len(ready) > 0 {
		c := ready[0]
		ready = ready[1:]
		order = append(order, c)
		for _, next := range ct.dag[c] {
			indeg[next]--
			if indeg[next] == 0 {
				ready = append(ready, next)
				sort.Ints(ready)
			}
		}
	}
	if len(order) != len(reachable) {
		// A condensed graph cannot contain a cycle, so this is unreachable
		// unless the SCC assignment is wrong. Route counts would silently
		// undercount, so say so rather than publish a bad total.
		log.Warn().
			Str("target", ct.targetKey).
			Int("ordered", len(order)).
			Int("reachable", len(reachable)).
			Msg("Condensed graph is not acyclic; condensed path total may be wrong")
	}
	return order
}

// countRoutes returns, per component, how many (condensed route, terminal) pairs
// start there — i.e. how many chains that component contributes. Computed in
// reverse topological order, so it is one O(V+E) pass and needs no recursion.
func (ct *condensedTrace) countRoutes(order []int) map[int]int {
	routes := make(map[int]int, len(order))
	for i := len(order) - 1; i >= 0; i-- {
		c := order[i]
		n := 0
		for _, member := range ct.members[c] {
			if ct.terminal[member] {
				n++
			}
		}
		for _, next := range ct.dag[c] {
			n += routes[next]
		}
		routes[c] = n
	}
	return routes
}

// enumerate walks the condensed DAG from the target's component and materializes
// one concrete chain per (route, terminal) pair, stopping at maxChains.
func (ct *condensedTrace) enumerate(maxChains int) []CallChain {
	var out []CallChain
	start := ct.comp[ct.targetKey]

	var walk func(route []int) bool
	walk = func(route []int) bool {
		current := route[len(route)-1]

		for _, member := range ct.members[current] {
			if !ct.terminal[member] {
				continue
			}
			if chain, ok := ct.materialize(route, member); ok {
				out = append(out, chain)
				if maxChains > 0 && len(out) >= maxChains {
					return false
				}
			}
		}

		for _, next := range ct.dag[current] {
			// Copy rather than append in place: sibling branches must not share
			// a backing array with the route handed to a deeper call.
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

// materialize expands a condensed route into a real function chain ending at the
// given terminal, ordered entry -> target.
//
// Inside a multi-function component the shortest hop sequence is used: a
// component is a cycle, so every internal order describes the same trip through
// it, and the shortest one is the readable representative. The component's full
// membership stays available to callers that want to show it.
func (ct *condensedTrace) materialize(route []int, terminal string) (CallChain, bool) {
	// Built target -> terminal, then reversed.
	backward := []string{ct.targetKey}
	current := ct.targetKey

	for i := 0; i+1 < len(route); i++ {
		edge := condensedEdge{from: route[i], to: route[i+1]}
		rep, ok := ct.repEdge[edge]
		if !ok {
			return CallChain{}, false
		}
		inside := ct.pathWithinComponent(current, rep[0], route[i])
		if inside == nil {
			return CallChain{}, false
		}
		backward = append(backward, inside...)
		backward = append(backward, rep[1])
		current = rep[1]
	}

	inside := ct.pathWithinComponent(current, terminal, route[len(route)-1])
	if inside == nil {
		return CallChain{}, false
	}
	backward = append(backward, inside...)

	steps := make([]CallChainStep, 0, len(backward))
	for i := len(backward) - 1; i >= 0; i-- {
		steps = append(steps, ct.buildStep(backward, i))
	}
	return CallChain{Steps: steps}, true
}

// pathWithinComponent returns the hops after from up to and including to, using
// only edges inside the component. Returns an empty (non-nil) slice when from
// and to are the same function, and nil when no internal path exists.
func (ct *condensedTrace) pathWithinComponent(from, to string, component int) []string {
	if from == to {
		return []string{}
	}

	prev := map[string]string{from: ""}
	queue := []string{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, caller := range ct.revAdj[cur] {
			if ct.comp[caller] != component {
				continue
			}
			if _, seen := prev[caller]; seen {
				continue
			}
			prev[caller] = cur
			if caller == to {
				var rev []string
				for at := to; at != from; at = prev[at] {
					rev = append(rev, at)
				}
				for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
					rev[i], rev[j] = rev[j], rev[i]
				}
				return rev
			}
			queue = append(queue, caller)
		}
	}
	return nil
}

// buildStep fills one chain step. backward is ordered target -> terminal, so the
// function a step calls is its predecessor in that slice; Line is the call site
// of that call, matching how enqueueCallers stamps lines.
func (ct *condensedTrace) buildStep(backward []string, i int) CallChainStep {
	key := backward[i]
	decl := ct.tracer.graph.Functions[key]
	step := CallChainStep{}
	if decl == nil {
		if id, err := ParseFunctionID(key); err == nil {
			step.Function = id
		}
		return step
	}
	step.Function = decl.ID
	step.FilePath = decl.FilePath
	if i == 0 {
		step.Line = decl.StartLine
		return step
	}
	step.Line = findCallLine(decl, backward[i-1])
	return step
}
