package callgraph

import "github.com/rs/zerolog/log"

// traceMaxFrontier caps the BFS queue size as a safety valve against
// pathological graphs. With the graph-global frontier set (see TraceBackLimited)
// each function is enqueued at most once, so the queue is bounded by the number
// of functions and this cap should never fire in practice — it exists purely to
// guarantee bounded memory if that invariant is ever violated.
const traceMaxFrontier = 1_000_000

// Tracer walks a CallGraph backwards from crypto findings to user entry points.
type Tracer struct {
	graph  *CallGraph
	pkgSep string
}

type traceBFSItem struct {
	chain []CallChainStep
}

// NewTracer creates a new backward tracer for the given call graph.
// pkgSep is the package path separator ("/" for Go, "." for Java).
func NewTracer(graph *CallGraph, pkgSep string) *Tracer {
	return &Tracer{graph: graph, pkgSep: pkgSep}
}

// TraceBackLimited behaves like TraceBack but can stop early after collecting
// maxChains complete chains. A maxChains value of 0 means unlimited.
func (t *Tracer) TraceBackLimited(target FunctionID, userPackages map[string]bool, maxDepth, maxChains int) ([]CallChain, bool) {
	targetKey := target.String()

	// Check if the target exists in the graph
	if _, exists := t.graph.Functions[targetKey]; !exists {
		log.Debug().Str("target", targetKey).Msg("Target function not found in call graph")
		return nil, false
	}

	var results []CallChain

	// enqueued is a graph-GLOBAL frontier set: a function is added to the queue
	// at most once across the entire traversal. This keeps the work O(V+E)
	// instead of O(paths), which on high-fan-in graphs (large crypto libraries
	// such as BouncyCastle) is the difference between bounded time and a hang.
	// The tradeoff is that re-convergent (diamond) paths through a shared
	// ancestor collapse to the first (shortest) path that reached it — which is
	// the right answer for reachability and was already lossy under maxChains.
	enqueued := map[string]bool{targetKey: true}

	initial := traceBFSItem{
		chain: []CallChainStep{{
			Function: target,
			FilePath: t.graph.Functions[targetKey].FilePath,
			Line:     t.graph.Functions[targetKey].StartLine,
		}},
	}

	queue := []traceBFSItem{initial}

	for len(queue) > 0 {
		if len(queue) >= traceMaxFrontier {
			log.Warn().Str("target", targetKey).Int("frontier", len(queue)).
				Msg("Call-chain frontier cap reached; truncating trace")
			return results, true
		}

		current := queue[0]
		queue = queue[1:]

		// Check depth limit
		if maxDepth > 0 && len(current.chain) > maxDepth {
			continue
		}

		headKey := current.chain[0].Function.String()
		callers := t.graph.Callers[headKey]

		collect, expand := t.classifyTraceItem(current, callers, userPackages)
		if collect {
			var truncated bool
			results, truncated = appendTraceResult(results, current.chain, maxChains)
			if truncated {
				return results, true
			}
		}
		if expand {
			queue = t.enqueueCallers(queue, current, callers, headKey, enqueued)
		}
	}

	return results, false
}

// classifyTraceItem decides what to do with a dequeued chain:
//   - collect=true: the chain is complete and should be recorded (it reached a
//     user-package boundary, or a graph root that reached user code).
//   - expand=true: the chain head has callers that should be enqueued.
//
// A graph root whose chain never reached user code yields both false — the item
// is simply dropped.
func (t *Tracer) classifyTraceItem(current traceBFSItem, callers []string, userPackages map[string]bool) (collect, expand bool) {
	if t.shouldStopAtUserBoundary(current, userPackages) {
		return true, false
	}
	if len(callers) == 0 {
		return t.rootChainIsComplete(current, userPackages), false
	}
	return false, true
}

func appendTraceResult(results []CallChain, chain []CallChainStep, maxChains int) ([]CallChain, bool) {
	results = append(results, CallChain{Steps: chain})
	return results, maxChains > 0 && len(results) >= maxChains
}

func (t *Tracer) shouldStopAtUserBoundary(current traceBFSItem, userPackages map[string]bool) bool {
	if len(current.chain) <= 1 || userPackages == nil {
		return false
	}
	head := current.chain[0]
	return isUserPackage(head.Function.Package, userPackages, t.pkgSep)
}

func (t *Tracer) rootChainIsComplete(current traceBFSItem, userPackages map[string]bool) bool {
	return len(current.chain) > 1 && chainReachesUserCode(current.chain, userPackages, t.pkgSep)
}

func (t *Tracer) enqueueCallers(
	queue []traceBFSItem,
	current traceBFSItem,
	callers []string,
	headKey string,
	enqueued map[string]bool,
) []traceBFSItem {
	for _, callerKey := range callers {
		// Graph-global dedup: enqueue each function at most once. This also
		// subsumes cycle prevention — a node already on the frontier (or
		// expanded) is never revisited — so no per-path visited set is needed.
		if enqueued[callerKey] {
			continue
		}

		callerFn, exists := t.graph.Functions[callerKey]
		if !exists {
			continue
		}
		enqueued[callerKey] = true

		callLine := findCallLine(callerFn, headKey)

		newChain := make([]CallChainStep, 0, len(current.chain)+1)
		newChain = append(newChain, CallChainStep{
			Function: callerFn.ID,
			FilePath: callerFn.FilePath,
			Line:     callLine,
		})
		newChain = append(newChain, current.chain...)

		queue = append(queue, traceBFSItem{chain: newChain})
	}
	return queue
}

// isUserPackage checks if the given package path belongs to user code.
// sep is the package path separator ("/" for Go, "." for Java).
func isUserPackage(pkg string, userPackages map[string]bool, sep string) bool {
	// Direct match
	if userPackages[pkg] {
		return true
	}
	// Check if pkg is a sub-package of any user package
	for userPkg := range userPackages {
		prefix := userPkg + sep
		if len(pkg) >= len(prefix) && pkg[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// chainReachesUserCode checks if any step in the chain belongs to a user package.
func chainReachesUserCode(chain []CallChainStep, userPackages map[string]bool, sep string) bool {
	if userPackages == nil {
		return true
	}
	for _, step := range chain {
		if isUserPackage(step.Function.Package, userPackages, sep) {
			return true
		}
	}
	return false
}

// findCallLine finds the line number where callerFn calls the function identified by calleeKey.
func findCallLine(callerFn *FunctionDecl, calleeKey string) int {
	calleeID, err := ParseFunctionID(calleeKey)
	for i := range callerFn.Calls {
		call := callerFn.Calls[i]
		if call.Callee.String() == calleeKey {
			return call.Line
		}
		if err == nil &&
			call.Callee.Package == calleeID.Package &&
			call.Callee.Type == calleeID.Type &&
			methodArityKey(call.Callee.Name) == methodArityKey(calleeID.Name) {
			return call.Line
		}
	}
	// Fallback to function start line if we can't find the specific call
	return callerFn.StartLine
}
