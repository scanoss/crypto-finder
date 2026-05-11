package callgraph

import "github.com/rs/zerolog/log"

// Tracer walks a CallGraph backwards from crypto findings to user entry points.
type Tracer struct {
	graph  *CallGraph
	pkgSep string
}

type traceBFSItem struct {
	chain   []CallChainStep
	visited map[string]bool
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

	initial := traceBFSItem{
		chain: []CallChainStep{{
			Function: target,
			FilePath: t.graph.Functions[targetKey].FilePath,
			Line:     t.graph.Functions[targetKey].StartLine,
		}},
		visited: map[string]bool{targetKey: true},
	}

	queue := []traceBFSItem{initial}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		// Check depth limit
		if maxDepth > 0 && len(current.chain) > maxDepth {
			continue
		}

		// Get the current head of the chain (the function we're tracing from)
		head := current.chain[0]
		headKey := head.Function.String()
		if t.shouldStopAtUserBoundary(current, userPackages) {
			var truncated bool
			results, truncated = appendTraceResult(results, current.chain, maxChains)
			if truncated {
				return results, true
			}
			continue
		}

		// Find all callers of the head function
		callers := t.graph.Callers[headKey]
		if len(callers) == 0 {
			// Root function (no callers) — chain is complete if it reached user code
			if t.rootChainIsComplete(current, userPackages) {
				var truncated bool
				results, truncated = appendTraceResult(results, current.chain, maxChains)
				if truncated {
					return results, true
				}
			}
			continue
		}

		queue = t.enqueueCallers(queue, current, callers, headKey)
	}

	return results, false
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
) []traceBFSItem {
	for _, callerKey := range callers {
		if current.visited[callerKey] {
			continue
		}

		callerFn, exists := t.graph.Functions[callerKey]
		if !exists {
			continue
		}

		callLine := findCallLine(callerFn, headKey)

		newChain := make([]CallChainStep, 0, len(current.chain)+1)
		newChain = append(newChain, CallChainStep{
			Function: callerFn.ID,
			FilePath: callerFn.FilePath,
			Line:     callLine,
		})
		newChain = append(newChain, current.chain...)

		newVisited := make(map[string]bool, len(current.visited)+1)
		for k, v := range current.visited {
			newVisited[k] = v
		}
		newVisited[callerKey] = true

		queue = append(queue, traceBFSItem{
			chain:   newChain,
			visited: newVisited,
		})
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
