package callgraph

import "github.com/rs/zerolog/log"

// Tracer walks a CallGraph backwards from crypto findings to user entry points.
type Tracer struct {
	graph  *CallGraph
	pkgSep string
}

// NewTracer creates a new backward tracer for the given call graph.
// pkgSep is the package path separator ("/" for Go, "." for Java).
func NewTracer(graph *CallGraph, pkgSep string) *Tracer {
	return &Tracer{graph: graph, pkgSep: pkgSep}
}

// FindContainingFunction finds the FunctionDecl that contains the given file:line.
// Returns nil if no function spans that location.
func (t *Tracer) FindContainingFunction(filePath string, line int) *FunctionDecl {
	for _, fn := range t.graph.Functions {
		if fn.FilePath == filePath && line >= fn.StartLine && line <= fn.EndLine {
			return fn
		}
	}
	return nil
}

// TraceBack finds all call chains from user entry points to the target function.
// It uses BFS backwards through the caller index, terminating chains when a
// function in a user package is reached.
//
// userPackages defines which Go import paths are considered "user code".
// maxDepth limits how deep the backward trace goes (0 = unlimited).
//
//nolint:gocognit // BFS traversal intentionally handles cycle checks, depth limits, and user-boundary termination in one pass.
func (t *Tracer) TraceBack(target FunctionID, userPackages map[string]bool, maxDepth int) []CallChain {
	targetKey := target.String()

	// Check if the target exists in the graph
	if _, exists := t.graph.Functions[targetKey]; !exists {
		log.Debug().Str("target", targetKey).Msg("Target function not found in call graph")
		return nil
	}

	var results []CallChain

	// BFS state: each item is a partial chain being built backwards
	type bfsItem struct {
		chain   []CallChainStep
		visited map[string]bool
	}

	initial := bfsItem{
		chain: []CallChainStep{{
			Function: target,
			FilePath: t.graph.Functions[targetKey].FilePath,
			Line:     t.graph.Functions[targetKey].StartLine,
		}},
		visited: map[string]bool{targetKey: true},
	}

	queue := []bfsItem{initial}

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

		// Find all callers of the head function
		callers := t.graph.Callers[headKey]
		if len(callers) == 0 {
			// Root function (no callers) — chain is complete if it reached user code
			if chainReachesUserCode(current.chain, userPackages, t.pkgSep) && len(current.chain) > 1 {
				results = append(results, CallChain{Steps: current.chain})
			}
			continue
		}

		for _, callerKey := range callers {
			if current.visited[callerKey] {
				continue // cycle detection
			}

			callerFn, exists := t.graph.Functions[callerKey]
			if !exists {
				continue
			}

			// Find the specific call line where the caller calls the head function
			callLine := findCallLine(callerFn, headKey)

			// Prepend caller to chain (building from target back to user)
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

			queue = append(queue, bfsItem{
				chain:   newChain,
				visited: newVisited,
			})
		}
	}

	return results
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
	for _, step := range chain {
		if isUserPackage(step.Function.Package, userPackages, sep) {
			return true
		}
	}
	return false
}

// findCallLine finds the line number where callerFn calls the function identified by calleeKey.
func findCallLine(callerFn *FunctionDecl, calleeKey string) int {
	for _, call := range callerFn.Calls {
		if call.Callee.String() == calleeKey {
			return call.Line
		}
	}
	// Fallback to function start line if we can't find the specific call
	return callerFn.StartLine
}
