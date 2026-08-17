package callgraph

import (
	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/pkg/graphwalk"
)

// condensed.go answers two reachability questions over the live call graph that
// TraceBackLimited cannot (issue #249):
//
//	which functions reach this crypto      -> ReachingFunctions
//	how many distinct routes lead to it    -> TraceBackCondensed
//
// TraceBackLimited enqueues each function at most once and collects a chain only
// at a user boundary, so when two callers converge on the same function the first
// branch to arrive claims it and the other yields no chain at all. On the IBM
// redis-demo that drops jedis.set (line 83) while jedis.get (line 84) survives —
// and since crypto_entry_points was folded from the emitted chains, the dropped
// call disappeared from the published surface too.
//
// Enumerating every path instead is not available: the reverse-reachable subgraph
// is cyclic, so the route set is unbounded, and bounded to depth 32 the redis case
// alone has 5.4e23 walks (bcprov-jdk18on@1.84 peaks at 2.5e69). Almost all of that
// is one strongly connected cluster — a retry loop — traversed in every internal
// order, which tells a reader nothing new.
//
// Collapsing each cluster to a single node removes exactly that redundancy: the
// result is acyclic, so the route set is finite and countable in O(V+E). Measured:
// redis 5.4e23 -> 6 routes; bcprov 2.5e69 -> 7.4M worst case, with 83.5% of its
// 2472 findings at or under 128.
//
// The traversal itself lives in pkg/graphwalk, shared with the stitcher so the
// two reachability paths cannot drift apart; this file supplies the live graph's
// adjacency and materializes the results into CallChains.

// nodeLess orders function keys so every traversal is reproducible, and matches
// the caller ordering TraceBackLimited applies.
func nodeLess(a, b string) bool { return a < b }

// walkOptions describes the live call graph to pkg/graphwalk.
//
// A user-package function is where a chain ends: reaching it answers "does the
// consumer's code get here", and its own callers belong to a different question.
// With no user packages known — the mine path, scanning a library alone — a graph
// root plays that role instead, since for a library that is its public API.
func (t *Tracer) walkOptions(userPackages map[string]bool, maxDepth int) graphwalk.Options[string] {
	return graphwalk.Options[string]{
		Callers: func(key string) []string {
			callers := t.graph.Callers[key]
			known := make([]string, 0, len(callers))
			for _, caller := range callers {
				if _, exists := t.graph.Functions[caller]; exists {
					known = append(known, caller)
				}
			}
			return known
		},
		Less: nodeLess,
		IsBoundary: func(key string) bool {
			if userPackages == nil {
				return false
			}
			decl, ok := t.graph.Functions[key]
			return ok && isUserPackage(decl.ID.Package, userPackages, t.pkgSep)
		},
		RootIsTerminal: userPackages == nil,
		MaxDepth:       maxDepth,
	}
}

// IsUserPackage reports whether pkg belongs to user code, given the user package
// set and the ecosystem's package separator. Exported so the export layer can
// classify a reaching function without duplicating the sub-package prefix rule.
func IsUserPackage(pkg string, userPackages map[string]bool, sep string) bool {
	return isUserPackage(pkg, userPackages, sep)
}

// ReachingFunctions returns every function that reaches target, keyed by
// FunctionID.String(), with the minimum number of calls it takes to get there
// (0 for the target itself). terminals reports which of those are where a chain
// ends.
//
// This answers "which functions reach this crypto", which is a different question
// from "how do you get there" and must not be derived from the second: a set of
// reaching functions loses nothing to re-convergence or to a route budget, while a
// set of paths loses both. Cost is O(V+E).
func (t *Tracer) ReachingFunctions(
	target FunctionID,
	userPackages map[string]bool,
	maxDepth int,
) (depths map[string]int, terminals map[string]bool) {
	if _, exists := t.graph.Functions[target.String()]; !exists {
		return nil, nil
	}
	reach := graphwalk.Reach(target.String(), t.walkOptions(userPackages, maxDepth))
	return reach.Depth, reach.Terminal
}

// TraceBackCondensed walks callers of target over the cycle-collapsed reverse
// graph and returns one chain per (route, terminal) pair, ordered entry -> target
// like TraceBackLimited.
//
// total is the exact number of such pairs, counted before any chain is built, so
// it is accurate even when maxChains truncates the returned slice. truncated
// reports whether len(chains) < total. A maxChains of 0 means unlimited.
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

	reach := graphwalk.Reach(targetKey, t.walkOptions(userPackages, maxDepth))
	if len(reach.Terminal) == 0 {
		// Nothing user code (or no graph root) reaches this function: the same
		// answer TraceBackLimited gives by returning no chains.
		return nil, 0, false
	}
	condensed := graphwalk.Condense(reach, nodeLess)

	total = graphwalk.Count(reach, condensed)
	for _, route := range graphwalk.Routes(reach, condensed, maxChains) {
		chains = append(chains, t.materializeRoute(route))
	}
	return chains, total, len(chains) < total
}

// materializeRoute turns a route — target first, terminal last — into a CallChain
// ordered entry -> target, stamping each step with the line where it calls the
// next one, the way enqueueCallers does.
func (t *Tracer) materializeRoute(route []string) CallChain {
	steps := make([]CallChainStep, 0, len(route))
	for i := len(route) - 1; i >= 0; i-- {
		steps = append(steps, t.buildStep(route, i))
	}
	return CallChain{Steps: steps}
}

func (t *Tracer) buildStep(route []string, i int) CallChainStep {
	key := route[i]
	decl := t.graph.Functions[key]
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
	step.Line = findCallLine(decl, route[i-1])
	return step
}
