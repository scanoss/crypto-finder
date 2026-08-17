package scan

import "github.com/scanoss/crypto-finder/internal/callgraph"

// export_reachset.go builds crypto_entry_points from reverse reachability rather
// than from the exported call chains (issue #249).
//
// The index was conceived as an inverted view of call_chains — "every function
// that appears in any call chain is a potential entry point". As an index of the
// output that is correct by construction. It stops being correct once the field
// is read as an answer about the GRAPH ("which of my calls reach this crypto"),
// because then a function's presence depends on whether some chain through it
// happened to be exported. Two things decide that and neither is about
// reachability: chains are only collected at a user boundary, so a shared user
// function is claimed by the first branch that arrives; and a condensed route
// takes the shortest way through a cycle, so the cycle's other members appear in
// no chain at all.
//
// Measured on the IBM postgres-demo with an explicit driver call, three
// functions inside one strongly connected cluster
// (PgConnection.setReadOnly, PgConnection.execSQLUpdate,
// PgStatement.executeWithFlags) dropped out of the index for the second reason,
// while all three were present in the finding's 393-function reaching set.
//
// So the set is computed directly and the index is filled from it. Every field
// keeps its meaning: chain_depth becomes the true BFS minimum instead of the
// minimum over exported chains, which is the same quantity wherever the old one
// was defined.

// reachSetEntry is one memoized reverse-reachability answer.
type reachSetEntry struct {
	depths    map[string]int
	terminals map[string]bool
}

// reachSetForFunction returns the memoized set of functions that reach
// containingFn, with minimum hop counts.
func reachSetForFunction(ctx *exportBuildContext, containingFn *callgraph.FunctionDecl) reachSetEntry {
	if ctx == nil || containingFn == nil || ctx.graph == nil {
		return reachSetEntry{}
	}
	if ctx.reachSetCache == nil {
		ctx.reachSetCache = make(map[string]reachSetEntry)
	}
	key := containingFn.ID.String()
	if cached, ok := ctx.reachSetCache[key]; ok {
		return cached
	}
	tracer := callgraph.NewTracer(ctx.graph, ctx.packageSeparator)
	depths, terminals := tracer.ReachingFunctions(containingFn.ID, ctx.userPackages, callGraphExportMaxDepth)
	entry := reachSetEntry{depths: depths, terminals: terminals}
	ctx.reachSetCache[key] = entry
	return entry
}

// addFindingGraphReachSetToEntryPointIndex indexes every function that reaches
// the finding, at its true distance, and attaches the finding's supporting calls
// to each of them.
//
// It replaces addFindingGraphToEntryPointIndex plus
// addFindingGraphSupportingToEntryPointIndex when the condensed traceback is
// enabled; the unreachable-finding filter (#244) still runs at the call site.
func addFindingGraphReachSetToEntryPointIndex(
	ctx *exportBuildContext,
	index map[string]*entryPointData,
	fg *callGraphExportFinding,
	containingFn *callgraph.FunctionDecl,
	supportingByID map[string]callGraphSupportingCall,
	referencedSupporting map[string]struct{},
) {
	if fg == nil || fg.MatchedOperation == nil || containingFn == nil {
		return
	}
	reach := reachSetForFunction(ctx, containingFn)
	if len(reach.depths) == 0 {
		// Nothing reaches this crypto. The chain-derived path would still have
		// published the containing function off its single-node fallback chain;
		// with the set there is simply nothing to publish, which is the answer
		// #244 wanted.
		claimSupportingCalls(referencedSupporting, fg)
		return
	}

	for functionKey, hops := range reach.depths {
		decl := ctx.graph.Functions[functionKey]
		if decl == nil {
			continue
		}
		node := buildChainNode(ctx, decl.ID, decl.FilePath)
		if node.FunctionName == "" {
			continue
		}
		ep := ensureEntryPointData(index, &node)

		// chain_depth counted frames, so the containing function is 1 and each
		// caller adds one. hops is 0 at the containing function.
		recordReachEntryPointFinding(ep, fg, hops+1)

		for _, supportingID := range fg.SupportingCallIDs {
			support, ok := supportingByID[supportingID]
			if !ok {
				continue
			}
			referencedSupporting[supportingID] = struct{}{}
			recordEntryPointSupporting(ep, support, hops+1)
		}
	}
}

// markReachSetRoots records the walk's terminals as chain roots.
//
// A terminal is where a chain ends: the first root-module caller when user
// packages are known, or an in-degree-zero graph root otherwise — which is the
// `root` flag's definition verbatim (6.8+). Reading it off the walk instead of
// off the exported chain heads keeps the flag correct when call_chains was
// capped, and keeps the index itself deliberately broad: the set stays complete
// and `root` is the classification on top of it, not a filter over it.
func markReachSetRoots(ctx *exportBuildContext, roots map[string]bool, containingFn *callgraph.FunctionDecl) {
	if roots == nil || containingFn == nil {
		return
	}
	reach := reachSetForFunction(ctx, containingFn)
	for key := range reach.terminals {
		roots[key] = true
	}
}

// recordReachEntryPointFinding records the finding reference, keeping the
// shallowest depth when the same finding is reachable from an entry point by
// more than one distance.
func recordReachEntryPointFinding(ep *entryPointData, fg *callGraphExportFinding, depth int) {
	if ep == nil || fg == nil || fg.MatchedOperation == nil {
		return
	}
	existing, exists := ep.findings[fg.FindingID]
	if exists && depth >= existing.chainDepth {
		return
	}
	ep.findings[fg.FindingID] = entryPointFindingRef{
		findingID:  fg.FindingID,
		matchedOp:  fg.MatchedOperation,
		chainDepth: depth,
	}
}
