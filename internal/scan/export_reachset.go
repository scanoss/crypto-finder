package scan

import (
	"fmt"

	"github.com/scanoss/crypto-finder/internal/callgraph"
)

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

	cacheKey := containingFn.ID.String()
	pathsTotal := ctx.condensedTotals[cacheKey]
	pathsTruncated := ctx.condensedTruncated[cacheKey]

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
		recordEntryPointFindingWithPaths(ep, fg, hops+1, pathsTotal, pathsTruncated)

		for _, supportingID := range fg.SupportingCallIDs {
			support, ok := supportingByID[supportingID]
			if !ok {
				continue
			}
			referencedSupporting[supportingID] = struct{}{}
			recordEntryPointSupporting(ep, support, hops+1)
		}

		if isUserCodeFunction(ctx, decl) {
			recordUserCallSites(ctx, ep, decl, reach.depths)
		}
	}
}

// recordEntryPointFindingWithPaths records the finding reference and, on the
// shallowest observation, the condensed route total for it.
func recordEntryPointFindingWithPaths(
	ep *entryPointData,
	fg *callGraphExportFinding,
	depth, pathsTotal int,
	pathsTruncated bool,
) {
	if ep == nil || fg == nil || fg.MatchedOperation == nil {
		return
	}
	existing, exists := ep.findings[fg.FindingID]
	if exists && depth >= existing.chainDepth {
		return
	}
	ep.findings[fg.FindingID] = entryPointFindingRef{
		findingID:      fg.FindingID,
		matchedOp:      fg.MatchedOperation,
		chainDepth:     depth,
		pathsTotal:     pathsTotal,
		pathsTruncated: pathsTruncated,
	}
}

// isUserCodeFunction reports whether a declaration belongs to the scanned
// project rather than a dependency. With no user packages known (the mine path)
// nothing is user code: there the entry point IS the library's public API and
// its call sites are not something a reader edits.
func isUserCodeFunction(ctx *exportBuildContext, decl *callgraph.FunctionDecl) bool {
	if ctx == nil || ctx.userPackages == nil || decl == nil {
		return false
	}
	return callgraph.IsUserPackage(decl.ID.Package, ctx.userPackages, ctx.packageSeparator)
}

// recordUserCallSites attaches the call sites of a user function whose callee
// also reaches the crypto — the lines a reader has to change.
//
// Dispatch fan-out is collapsed per (line, callee): one source line resolved to
// several candidate receivers is one call site, not several.
func recordUserCallSites(
	ctx *exportBuildContext,
	ep *entryPointData,
	decl *callgraph.FunctionDecl,
	reachable map[string]int,
) {
	for i := range decl.Calls {
		call := &decl.Calls[i]
		calleeKey := call.Callee.String()
		if _, ok := reachable[calleeKey]; !ok {
			continue
		}
		if call.Line <= 0 {
			continue
		}
		site := callGraphUserCallSite{
			FilePath: normalizeExportPath(ctx, decl.FilePath).FilePath,
			Line:     call.Line,
			Callee:   fullFunctionName(call.Callee),
		}
		if ep.userCallSites == nil {
			ep.userCallSites = make(map[string]callGraphUserCallSite)
		}
		ep.userCallSites[fmt.Sprintf("%d|%s", site.Line, site.Callee)] = site
	}
}
