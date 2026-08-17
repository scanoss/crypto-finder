// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "sort"

// stitch_reachset.go derives the served crypto_entry_points from reverse
// reachability instead of from the chains that survived the stitch (issue #249).
//
// buildCallgraphCryptoEntryPoints folds the emitted chains into the index, so a
// function's presence there depends on whether some chain through it was
// emitted — and two things decide that which have nothing to do with
// reachability: a chain is only collected at an entry, so a shared caller is
// claimed by the first branch to arrive; and the per-op chain budget cuts the
// rest. Neither is visible in the output, which is how jedis ends up publishing
// 71 entry points for a graph where 1,142 functions reach the crypto.
//
// The computation this needs already exists for the cross-fragment composition
// path: backwardDistances is a reverse BFS with per-node minimum depth. Applying
// it per crypto operation is the same question asked at the single-component
// level, so this file reuses it rather than adding a third traversal.
//
// The index stays deliberately broad, per the 6.8 contract: every function that
// reaches the crypto is published, and `root` marks the chain roots on top of
// it. No filtering — a narrower index is a different projection, not this one.

// callersWithoutCallSites drops the call-site payload from a reverse adjacency,
// leaving the plain caller map backwardDistances walks.
func callersWithoutCallSites(reverse map[graphNode][]reverseEdge) map[graphNode][]graphNode {
	plain := make(map[graphNode][]graphNode, len(reverse))
	for target, edges := range reverse {
		callers := make([]graphNode, 0, len(edges))
		for _, edge := range edges {
			callers = append(callers, edge.caller)
		}
		plain[target] = callers
	}
	return plain
}

// reachEntry is one function that reaches a crypto operation, carrying the frame
// the served export needs plus its distance and whether it is a chain root.
type reachEntry struct {
	frame CallFrame
	depth int
	root  bool
}

// recordReachEntries computes the set of functions that reach opNode and files
// it under that node.
//
// Keyed by the crypto-op node rather than by finding id, because the export
// recomputes dependency finding_ids with a module prefix; the anchor node is the
// same identity on both sides, and is how forwardClosures is keyed too.
//
// depth is frame count, not hops: the operation's own function is 1 and each
// caller adds one, matching what the chain-derived index published.
func recordReachEntries(
	opNode graphNode,
	reverse map[graphNode][]graphNode,
	entrySet map[graphNode]bool,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]Function,
	out *Result,
) {
	distances := backwardDistances(opNode, reverse)
	if len(distances) == 0 {
		return
	}

	nodes := make([]graphNode, 0, len(distances))
	for node := range distances {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Function != nodes[j].Function {
			return nodes[i].Function < nodes[j].Function
		}
		return nodes[i].Component.String() < nodes[j].Component.String()
	})

	entries := make([]reachEntry, 0, len(nodes))
	for _, node := range nodes {
		entries = append(entries, reachEntry{
			frame: buildFrame(node, nil, fragments, functionsByNode),
			depth: distances[node] + 1,
			root:  entrySet[node],
		})
	}

	if out.reachByAnchor == nil {
		out.reachByAnchor = make(map[graphNode][]reachEntry)
	}
	out.reachByAnchor[opNode] = entries
}

// buildEntryPointsFromReach builds the served index from the reachability sets,
// keeping the same entry shape and the same supporting-call attachment the
// chain-derived builder produced.
func buildEntryPointsFromReach(
	reachByAnchor map[graphNode][]reachEntry,
	anchorByFinding map[string]graphNode,
	root ComponentKey,
	findingGraphs []ExportFindingGraph,
	supportingCalls []ExportSupportingCall,
) []ExportCryptoEntryPoint {
	index := make(map[string]*epData)
	rootKeys := make(map[string]bool)

	supportingByID := make(map[string]ExportSupportingCall, len(supportingCalls))
	for i := range supportingCalls {
		if supportingCalls[i].SupportingID != "" {
			supportingByID[supportingCalls[i].SupportingID] = supportingCalls[i]
		}
	}
	referencedSupporting := make(map[string]struct{}, len(supportingByID))

	for i := range findingGraphs {
		fg := &findingGraphs[i]
		anchor := anchorByFinding[fg.FindingID]
		indexFindingReach(index, rootKeys, fg, reachByAnchor[anchor],
			root, supportingByID, referencedSupporting)
	}

	// Supporting calls no finding graph claimed still deserve an entry, exactly
	// as in the chain-derived builder.
	for i := range supportingCalls {
		if _, ok := referencedSupporting[supportingCalls[i].SupportingID]; ok {
			continue
		}
		addSupportingCallToEPI(index, supportingCalls[i])
	}

	out := flattenEPI(index)
	for i := range out {
		if rootKeys[out[i].FunctionKey] {
			out[i].Root = true
		}
	}
	return out
}

// indexFindingReach files one finding against every function that reaches it.
func indexFindingReach(
	index map[string]*epData,
	rootKeys map[string]bool,
	fg *ExportFindingGraph,
	entries []reachEntry,
	root ComponentKey,
	supportingByID map[string]ExportSupportingCall,
	referencedSupporting map[string]struct{},
) {
	if len(entries) == 0 || fg.MatchedOperation == nil {
		return
	}
	for j := range entries {
		entry := &entries[j]
		node := buildExportNode(&entry.frame, root)
		if node.FunctionName == "" && node.FunctionKey == "" {
			continue
		}
		ep := ensureEPData(index, &node)
		recordReachEPFinding(ep, fg, entry.depth)
		if entry.root {
			rootKeys[ep.functionKey] = true
		}
		attachFindingSupporting(ep, fg, entry.depth, supportingByID, referencedSupporting)
	}
}

// attachFindingSupporting hangs the finding's supporting calls off one entry point
// at that entry's depth.
func attachFindingSupporting(
	ep *epData,
	fg *ExportFindingGraph,
	depth int,
	supportingByID map[string]ExportSupportingCall,
	referencedSupporting map[string]struct{},
) {
	for _, supportingID := range fg.SupportingCallIDs {
		support, ok := supportingByID[supportingID]
		if !ok {
			continue
		}
		referencedSupporting[supportingID] = struct{}{}
		recordEPSupporting(ep, support, depth)
	}
}

// recordAllReachEntries answers "which functions reach this crypto" for every
// operation in the closure. Both stitch paths call it: the index is a question
// about the graph, so it must not depend on which traversal emitted the chains.
func recordAllReachEntries(
	reverse map[graphNode][]graphNode,
	opsByNode map[graphNode][]CryptoOperation,
	entrySet map[graphNode]bool,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]Function,
	out *Result,
) {
	for _, opNode := range sortedNodes(opsByNode) {
		recordReachEntries(opNode, reverse, entrySet, fragments, functionsByNode, out)
	}
}

// recordReachEPFinding records the finding reference, keeping the shallowest
// depth when the same finding is reachable from an entry point by more than one
// distance.
func recordReachEPFinding(ep *epData, fg *ExportFindingGraph, depth int) {
	if ep == nil || fg == nil || fg.MatchedOperation == nil {
		return
	}
	existing, exists := ep.findings[fg.FindingID]
	if exists && depth >= existing.depth {
		return
	}
	ep.findings[fg.FindingID] = epFindingRef{
		findingID: fg.FindingID,
		matchedOp: fg.MatchedOperation,
		depth:     depth,
	}
}
