// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

// stitch_unresolved_dispatch.go gives the stitched export the live export's
// unresolved_dispatch verdict: a finding every route to which crosses a
// name_only edge reads unknown, never reachable. The stitch never traverses a
// name_only edge, so its own chains already hold without one. Two things can
// still say more, or less, than the typed graph proves: a dependency's
// mine-time entry-point index, whose depths the live tracer counted over
// name_only edges too, and a finding with no chain, which never said why it
// is unknown.

// UnresolvedReasonDispatch is the unresolved_reason of a finding whose every
// route crosses a name_only edge, the value the live export uses.
const UnresolvedReasonDispatch = "unresolved_dispatch"

// unresolvedDispatchOps returns the crypto operations the root component's
// functions reach only when name_only edges are admitted: no route over the
// traversed and ambiguous-dispatch edges, and one once name_only edges join.
// Ambiguous dispatch counts as typed, as it does in the live tracer: the
// receiver type is known, only the implementation is not.
func unresolvedDispatchOps(
	root ComponentKey,
	rootFragment Fragment,
	opsByNode map[graphNode][]CryptoOperation,
	adjacency, ambiguousCandidates, nameOnly map[graphNode][]adjacencyEdge,
) map[graphNode]bool {
	if len(nameOnly) == 0 {
		return nil
	}
	seeds := make(map[graphNode]bool, len(rootFragment.Functions))
	for i := range rootFragment.Functions {
		seeds[graphNode{Component: root, Function: rootFragment.Functions[i].Signature}] = true
	}
	typed := forwardReachableSetOver(seeds, adjacency, ambiguousCandidates)
	guessed := forwardReachableSetOver(seeds, adjacency, ambiguousCandidates, nameOnly)
	var out map[graphNode]bool
	for node := range opsByNode {
		if typed[node] || !guessed[node] {
			continue
		}
		if out == nil {
			out = make(map[graphNode]bool)
		}
		out[node] = true
	}
	return out
}

// forwardReachableSetOver is forwardReachableSet over the union of several
// adjacency maps.
func forwardReachableSetOver(sources map[graphNode]bool, maps ...map[graphNode][]adjacencyEdge) map[graphNode]bool {
	seen := make(map[graphNode]bool, len(sources))
	queue := make([]graphNode, 0, len(sources))
	for n := range sources {
		seen[n] = true
		queue = append(queue, n)
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, m := range maps {
			for _, edge := range m[n] {
				if !seen[edge.target] {
					seen[edge.target] = true
					queue = append(queue, edge.target)
				}
			}
		}
	}
	return seen
}

// markUnresolvedDispatch reads a finding the stitch could not prove reachable,
// and that the root reaches only over a name_only edge, as unknown with
// unresolved_dispatch. It runs after the composed upgrade, which skips such a
// finding (see upgradeComposedReachability).
func (r *Result) markUnresolvedDispatch(fg *ExportFindingGraph, anchor graphNode) {
	if fg == nil || !r.unresolvedDispatchOps[anchor] {
		return
	}
	if fg.Reachability == ReachabilityReachable || fg.Reachability == ReachabilityNotApplicable {
		return
	}
	fg.Reachability = ReachabilityUnknown
	fg.UnresolvedReason = UnresolvedReasonDispatch
}
