// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"github.com/scanoss/crypto-finder/pkg/graphwalk"
)

// stitch_condensed.go enumerates the served call chains over the cycle-collapsed
// reverse graph, so the stitcher reports the same routes the live exporter does
// (issue #249).
//
// backwardBFS enqueues each node once and collects a chain only at an entry, so
// when two callers converge on the same node the first branch to arrive claims it
// and the other yields no chain. On the diamond fixture that is two routes
// reported out of four; live, walking the collapsed graph, reports all four. Both
// walk the same map — the divergence is the algorithm, not the data.
//
// Cycles are why the collapse is needed before enumerating at all: without it the
// route set is unbounded, since a cluster of mutually recursive functions can be
// traversed in every internal order. The traversal is shared with the live path
// through pkg/graphwalk; this file supplies the stitched adjacency and rebuilds
// backwardChain — including each frame's inbound call site — so emitChain is
// untouched.

// nodeLess orders stitched nodes exactly as reverseAdjacency does, keeping every
// traversal reproducible.
func nodeLess(a, b graphNode) bool {
	if a.Function != b.Function {
		return a.Function < b.Function
	}
	return a.Component.String() < b.Component.String()
}

// callSiteKey identifies one forward edge: the caller and the node it calls.
type callSiteKey struct {
	caller, target graphNode
}

// condensedBackwardChains returns one chain per (route, entry) pair plus the exact
// total, counted before any chain is built so a truncated result can state how
// much it left out.
func condensedBackwardChains(
	opNode graphNode,
	reverse map[graphNode][]reverseEdge,
	entrySet map[graphNode]bool,
) (chains []backwardChain, total int, truncated bool) {
	callers := make(map[graphNode][]graphNode, len(reverse))
	inbounds := make(map[callSiteKey]inbound, len(reverse))
	for target, edges := range reverse {
		list := make([]graphNode, 0, len(edges))
		for _, edge := range edges {
			list = append(list, edge.caller)
			inbounds[callSiteKey{caller: edge.caller, target: target}] = edge.inbound
		}
		callers[target] = list
	}

	reach := graphwalk.Reach(opNode, graphwalk.Options[graphNode]{
		Callers:    func(n graphNode) []graphNode { return callers[n] },
		Less:       nodeLess,
		IsBoundary: func(n graphNode) bool { return entrySet[n] },
		// An entry is the boundary here; a node with no callers that is not an
		// entry means nothing root-side reaches the operation, which mirrors
		// live's "chain never reached user code" drop.
		RootIsTerminal: false,
		MaxDepth:       stitchMaxDepth,
	})
	if len(reach.Terminal) == 0 {
		return nil, 0, false
	}

	condensed := graphwalk.Condense(reach, nodeLess)
	total = graphwalk.Count(reach, condensed)
	for _, route := range graphwalk.Routes(reach, condensed, stitchMaxChainsPerOp) {
		chains = append(chains, materializeBackwardChain(route, inbounds))
	}
	return chains, total, len(chains) < total
}

// materializeBackwardChain reverses a route — target first, entry last — into the
// entry->op order emitChain expects, stamping each frame with the call site of the
// edge that arrives at it. The head frame has no inbound edge, so its entry call
// is nil, exactly as the incremental walk left it.
func materializeBackwardChain(route []graphNode, inbounds map[callSiteKey]inbound) backwardChain {
	nodes := make([]graphNode, 0, len(route))
	for i := len(route) - 1; i >= 0; i-- {
		nodes = append(nodes, route[i])
	}

	stamped := make([]inbound, len(nodes))
	for i := 1; i < len(nodes); i++ {
		stamped[i] = inbounds[callSiteKey{caller: nodes[i-1], target: nodes[i]}]
	}
	return backwardChain{nodes: nodes, inbounds: stamped}
}
