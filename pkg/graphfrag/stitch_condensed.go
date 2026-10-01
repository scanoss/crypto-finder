// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"strings"

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
//
// It rebuilds callers/inbounds from reverse on every call — fine for a single
// lookup, wasteful when traceBackward calls this once per crypto operation on a
// large component. condensedBackwardChainsFast takes those pre-built once and
// is what the hot loop actually uses; this wrapper stays for callers with only
// reverse in hand (tests, one-off lookups).
func condensedBackwardChains(
	opNode graphNode,
	reverse map[graphNode][]reverseEdge,
	entrySet map[graphNode]bool,
	maxChains int,
) (chains []backwardChain, total int, truncated bool) {
	callers, inbounds := flattenReverse(reverse)
	return condensedBackwardChainsFast(opNode, callers, inbounds, flattenDirectReverse(reverse), entrySet, maxChains)
}

// reverseView is one flattened reverse adjacency: the callers of each node
// and the call site of each edge.
type reverseView struct {
	callers  map[graphNode][]graphNode
	inbounds map[callSiteKey]inbound
}

// flattenDirectReverse is flattenReverse without the interface-dispatch
// edges: the routes whose every call resolved statically. It is nil when the
// graph has no dispatch edge, since it would then be the whole graph again.
func flattenDirectReverse(reverse map[graphNode][]reverseEdge) *reverseView {
	direct := make(map[graphNode][]reverseEdge, len(reverse))
	dispatch := false
	for target, edges := range reverse {
		kept := make([]reverseEdge, 0, len(edges))
		for _, edge := range edges {
			if edge.resolution == ResolutionInterfaceDispatch {
				dispatch = true
				continue
			}
			kept = append(kept, edge)
		}
		if len(kept) > 0 {
			direct[target] = kept
		}
	}
	if !dispatch {
		return nil
	}
	callers, inbounds := flattenReverse(direct)
	return &reverseView{callers: callers, inbounds: inbounds}
}

// flattenReverse converts the edge-list reverse adjacency into the plain
// caller lists and call-site index condensedBackwardChainsFast walks. Callers
// that invoke it once per traceBackward run (rather than once per operation)
// avoid rebuilding the same maps for every crypto op on the component.
func flattenReverse(reverse map[graphNode][]reverseEdge) (callers map[graphNode][]graphNode, inbounds map[callSiteKey]inbound) {
	callers = make(map[graphNode][]graphNode, len(reverse))
	inbounds = make(map[callSiteKey]inbound, len(reverse))
	for target, edges := range reverse {
		list := make([]graphNode, 0, len(edges))
		for _, edge := range edges {
			list = append(list, edge.caller)
			inbounds[callSiteKey{caller: edge.caller, target: target}] = edge.inbound
		}
		callers[target] = list
	}
	return callers, inbounds
}

// condensedBackwardChainsFast is condensedBackwardChains against pre-flattened
// callers/inbounds, so a caller walking many operations over the same reverse
// graph (traceBackward) builds them once instead of per operation.
//
// The budget goes to the strongest evidence first: the routes over direct,
// the graph without interface-dispatch edges, then the remaining routes. A
// route whose every call resolved statically is therefore always kept when
// one exists. direct is nil when the graph has no dispatch edge. total counts
// the routes of the whole graph.
func condensedBackwardChainsFast(
	opNode graphNode,
	callers map[graphNode][]graphNode,
	inbounds map[callSiteKey]inbound,
	direct *reverseView,
	entrySet map[graphNode]bool,
	maxChains int,
) (chains []backwardChain, total int, truncated bool) {
	maxChains = ResolveMaxChains(maxChains)
	reach, condensed, ok := backwardReach(opNode, callers, entrySet)
	if !ok {
		return nil, 0, false
	}
	total = graphwalk.Count(reach, condensed)

	taken := make(map[string]bool)
	take := func(route []graphNode, inbounds map[callSiteKey]inbound) bool {
		key := routeNodesKey(route)
		if !taken[key] {
			taken[key] = true
			chains = append(chains, materializeBackwardChain(route, inbounds))
		}
		return len(chains) < maxChains
	}
	if direct != nil {
		if dReach, dCondensed, ok := backwardReach(opNode, direct.callers, entrySet); ok {
			for _, route := range graphwalk.Routes(dReach, dCondensed, maxChains) {
				take(route, direct.inbounds)
			}
		}
	}
	if len(chains) < maxChains {
		// The whole graph yields the direct routes again; a budget of
		// maxChains leaves room for every chain still missing.
		for _, route := range graphwalk.Routes(reach, condensed, maxChains) {
			if !take(route, inbounds) {
				break
			}
		}
	}
	return chains, total, len(chains) < total
}

// backwardReach walks callers back from opNode to the entries; ok is false
// when no entry is reached.
func backwardReach(
	opNode graphNode,
	callers map[graphNode][]graphNode,
	entrySet map[graphNode]bool,
) (graphwalk.Reachable[graphNode], graphwalk.Condensed[graphNode], bool) {
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
		return reach, graphwalk.Condensed[graphNode]{}, false
	}
	return reach, graphwalk.Condense(reach, nodeLess), true
}

// routeNodesKey identifies a concrete route by its nodes.
func routeNodesKey(route []graphNode) string {
	var b strings.Builder
	for _, node := range route {
		b.WriteString(node.Component.String())
		b.WriteByte(0)
		b.WriteString(node.Function)
		b.WriteByte(0)
	}
	return b.String()
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
