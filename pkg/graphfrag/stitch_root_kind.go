// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

// Root kinds a stitched chain's first frame can carry (ExportChainNode.RootKind).
// They mirror the live callgraph export. The stitched export never says
// depth_limit: its walk has no depth limit.
const (
	// RootKindMain is a program entry point.
	RootKindMain = "main"
	// RootKindFrameworkEntry is a function a framework or the runtime calls.
	RootKindFrameworkEntry = "framework_entry"
	// RootKindNoCallers is a root-component function nothing in the stitched
	// graph calls and the producer did not recognize as an entry point.
	RootKindNoCallers = "no_callers"
)

// classifyRootKinds gives each chain root its root_kind: the entry kind its
// fragment recorded, else no_callers when the fragment recorded entry kinds at
// all. A root of a fragment without entry-kind data (graph-fragment-1.13 and
// older) gets no kind: the function may well be a framework entry the
// producer could not mark, so reading it as no_callers would understate it.
func classifyRootKinds(rootFragment *Fragment, roots []graphNode) map[graphNode]string {
	kinds := make(map[graphNode]string, len(roots))
	for _, node := range roots {
		switch kind := rootFragment.EntryKinds[node.Function]; {
		case kind == RootKindMain || kind == RootKindFrameworkEntry:
			kinds[node] = kind
		case kind == "" && rootFragment.EntryKinds != nil:
			kinds[node] = RootKindNoCallers
		}
	}
	return kinds
}

// noCallersOnly reports whether every root that reaches the anchor is a
// no_callers root, which is the live export's analysis.no_callers_only: the
// crypto is reached only from application code nothing calls. The stitched
// graph holds no name_only edge, so its roots are the live "supporting" ones.
//
// The anchor itself is not a root when nothing calls it and it is no entry
// point (dead code, not a route). A root with no recorded kind, or an entry
// kind, makes the answer false, so does having no root at all.
func (r *Result) noCallersOnly(anchor graphNode) bool {
	if r.rootKinds == nil || r.composedRouteChains[anchor] {
		return false
	}
	roots := 0
	reach := r.reachByAnchor[anchor]
	for i := range reach {
		entry := &reach[i]
		if !entry.root {
			continue
		}
		node := graphNode{Component: entry.frame.Component, Function: entry.frame.Signature}
		kind := r.rootKinds[node]
		if node == anchor && kind == RootKindNoCallers {
			continue
		}
		if kind != RootKindNoCallers {
			return false
		}
		roots++
	}
	return roots > 0
}
