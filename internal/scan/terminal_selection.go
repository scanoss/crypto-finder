// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

// candidateView is the minimal per-call identity the position-based terminal
// selection needs: the call expression's columns, its fluent-chain grouping, the
// variable its result binds to, and the length of its raw expression. The live
// exporter projects it from *callgraph.FunctionCall (callCandidateViews) and the
// annotate-from-cache path projects it from a graph-fragment edge
// (edgeCandidateViews), so BOTH run the IDENTICAL tightest-span + chain-root
// selection policy. This is the single source of truth for "which
// call on this line is the terminal crypto operation"; keeping the policy here
// (not duplicated per path) is what guarantees cache-derived supporting calls
// match a live scan on nested / multi-call / fluent-chain lines.
type candidateView struct {
	StartCol    int
	EndCol      int
	ChainID     string
	AssignedVar string
	RawLen      int
}

// identityIndices returns [0, 1, ..., n-1] — the full candidate set, used when a
// path wants to run the selection over every candidate.
func identityIndices(n int) []int {
	idxs := make([]int, n)
	for i := range idxs {
		idxs[i] = i
	}
	return idxs
}

// columnFilterIndices keeps the candidates (from idxs) whose [StartCol, EndCol)
// half-open span intersects the asset's [assetStartCol, assetEndCol) span. When
// nested calls both intersect, it keeps the tightest call span that contains the
// complete asset span. Candidates from that call's fluent chain stay eligible so
// the existing chain-root tie-break still applies.
//
// It falls back to the input idxs unchanged (line-only behavior, never worse)
// when the asset carries no columns, or when no surviving candidate carries
// columns / intersects — e.g. legacy fragments exported before columns were
// threaded, where every edge's columns are 0.
func columnFilterIndices(views []candidateView, idxs []int, assetStartCol, assetEndCol int) []int {
	if assetStartCol <= 0 || assetEndCol <= 0 {
		return idxs
	}
	filtered := make([]int, 0, len(idxs))
	for _, i := range idxs {
		v := views[i]
		if v.StartCol <= 0 || v.EndCol <= 0 {
			continue
		}
		// Half-open intersection: [v.StartCol, v.EndCol) ∩ [assetStartCol, assetEndCol)
		if v.StartCol < assetEndCol && assetStartCol < v.EndCol {
			filtered = append(filtered, i)
		}
	}
	if len(filtered) == 0 {
		return idxs
	}
	return tightestContainingIndices(views, filtered, assetStartCol, assetEndCol)
}

func tightestContainingIndices(views []candidateView, idxs []int, assetStartCol, assetEndCol int) []int {
	best := -1
	for _, i := range idxs {
		v := views[i]
		if v.StartCol > assetStartCol || v.EndCol < assetEndCol {
			continue
		}
		if best == -1 || v.EndCol-v.StartCol < views[best].EndCol-views[best].StartCol {
			best = i
		}
	}
	if best == -1 {
		return idxs
	}

	minSpan := views[best].EndCol - views[best].StartCol
	chainID := views[best].ChainID
	tightest := make([]int, 0, len(idxs))
	for _, i := range idxs {
		v := views[i]
		if v.StartCol > assetStartCol || v.EndCol < assetEndCol {
			continue
		}
		if v.EndCol-v.StartCol == minSpan || chainID != "" && v.ChainID == chainID {
			tightest = append(tightest, i)
		}
	}
	return tightest
}

// chainRootIndexAmong returns the index (drawn from idxs) of the fluent-chain
// root: a chain candidate (ChainID != "") that binds its result to a variable
// (AssignedVar != ""), tie-broken by lowest StartCol then slice order. Returns -1
// when no candidate qualifies. The chain root is required because object-lifecycle
// derivation keys off the root's AssignedVar/ChainID.
func chainRootIndexAmong(views []candidateView, idxs []int) int {
	best := -1
	for _, i := range idxs {
		v := views[i]
		if v.ChainID == "" || v.AssignedVar == "" {
			continue
		}
		if best == -1 || v.StartCol < views[best].StartCol {
			best = i
		}
	}
	return best
}

// longestChainIndexAmong returns the index (drawn from idxs) of the chain
// candidate with the longest raw expression — the outermost fluent link, the
// actual terminal of a chain. Returns -1 when no chain candidate is present. Used
// as the fallback when no chain candidate carries AssignedVar.
func longestChainIndexAmong(views []candidateView, idxs []int) int {
	best := -1
	for _, i := range idxs {
		v := views[i]
		if v.ChainID == "" {
			continue
		}
		if best == -1 || v.RawLen > views[best].RawLen {
			best = i
		}
	}
	return best
}

// lowestStartColIndexAmong returns the index (drawn from idxs) with the lowest
// non-zero StartCol, falling back to the first index. It is the deterministic
// final tie-break shared by both paths when neither columns nor chain structure
// single out a candidate.
func lowestStartColIndexAmong(views []candidateView, idxs []int) int {
	if len(idxs) == 0 {
		return -1
	}
	best := idxs[0]
	for _, i := range idxs[1:] {
		if views[i].StartCol > 0 && (views[best].StartCol == 0 || views[i].StartCol < views[best].StartCol) {
			best = i
		}
	}
	return best
}
