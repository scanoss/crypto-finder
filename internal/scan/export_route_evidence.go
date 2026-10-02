// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"github.com/scanoss/crypto-finder/internal/callgraph"
)

// rootKindNoCallers is the root_kind of a chain whose first frame is an
// application function nothing calls.
const rootKindNoCallers = string(callgraph.RootKindNoCallers)

// reviseRouteEvidence replaces what the containing function's unfiltered trace
// recorded (route_evidence, no_callers_only) with what the finding's surviving
// chains show. A parameter condition drops the chains that carry another call's
// value, and the trace cached per function rated the routes of every value
// together: a finding whose condition refutes the direct route would otherwise
// still read direct. With no chain left there is no route to rate, so both
// fields stay empty.
//
// The surviving chains are a bounded sample, so the revision rates the routes
// the finding exports, not every route the graph holds.
//
// It acts only when narrowed: the condition dropped chains of a traced finding.
func reviseRouteEvidence(fg *callGraphExportFinding, narrowed bool) {
	if !narrowed || fg.Analysis == nil {
		return
	}
	fg.Analysis.RouteEvidence = ""
	fg.Analysis.NoCallersOnly = false
	if len(fg.CallChains) == 0 {
		return
	}
	best, noCallersOnly := rateRoutes(fg.CallChains)
	fg.Analysis.RouteEvidence = string(best)
	fg.Analysis.NoCallersOnly = noCallersOnly
}

// rateRoutes rates a set of chains the way the tracer rates a function's
// routes: the evidence of the strongest chain, and whether every chain that
// supports it starts at an application function nothing calls. The supporting
// chains are those free of name_only edges, or every chain when each needs one.
func rateRoutes(chains [][]callGraphChainNode) (best callgraph.RouteEvidence, noCallersOnly bool) {
	evidence := make([]callgraph.RouteEvidence, len(chains))
	best = callgraph.RouteEvidenceNameOnly
	for i, chain := range chains {
		evidence[i] = chainRouteEvidence(chain)
		if evidence[i].StrongerThan(best) {
			best = evidence[i]
		}
	}
	supporting, noCallers := 0, 0
	for i, chain := range chains {
		if best != callgraph.RouteEvidenceNameOnly && evidence[i] == callgraph.RouteEvidenceNameOnly {
			continue
		}
		supporting++
		if len(chain) > 0 && chain[0].RootKind == rootKindNoCallers {
			noCallers++
		}
	}
	return best, supporting > 0 && noCallers == supporting
}

// chainRouteEvidence rates one chain by its weakest frame: how the call
// arriving at each frame after the first was resolved. A frame with no
// recorded resolution is a direct call.
func chainRouteEvidence(chain []callGraphChainNode) callgraph.RouteEvidence {
	weakest := callgraph.RouteEvidenceDirect
	for i := range chain {
		var frame callgraph.RouteEvidence
		switch chain[i].EntryResolution {
		case string(callgraph.EdgeKindNameOnly):
			frame = callgraph.RouteEvidenceNameOnly
		case string(callgraph.EdgeKindInterfaceDispatch), string(callgraph.EdgeKindPythonSubclassDispatch):
			frame = callgraph.RouteEvidenceDispatch
		default:
			frame = callgraph.RouteEvidenceDirect
		}
		if weakest.StrongerThan(frame) {
			weakest = frame
		}
	}
	return weakest
}
