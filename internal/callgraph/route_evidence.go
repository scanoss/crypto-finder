package callgraph

import (
	"strings"

	"github.com/scanoss/crypto-finder/pkg/graphwalk"
)

// RouteEvidence says how strongly a route's calls were resolved: by its
// weakest edge, since a route holds only as well as its least certain call.
type RouteEvidence string

const (
	// RouteEvidenceDirect is a route whose every call resolved to its target
	// statically: an exact call, or one with no recorded resolution.
	RouteEvidenceDirect RouteEvidence = "direct"
	// RouteEvidenceDispatch is a route that needs at least one call linked to
	// an implementation of the receiver's declared type (interface_dispatch or
	// python_subclass_dispatch), and no name_only call.
	RouteEvidenceDispatch RouteEvidence = "dispatch"
	// RouteEvidenceNameOnly is a route that needs at least one call linked to
	// a same-named method of a class not proven to be a subtype of the
	// receiver's type.
	RouteEvidenceNameOnly RouteEvidence = "name_only"
)

// weakness orders evidence from the strongest (0) to the weakest.
func (e RouteEvidence) weakness() int {
	switch e {
	case RouteEvidenceDirect:
		return 0
	case RouteEvidenceDispatch:
		return 1
	case RouteEvidenceNameOnly:
		return 2
	default:
		return 2
	}
}

// StrongerThan reports whether e is better evidence than other.
func (e RouteEvidence) StrongerThan(other RouteEvidence) bool {
	return e.weakness() < other.weakness()
}

// edgeKindEvidence is the evidence one edge lends a route.
func edgeKindEvidence(kind EdgeKind) RouteEvidence {
	switch kind {
	case EdgeKindNameOnly:
		return RouteEvidenceNameOnly
	case EdgeKindInterfaceDispatch, EdgeKindPythonSubclassDispatch:
		return RouteEvidenceDispatch
	case EdgeKindExact:
		return RouteEvidenceDirect
	default:
		return RouteEvidenceDirect
	}
}

// pairResolution is the strongest recorded resolution of one caller->callee
// pair and the call site it was recorded at. A chain step names that site, so
// the entry_resolution the export stamps on the frame agrees with the
// evidence the route was selected by.
type pairResolution struct {
	kind                   EdgeKind
	line, startCol, endCol int
}

// edgeIndex holds, per callee and then caller, the strongest recorded
// resolution of every pair the builder classified. A pair with no entry is an
// exact source call. Built on first use.
type edgeIndex struct {
	pairs       map[string]map[string]pairResolution
	hasDispatch bool
	hasNameOnly bool
}

func (t *Tracer) edges() *edgeIndex {
	if t.edgeIdx != nil {
		return t.edgeIdx
	}
	idx := &edgeIndex{pairs: make(map[string]map[string]pairResolution)}
	for key := range t.graph.EdgeResolutions {
		res := t.graph.EdgeResolutions[key]
		caller, callee, ok := EdgeResolutionEndpoints(key, res)
		if !ok {
			continue
		}
		byCaller := idx.pairs[callee]
		if byCaller == nil {
			byCaller = make(map[string]pairResolution)
			idx.pairs[callee] = byCaller
		}
		candidate := pairResolution{kind: res.Kind, line: res.CallSite, startCol: res.StartCol, endCol: res.EndCol}
		if current, seen := byCaller[caller]; !seen || strongerPairResolution(candidate, current) {
			byCaller[caller] = candidate
		}
	}
	for _, byCaller := range idx.pairs {
		for _, res := range byCaller {
			switch edgeKindEvidence(res.kind) {
			case RouteEvidenceDispatch:
				idx.hasDispatch = true
			case RouteEvidenceNameOnly:
				idx.hasNameOnly = true
			case RouteEvidenceDirect:
			}
		}
	}
	t.edgeIdx = idx
	return idx
}

// strongerPairResolution orders a pair's recorded resolutions: the most
// certain kind first, then the earliest call site, so the choice is
// reproducible whatever the map order.
func strongerPairResolution(a, b pairResolution) bool {
	if ra, rb := edgeKindRank(a.kind), edgeKindRank(b.kind); ra != rb {
		return ra > rb
	}
	if a.line != b.line {
		return a.line < b.line
	}
	if a.startCol != b.startCol {
		return a.startCol < b.startCol
	}
	return a.endCol < b.endCol
}

// admits reports whether a walk admitting edges up to evidence may follow
// caller -> callee.
func (idx *edgeIndex) admits(callee, caller string, evidence RouteEvidence) bool {
	res, recorded := idx.pairs[callee][caller]
	return !recorded || edgeKindEvidence(res.kind).weakness() <= evidence.weakness()
}

// tierWalk is one walk restricted to edges of at least some evidence.
type tierWalk struct {
	evidence RouteEvidence
	walk     *reverseWalk
}

// tierWalks returns the walks a finding's chains are chosen from, strongest
// evidence first and the unrestricted walk full last. A walk equal to a
// looser one by construction (the graph has no edge of the kind it drops) is
// that walk, not a second run.
func (t *Tracer) tierWalks(target FunctionID, userPackages map[string]bool, maxDepth int, full *reverseWalk) []tierWalk {
	idx := t.edges()
	typed := full
	if idx.hasNameOnly {
		w := t.walk(target, userPackages, maxDepth, RouteEvidenceDispatch)
		typed = &w
	}
	direct := typed
	if idx.hasDispatch {
		w := t.walk(target, userPackages, maxDepth, RouteEvidenceDirect)
		direct = &w
	}
	return []tierWalk{
		{RouteEvidenceDirect, direct},
		{RouteEvidenceDispatch, typed},
		{RouteEvidenceNameOnly, full},
	}
}

// reaches reports whether a walk proves the target reachable at its evidence:
// a root was found, or the depth limit stopped it before one could be.
//
// A walk the depth limit cut counts as reaching. The cut hides routes the walk
// never saw, so it cannot show that only weaker routes exist, and a finding
// would otherwise flip to unresolved dispatch arbitrarily with the depth
// limit. Only a walk that ran to completion and found no root rules its tier out.
func (w *reverseWalk) reaches() bool {
	return len(w.reach.Terminal) > 0 || w.truncated
}

// strongestEvidence is the evidence of the first walk that reaches the target.
func strongestEvidence(walks []tierWalk) RouteEvidence {
	for _, tw := range walks {
		if tw.walk.reaches() {
			return tw.evidence
		}
	}
	return RouteEvidenceNameOnly
}

// noCallersOnly reports whether every root of the routes that support the
// verdict is an application function nothing calls (RootKindNoCallers). The
// supporting routes are those free of name_only edges when there are any, and
// every route otherwise.
func noCallersOnly(walks []tierWalk) bool {
	supporting := walks[len(walks)-1].walk
	for _, tw := range walks {
		if tw.evidence == RouteEvidenceDispatch && tw.walk.reaches() {
			supporting = tw.walk
			break
		}
	}
	if len(supporting.reach.Terminal) == 0 {
		return false
	}
	for key := range supporting.reach.Terminal {
		if supporting.rootKinds[key] != RootKindNoCallers {
			return false
		}
	}
	return true
}

// selectTiered spends the chain budget strongest evidence first: every route
// the direct walk selects (one per root first, then further routes), then
// those the dispatch walk adds, then the rest. The route that justifies the
// verdict is therefore always kept. A maxChains of 0 means unlimited.
func (t *Tracer) selectTiered(walks []tierWalk, maxChains int) []CallChain {
	var out []CallChain
	taken := make(map[string]bool)
	full := func() bool { return maxChains > 0 && len(out) >= maxChains }
	var previous *reverseWalk
	for _, tw := range walks {
		w := tw.walk
		if full() {
			break
		}
		if w == previous || len(w.reach.Terminal) == 0 {
			previous = w
			continue
		}
		previous = w
		// A looser walk selects the stricter walks' routes again; asking for
		// the whole budget leaves room for maxChains-len(out) new ones.
		for _, route := range graphwalk.Select(w.reach, w.condensed, maxChains, w.rootLess) {
			key := strings.Join(route, "\x00")
			if taken[key] {
				continue
			}
			taken[key] = true
			chain := t.materializeRoute(route)
			chain.RootKind = w.rootKinds[route[len(route)-1]]
			out = append(out, chain)
			if full() {
				break
			}
		}
	}
	return out
}

// rootLess orders a walk's roots for graphwalk.Select: recognized entry
// points first, then the nearest, then by name.
func (w *reverseWalk) rootLess(a, b string) bool {
	ra, rb := rootKindRank(w.rootKinds[a]), rootKindRank(w.rootKinds[b])
	if ra != rb {
		return ra < rb
	}
	if da, db := w.reach.Depth[a], w.reach.Depth[b]; da != db {
		return da < db
	}
	return a < b
}
