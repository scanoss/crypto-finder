package callgraph

import (
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/pkg/graphwalk"
)

// condensed.go answers two reachability questions over the live call graph that
// TraceBackLimited cannot (issue #249):
//
//	which functions reach this crypto      -> ReachingFunctions
//	how many distinct routes lead to it    -> TraceBackCondensed
//
// TraceBackLimited enqueues each function at most once and collects a chain only
// at a user boundary, so when two callers converge on the same function the first
// branch to arrive claims it and the other yields no chain at all. On the IBM
// redis-demo that drops jedis.set (line 83) while jedis.get (line 84) survives —
// and since crypto_entry_points was folded from the emitted chains, the dropped
// call disappeared from the published surface too.
//
// Enumerating every path instead is not available: the reverse-reachable subgraph
// is cyclic, so the route set is unbounded, and bounded to depth 32 the redis case
// alone has 5.4e23 walks (bcprov-jdk18on@1.84 peaks at 2.5e69). Almost all of that
// is one strongly connected cluster — a retry loop — traversed in every internal
// order, which tells a reader nothing new.
//
// Collapsing each cluster to a single node removes exactly that redundancy: the
// result is acyclic, so the route set is finite and countable in O(V+E). Measured:
// redis 5.4e23 -> 6 routes; bcprov 2.5e69 -> 7.4M worst case, with 83.5% of its
// 2472 findings at or under 128.
//
// The traversal itself lives in pkg/graphwalk, shared with the stitcher so the
// two reachability paths cannot drift apart; this file supplies the live graph's
// adjacency and materializes the results into CallChains.

// nodeLess orders function keys so every traversal is reproducible, and matches
// the caller ordering TraceBackLimited applies.
func nodeLess(a, b string) bool { return a < b }

// walkOptions describes the live call graph to pkg/graphwalk.
//
// With user packages known, a chain walks back through application code until
// it reaches a function no application code calls: that is where the program
// starts (main, a handler a framework invokes), and a chain that stops at the
// first application frame instead hides which entry point runs the crypto.
// Application functions therefore follow only their application callers
// (a library calling back into the application does not make the application
// function any less of a root), and one with none is a terminal. Library code
// follows every caller, and a library function nothing calls is a dead end.
// The target follows every caller either way: crypto in an application
// callback is reached through the library that calls it back.
//
// With no user packages known — the mine path, scanning a library alone — a
// graph root is where a chain ends, since for a library that is its public API.
//
// admit is the weakest edge evidence the walk follows: RouteEvidenceNameOnly
// follows every edge, RouteEvidenceDispatch drops name_only edges, and
// RouteEvidenceDirect drops dispatch edges too, leaving the routes that hold
// with every call statically resolved.
func (t *Tracer) walkOptions(targetKey string, userPackages map[string]bool, maxDepth int, admit RouteEvidence) graphwalk.Options[string] {
	callers := func(key string) []string { return t.knownCallers(key, targetKey, userPackages) }
	if admit != RouteEvidenceNameOnly {
		idx := t.edges()
		callers = func(key string) []string {
			known := t.knownCallers(key, targetKey, userPackages)
			if len(idx.pairs[key]) == 0 {
				return known
			}
			kept := known[:0]
			for _, caller := range known {
				if idx.admits(key, caller, admit) {
					kept = append(kept, caller)
				}
			}
			return kept
		}
	}
	opts := graphwalk.Options[string]{
		Callers:  callers,
		Less:     nodeLess,
		MaxDepth: maxDepth,
	}
	if userPackages == nil {
		opts.RootIsTerminal = true
		return opts
	}
	opts.RootTerminal = func(key string) bool { return t.isUserFunction(key, userPackages) }
	return opts
}

// knownCallers returns the declared callers of key; an application function
// other than the target keeps only its application callers, never itself.
func (t *Tracer) knownCallers(key, targetKey string, userPackages map[string]bool) []string {
	callers := t.graph.Callers[key]
	appOnly := userPackages != nil && key != targetKey && t.isUserFunction(key, userPackages)
	known := make([]string, 0, len(callers))
	for _, caller := range callers {
		if _, exists := t.graph.Functions[caller]; !exists {
			continue
		}
		if appOnly && (caller == key || !t.isUserFunction(caller, userPackages)) {
			continue
		}
		known = append(known, caller)
	}
	return known
}

func (t *Tracer) isUserFunction(key string, userPackages map[string]bool) bool {
	decl, ok := t.graph.Functions[key]
	return ok && isUserPackage(decl.ID.Package, userPackages, t.pkgSep)
}

// isUserType reports whether a fully qualified type belongs to the code whose
// entry points are being looked for: the user packages when known, otherwise
// any type the scanned sources declare.
func (t *Tracer) isUserType(typeName string, userPackages map[string]bool) bool {
	if userPackages == nil {
		_, declared := t.graph.SourceSupertypes[typeName]
		return declared
	}
	pkg := ""
	if dot := strings.LastIndex(typeName, t.pkgSep); dot >= 0 {
		pkg = typeName[:dot]
	}
	return isUserPackage(pkg, userPackages, t.pkgSep)
}

// reverseWalk is one finding function's backward walk: who reaches it, where
// each chain starts and why, and whether a limit cut any route.
type reverseWalk struct {
	reach     graphwalk.Reachable[string]
	condensed graphwalk.Condensed[string]
	rootKinds map[string]RootKind
	// truncated reports that the depth limit stopped the walk at a function
	// that is not a chain root, so routes through it were never seen.
	truncated bool
	// appCut reports that the depth limit made an application frame a root
	// (RootKindDepthLimit): the chain is real but shorter than the program.
	appCut bool
}

// walk runs the backward traversal from target and classifies its terminals.
//
// Three adjustments turn graphwalk's terminals into chain roots when user
// packages are known:
//
//   - an application frame the depth limit stopped is a root (depth_limit):
//     application code reaches the crypto, the chain is just shorter than the
//     program. A library frame the limit stopped makes the walk truncated.
//   - the target itself is a root when it is a recognized entry point that no
//     application code calls: a handler doing crypto inline. A target that is
//     not an entry and that nothing calls is dead code and stays unreachable.
//   - a cycle of application functions that nothing outside it calls has no
//     member without callers, so one member is made its root. Otherwise
//     mutual recursion would read as unreachable.
func (t *Tracer) walk(target FunctionID, userPackages map[string]bool, maxDepth int, admit RouteEvidence) reverseWalk {
	targetKey := target.String()
	reach := graphwalk.Reach(targetKey, t.walkOptions(targetKey, userPackages, maxDepth, admit))
	out := reverseWalk{reach: reach, rootKinds: map[string]RootKind{}}

	for key := range reach.Capped {
		if userPackages != nil && t.isUserFunction(key, userPackages) {
			reach.Terminal[key] = true
			out.rootKinds[key] = RootKindDepthLimit
			out.appCut = true
			continue
		}
		out.truncated = true
	}
	isUserType := func(typeName string) bool { return t.isUserType(typeName, userPackages) }
	if userPackages != nil && t.isUserFunction(targetKey, userPackages) &&
		len(t.knownCallers(targetKey, "", userPackages)) == 0 {
		if kind, ok := t.entryRootKind(t.graph.Functions[targetKey], isUserType); ok {
			reach.Terminal[targetKey] = true
			out.rootKinds[targetKey] = kind
		}
	}

	out.condensed = graphwalk.Condense(reach, nodeLess)
	if userPackages != nil {
		t.rootUncalledCycles(&out, targetKey, userPackages)
	}

	for key := range reach.Terminal {
		if _, classified := out.rootKinds[key]; classified {
			continue
		}
		kind, ok := t.entryRootKind(t.graph.Functions[key], isUserType)
		if !ok {
			kind = RootKindNoCallers
		}
		out.rootKinds[key] = kind
	}
	return out
}

// rootUncalledCycles gives a root to every cycle of application functions that
// no caller outside the cycle reaches: its first application member.
func (t *Tracer) rootUncalledCycles(w *reverseWalk, targetKey string, userPackages map[string]bool) {
	targetComp := w.condensed.Comp[targetKey]
	for comp, members := range w.condensed.Members {
		if comp == targetComp || len(members) < 2 || len(w.condensed.DAG[comp]) > 0 {
			continue
		}
		rooted := false
		for _, member := range members {
			if w.reach.Terminal[member] || w.reach.Capped[member] {
				rooted = true
				break
			}
		}
		if rooted {
			continue
		}
		for _, member := range members {
			if t.isUserFunction(member, userPackages) {
				w.reach.Terminal[member] = true
				break
			}
		}
	}
}

// IsUserPackage reports whether pkg belongs to user code, given the user package
// set and the ecosystem's package separator. Exported so the export layer can
// classify a reaching function without duplicating the sub-package prefix rule.
func IsUserPackage(pkg string, userPackages map[string]bool, sep string) bool {
	return isUserPackage(pkg, userPackages, sep)
}

// ReachingFunctions returns every function that reaches target, keyed by
// FunctionID.String(), with the minimum number of calls it takes to get there
// (0 for the target itself). terminals reports which of those are where a chain
// ends.
//
// This answers "which functions reach this crypto", which is a different question
// from "how do you get there" and must not be derived from the second: a set of
// reaching functions loses nothing to re-convergence or to a route budget, while a
// set of paths loses both. Cost is O(V+E).
func (t *Tracer) ReachingFunctions(
	target FunctionID,
	userPackages map[string]bool,
	maxDepth int,
) (depths map[string]int, terminals map[string]bool) {
	if _, exists := t.graph.Functions[target.String()]; !exists {
		return nil, nil
	}
	w := t.walk(target, userPackages, maxDepth, RouteEvidenceNameOnly)
	return w.reach.Depth, w.reach.Terminal
}

// CondensedTrace is TraceBackCondensed's answer for one function.
type CondensedTrace struct {
	// Chains holds the selected routes, ordered entry -> target, each stamped
	// with its RootKind.
	Chains []CallChain
	// Total is the number of (route, root) pairs the graph holds, counted
	// before any chain is built. It saturates at math.MaxInt.
	Total int
	// Truncated reports that the answer is incomplete: fewer chains than
	// Total were kept, or the depth limit stopped the walk somewhere, so some
	// routes were never seen or start at a depth_limit root.
	Truncated bool
	// DepthLimited reports the second cause alone. With no chain found it
	// means the verdict is unknown, not unreachable.
	DepthLimited bool
	// UnresolvedDispatch reports that every route found crosses at least one
	// name_only edge: a call linked to a same-named method whose class is not
	// proven to be a subtype of the receiver's type. Chains exist, but none
	// proves the target runs, so the verdict is unknown.
	UnresolvedDispatch bool
	// Evidence is the evidence of the strongest route found: direct when one
	// route resolves every call statically, dispatch when the best route needs
	// a dispatch edge, name_only (UnresolvedDispatch) when every route needs a
	// name_only edge. Chains holds the strongest routes first.
	Evidence RouteEvidence
	// NoCallersOnly reports that every root of the routes supporting the
	// verdict is an application function nothing calls (RootKindNoCallers):
	// the crypto is reached only from code with no known callers. The
	// supporting routes are those free of name_only edges, or every route when
	// none is.
	NoCallersOnly bool
}

// TraceBackCondensed walks callers of target over the cycle-collapsed reverse
// graph and returns up to maxChains chains, ordered entry -> target like
// TraceBackLimited. A maxChains of 0 means unlimited.
//
// Chains are selected strongest evidence first (selectTiered), and within one
// evidence tier one per root first, recognized entry points before other
// roots (graphwalk.Select), so a small budget shows the route that justifies
// the verdict and the distinct places the crypto is reached from rather than
// variations of one route.
func (t *Tracer) TraceBackCondensed(
	target FunctionID,
	userPackages map[string]bool,
	maxDepth, maxChains int,
) CondensedTrace {
	targetKey := target.String()
	if _, exists := t.graph.Functions[targetKey]; !exists {
		log.Debug().Str("target", targetKey).Msg("Target function not found in call graph")
		return CondensedTrace{}
	}

	w := t.walk(target, userPackages, maxDepth, RouteEvidenceNameOnly)
	out := CondensedTrace{DepthLimited: w.truncated, Truncated: w.truncated || w.appCut}
	if len(w.reach.Terminal) == 0 {
		// Nothing user code (or no graph root) reaches this function: the same
		// answer TraceBackLimited gives by returning no chains.
		return out
	}

	out.Total = graphwalk.Count(w.reach, w.condensed)
	walks := t.tierWalks(target, userPackages, maxDepth, &w)
	out.Evidence = strongestEvidence(walks)
	out.UnresolvedDispatch = out.Evidence == RouteEvidenceNameOnly
	out.NoCallersOnly = noCallersOnly(walks)
	out.Chains = t.selectTiered(walks, maxChains)
	if len(out.Chains) < out.Total {
		out.Truncated = true
	}
	return out
}

// materializeRoute turns a route — target first, terminal last — into a CallChain
// ordered entry -> target, stamping each step with the line where it calls the
// next one, the way enqueueCallers does.
func (t *Tracer) materializeRoute(route []string) CallChain {
	steps := make([]CallChainStep, 0, len(route))
	for i := len(route) - 1; i >= 0; i-- {
		steps = append(steps, t.buildStep(route, i))
	}
	return CallChain{Steps: steps}
}

func (t *Tracer) buildStep(route []string, i int) CallChainStep {
	key := route[i]
	decl := t.graph.Functions[key]
	step := CallChainStep{}
	if decl == nil {
		if id, err := ParseFunctionID(key); err == nil {
			step.Function = id
		}
		return step
	}
	step.Function = decl.ID
	step.FilePath = decl.FilePath
	if i == 0 {
		step.Line = decl.StartLine
		return step
	}
	// A classified pair names the call site of its strongest resolution, so
	// the frame's entry_resolution matches the evidence the route was chosen
	// by. Otherwise the first call to the callee is the site.
	if res, ok := t.edges().pairs[route[i-1]][key]; ok && res.line > 0 {
		step.Line, step.StartCol, step.EndCol = res.line, res.startCol, res.endCol
		return step
	}
	step.Line = findCallLine(decl, route[i-1])
	return step
}
