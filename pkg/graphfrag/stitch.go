// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"sort"
	"strings"
)

// StitchOptions tunes which root-fragment functions a stitch traces from. The
// zero value reproduces the historical Stitch behavior (trace from every
// root-fragment function), so adding fields here never changes existing callers.
type StitchOptions struct {
	// EntryRootedOnly, when true, traces only from root-fragment functions that
	// have NO incoming edge in the dependency-closure adjacency (in-degree 0) —
	// the graph's entry points. Tracing from every one of an 18k-function
	// library's functions is intractable and, for serving, redundant: a finding
	// reachable from a non-entry function is still reachable from the entry that
	// calls it, so the set of reachable terminal findings is preserved while the
	// number of traced roots collapses to the true entry points.
	EntryRootedOnly bool

	// ForwardClosure, when true, additionally computes a per-finding-anchor
	// forward reachability graph (see forwardClosure) and carries it on
	// Result.forwardClosures for ToCallgraphExport to project as the
	// `forward_calls` block. Zero value (false) is OFF: no forward traversal
	// runs, no allocation happens, and served output is byte-identical to the
	// pre-forward-closure shape (modulo the reviewed schema_version bump).
	ForwardClosure bool

	// MaxForwardDepth caps the forward BFS depth (hops from the anchor). Zero
	// resolves to defaultMaxForwardDepth.
	MaxForwardDepth int
	// MaxForwardNodesPerAnchor caps the number of distinct forward-reachable
	// nodes retained per anchor. Zero resolves to defaultMaxForwardNodesPerAnchor.
	MaxForwardNodesPerAnchor int
	// MaxForwardEdgesPerAnchor caps the number of forward edges retained per
	// anchor. Zero resolves to defaultMaxForwardEdgesPerAnchor.
	MaxForwardEdgesPerAnchor int
}

// Defaults applied by forwardCapsFrom when the corresponding StitchOptions
// field is left at its zero value.
const (
	defaultMaxForwardDepth          = 4
	defaultMaxForwardNodesPerAnchor = 256
	defaultMaxForwardEdgesPerAnchor = 512
)

// forwardCaps is the resolved (zero-values-defaulted) cap set for one
// buildForwardClosures run.
type forwardCaps struct {
	maxDepth int
	maxNodes int
	maxEdges int
}

// forwardCapsFrom resolves opts' forward-closure caps, defaulting any
// zero-value field.
func forwardCapsFrom(opts StitchOptions) forwardCaps {
	caps := forwardCaps{
		maxDepth: opts.MaxForwardDepth,
		maxNodes: opts.MaxForwardNodesPerAnchor,
		maxEdges: opts.MaxForwardEdgesPerAnchor,
	}
	if caps.maxDepth == 0 {
		caps.maxDepth = defaultMaxForwardDepth
	}
	if caps.maxNodes == 0 {
		caps.maxNodes = defaultMaxForwardNodesPerAnchor
	}
	if caps.maxEdges == 0 {
		caps.maxEdges = defaultMaxForwardEdgesPerAnchor
	}
	return caps
}

// forwardClosure is the rooted forward call graph from ONE finding anchor
// node, computed once per distinct anchor (memoized in
// Result.forwardClosures). Pre-projection model — ToCallgraphExport projects
// it into the exported forward_calls shape.
type forwardClosure struct {
	anchor    CallFrame     // resolved anchor identity (depth 0); reuses buildFrame output
	nodes     []forwardNode // forward-reachable nodes, depth >= 1, deduped by graphNode
	edges     []forwardEdge // directed traversed edges (endpoints always in {anchor} ∪ nodes)
	maxDepth  int           // the depth CAP applied (== resolved MaxForwardDepth)
	truncated bool          // any cap hit (depth/node/edge) -> true; never silent
}

// forwardNode is one forward-reachable node (depth >= 1) in a forwardClosure.
type forwardNode struct {
	node               graphNode // internal identity (Component+Function)
	frame              CallFrame // resolved via buildFrame (Function identity + Module)
	depth              int       // shortest-path hops from anchor (BFS layer)
	cryptoRelevant     bool      // node ∈ opsByNode OR has non-empty supporting Category
	supportingCategory string    // first non-empty supportingByNode[node].Category
}

// forwardEdge is one directed traversed edge (from -> to) in a forwardClosure.
type forwardEdge struct {
	from      graphNode
	to        graphNode
	entryCall *CallSite // the (from->to) call site: line + resolved-value Parameters
}

// Stitch composes reusable component graph fragments into root-to-crypto
// reachability chains for root.
//
// This is the pure graph algorithm. It deliberately does not know about
// storage, compression, or HTTP response DTOs. It traces from every
// root-fragment function; for entry-point-only rooting use StitchWithOptions.
func Stitch(root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment) (*Result, error) {
	return StitchWithOptions(root, deps, fragments, StitchOptions{})
}

// StitchWithOptions is Stitch with an explicit rooting policy. See StitchOptions.
func StitchWithOptions(root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment, opts StitchOptions) (*Result, error) {
	closure := dependencyClosure(root, deps)
	missing := missingFragments(closure, fragments)
	if len(missing) > 0 {
		return nil, &ErrMissingFragment{Components: missing}
	}

	functionsBySignature := indexFunctions(closure, fragments)
	adjacency, suppressed := buildAdjacency(closure, deps, fragments, functionsBySignature)
	opsByNode := indexCryptoOperations(closure, fragments)
	supportingByNode := indexSupportingCalls(closure, fragments)

	rootFragment := fragments[root]
	roots := rootNodes(root, rootFragment, adjacency, opts.EntryRootedOnly)

	out := Result{Suppressed: suppressed}
	if opts.EntryRootedOnly {
		// Serving path. Mirror live `--export-callgraph` (TraceBackLimited): a
		// backward BFS from each crypto op with a per-op graph-global frontier set.
		// This is O(V+E) per op (no per-path visited clone) and collapses
		// re-convergent (diamond) branches to a single representative, so the served
		// callgraph matches live byte-for-byte (the parity contract) and stays
		// bounded on high-fan-in libraries (BouncyCastle, 18k functions) where the
		// old all-simple-paths forward DFS hangs.
		traceBackward(adjacency, opsByNode, supportingByNode, fragments, roots, &out)
		attachAnnotationSupportingCalls(closure, fragments, &out)
		if opts.ForwardClosure {
			out.forwardClosures = buildForwardClosures(adjacency, opsByNode, supportingByNode, fragments, forwardCapsFrom(opts))
		}
		return &out, nil
	}

	// Historical full-rooting path (Stitch / EntryRootedOnly=false): trace forward
	// from every root-fragment function, emitting a chain rooted at each ancestor of
	// each op. This is the documented zero-value behavior pinned by the resolution
	// fail-closed and parallel-edge tests; it is NOT under the live parity contract
	// (that contract is the serving path above) and keeps its exact prior output.
	for _, start := range roots {
		trace(start, adjacency, opsByNode, supportingByNode, fragments, nil, nil, map[graphNode]bool{}, &out)
	}
	attachAnnotationSupportingCalls(closure, fragments, &out)
	if opts.ForwardClosure {
		out.forwardClosures = buildForwardClosures(adjacency, opsByNode, supportingByNode, fragments, forwardCapsFrom(opts))
	}
	return &out, nil
}

// attachAnnotationSupportingCalls resolves each surviving finding's
// supporting_call_ids (the per-finding FK the fragment's crypto annotation
// declares) against the closure's supporting-call pool, adding any the chain
// traversal did not already emit.
//
// flushSupportingCalls only emits supporting calls for nodes that appear on a
// backward chain to a crypto op. Contract/lifecycle supporting calls — e.g.
// Password4J's Password.hash / addRandomSalt / Hash.getResult, attached to a
// synthesized terminal by deriveContractSupportingCalls at export time — are
// upstream public-API callers that are NOT on any backward chain from the
// terminal (the terminal has in-degree 0), so traversal alone silently drops
// them and their supporting_call_ids dangle against an empty pool. Honoring the
// fragment's pre-computed FK here is what makes the served callgraph match a
// live --export-callgraph (which carries them in supporting_calls).
func attachAnnotationSupportingCalls(closure []ComponentKey, fragments map[ComponentKey]Fragment, out *Result) {
	byID := indexAnnotationSupportingCalls(closure, fragments)
	if len(byID) == 0 {
		return
	}
	seen := indexResultSupportingCalls(out)
	attachMissingAnnotationSupportingCalls(byID, seen, out)
}

func indexAnnotationSupportingCalls(closure []ComponentKey, fragments map[ComponentKey]Fragment) map[string]SupportingCall {
	byID := make(map[string]SupportingCall)
	for _, key := range closure {
		fragment := fragments[key]
		for i := range fragment.SupportingCalls {
			sc := fragment.SupportingCalls[i]
			if sc.SupportingID == "" {
				continue
			}
			if _, ok := byID[sc.SupportingID]; !ok {
				byID[sc.SupportingID] = sc
			}
		}
	}
	return byID
}

func indexResultSupportingCalls(out *Result) map[string]bool {
	seen := make(map[string]bool, len(out.SupportingCalls))
	for i := range out.SupportingCalls {
		if id := out.SupportingCalls[i].SupportingID; id != "" {
			seen[id] = true
		}
	}
	return seen
}

func attachMissingAnnotationSupportingCalls(
	byID map[string]SupportingCall,
	seen map[string]bool,
	out *Result,
) {
	for i := range out.Chains {
		op := out.Chains[i].CryptoOp
		if op == nil {
			continue
		}
		appendMissingSupportingCalls(op.SupportingCallIDs, byID, seen, out)
	}
}

func appendMissingSupportingCalls(
	ids []string,
	byID map[string]SupportingCall,
	seen map[string]bool,
	out *Result,
) {
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		sc, ok := byID[id]
		if !ok {
			continue
		}
		seen[id] = true
		out.SupportingCalls = append(out.SupportingCalls, sc)
	}
}

// rootNodes selects the set of root-fragment functions to start traces from.
// With entryRootedOnly false this is every root-fragment function (historical
// behavior). With it true, only root-fragment functions with no incoming edge
// in the closure adjacency (in-degree 0) are kept.
func rootNodes(root ComponentKey, rootFragment Fragment, adjacency map[graphNode][]adjacencyEdge, entryRootedOnly bool) []graphNode {
	roots := make([]graphNode, 0, len(rootFragment.Functions))
	if !entryRootedOnly {
		for i := range rootFragment.Functions {
			roots = append(roots, graphNode{Component: root, Function: rootFragment.Functions[i].Signature})
		}
		return roots
	}

	hasIncoming := incomingNodes(adjacency)
	for i := range rootFragment.Functions {
		node := graphNode{Component: root, Function: rootFragment.Functions[i].Signature}
		if hasIncoming[node] {
			continue
		}
		roots = append(roots, node)
	}
	return roots
}

// incomingNodes returns the set of nodes that are the target of at least one
// traversable edge in the adjacency — i.e. every node with in-degree >= 1.
func incomingNodes(adjacency map[graphNode][]adjacencyEdge) map[graphNode]bool {
	incoming := make(map[graphNode]bool)
	for _, edges := range adjacency {
		for _, edge := range edges {
			incoming[edge.target] = true
		}
	}
	return incoming
}

type graphNode struct {
	Component ComponentKey
	Function  string
}

type adjacencyEdge struct {
	target    graphNode
	entryCall *CallSite
}

func dependencyClosure(root ComponentKey, deps DependencyGraph) []ComponentKey {
	seen := map[ComponentKey]bool{root: true}
	queue := []ComponentKey{root}
	out := []ComponentKey{root}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, dep := range deps[current] {
			if seen[dep] {
				continue
			}
			seen[dep] = true
			queue = append(queue, dep)
			out = append(out, dep)
		}
	}
	return out
}

func missingFragments(closure []ComponentKey, fragments map[ComponentKey]Fragment) []ComponentKey {
	var missing []ComponentKey
	for _, key := range closure {
		if _, ok := fragments[key]; !ok {
			missing = append(missing, key)
		}
	}
	return missing
}

func indexFunctions(closure []ComponentKey, fragments map[ComponentKey]Fragment) map[string][]graphNode {
	out := make(map[string][]graphNode)
	for _, key := range closure {
		fragment := fragments[key]
		for i := range fragment.Functions {
			node := graphNode{Component: key, Function: fragment.Functions[i].Signature}
			out[fragment.Functions[i].Signature] = append(out[fragment.Functions[i].Signature], node)
		}
	}
	return out
}

// dispatchGroupKey identifies one interface call site so that the sibling
// candidate edges the producer emitted for it can be grouped and judged
// together: a single source call expression that the producer expanded into N
// concrete implementations.
type dispatchGroupKey struct {
	Component  ComponentKey
	Caller     string
	CallSite   int
	MethodName string
	Arity      int
}

// callEdge is the scope-agnostic view of one resolved call edge. Internal and
// external edges are normalised into this shape so the resolution policy — and
// crucially the per-call-site ambiguity check — can span both: an interface
// call site whose implementations straddle the component boundary must be judged
// as one group, not two.
type callEdge struct {
	caller               string
	target               string
	resolution           ResolutionKind
	method               string
	arity                int
	callSite             int
	internal             bool
	entryCall            *CallSite
	resolvedReceiverType string
}

// buildAdjacency composes the traversable call graph from the fragment closure
// while applying the edge-resolution policy. It returns the adjacency map plus
// the list of edges/call sites it refused to traverse (fail-closed audit trail).
//
// Policy (tiered, fail-closed by default):
//   - exact              -> always traversed.
//   - interface_dispatch -> traversed only if exactly one concrete impl is
//     present in the current component's direct dependencies for that call
//     site; >1 is ambiguous and fails closed (recorded). 0 is simply
//     unreachable.
//   - name_only          -> never traversed (recorded).
//   - unknown (zero)     -> never traversed (recorded); usually a producer bug.
func buildAdjacency(
	closure []ComponentKey,
	deps DependencyGraph,
	fragments map[ComponentKey]Fragment,
	functionsBySignature map[string][]graphNode,
) (map[graphNode][]adjacencyEdge, []SuppressedEdge) {
	out := make(map[graphNode][]adjacencyEdge)
	var suppressed []SuppressedEdge
	ownerTypes := indexOwnerTypes(closure, fragments)

	for _, key := range closure {
		fragment := fragments[key]
		componentSigs := indexComponentSignatures(key, fragment, out)
		edges := collectCallEdges(fragment)
		resolve := callEdgeResolver(key, componentSigs, componentSet(deps[key]), functionsBySignature)

		dispatchGroups := applyImmediateEdgePolicy(key, edges, resolve, out, &suppressed)
		applyDispatchGroups(key, dispatchGroups, resolve, ownerTypes, out, &suppressed)
	}
	return out, suppressed
}

// indexOwnerTypes maps each node to the declaring type of its function, derived
// from Function.FunctionName (the fully-qualified, dotted, customer-facing name
// e.g. "com.password4j.PBKDF2Function.hash" -> "com.password4j.PBKDF2Function").
// This is ecosystem-agnostic: every producer populates FunctionName in this
// "<owner>.<method>" shape (see ConstructorDisplayFromSymbol for the same
// convention used elsewhere in this package). Used only to disambiguate an
// otherwise-ambiguous interface-dispatch group against a resolved receiver type
// (see applyDispatchGroups); absent or malformed names simply never match.
func indexOwnerTypes(closure []ComponentKey, fragments map[ComponentKey]Fragment) map[graphNode]string {
	out := make(map[graphNode]string)
	for _, key := range closure {
		fragment := fragments[key]
		for i := range fragment.Functions {
			fn := &fragment.Functions[i]
			if owner := ownerTypeFromFunctionName(fn.FunctionName); owner != "" {
				out[graphNode{Component: key, Function: fn.Signature}] = owner
			}
		}
	}
	return out
}

// ownerTypeFromFunctionName strips the trailing ".<method>" segment from a
// fully-qualified function name, returning the declaring type. Returns "" when
// name has no dot (no owner to derive).
func ownerTypeFromFunctionName(name string) string {
	dot := strings.LastIndex(name, ".")
	if dot <= 0 {
		return ""
	}
	return name[:dot]
}

func componentSet(closure []ComponentKey) map[ComponentKey]bool {
	out := make(map[ComponentKey]bool, len(closure))
	for _, key := range closure {
		out[key] = true
	}
	return out
}

func indexComponentSignatures(key ComponentKey, fragment Fragment, adjacency map[graphNode][]adjacencyEdge) map[string]bool {
	componentSigs := make(map[string]bool, len(fragment.Functions))
	for i := range fragment.Functions {
		node := graphNode{Component: key, Function: fragment.Functions[i].Signature}
		if _, ok := adjacency[node]; !ok {
			adjacency[node] = nil
		}
		componentSigs[fragment.Functions[i].Signature] = true
	}
	return componentSigs
}

func collectCallEdges(fragment Fragment) []callEdge {
	edges := make([]callEdge, 0, len(fragment.InternalEdges)+len(fragment.ExternalCalls))
	for i := range fragment.InternalEdges {
		e := &fragment.InternalEdges[i]
		edges = append(edges, callEdge{
			caller: e.Caller, target: e.Callee, resolution: e.Resolution,
			method: e.MethodName, arity: e.Arity, callSite: e.CallSite, internal: true, entryCall: e.EntryCall,
			resolvedReceiverType: e.ResolvedReceiverType,
		})
	}
	for i := range fragment.ExternalCalls {
		c := &fragment.ExternalCalls[i]
		edges = append(edges, callEdge{
			caller: c.Caller, target: c.TargetSignature, resolution: c.Resolution,
			method: c.MethodName, arity: c.Arity, callSite: c.CallSite, internal: false, entryCall: c.EntryCall,
			resolvedReceiverType: c.ResolvedReceiverType,
		})
	}
	return edges
}

type edgeResolver func(callEdge) []graphNode

// callEdgeResolver maps one edge to the concrete target nodes it could reach.
// Internal edges resolve within the component; external edges resolve to other
// components that are direct dependencies of the current component.
func callEdgeResolver(
	key ComponentKey,
	componentSigs map[string]bool,
	directDeps map[ComponentKey]bool,
	functionsBySignature map[string][]graphNode,
) edgeResolver {
	return func(e callEdge) []graphNode {
		if e.internal {
			if componentSigs[e.target] {
				return []graphNode{{Component: key, Function: e.target}}
			}
			return nil
		}
		return externalTargets(e.target, directDeps, functionsBySignature)
	}
}

func externalTargets(
	target string,
	directDeps map[ComponentKey]bool,
	functionsBySignature map[string][]graphNode,
) []graphNode {
	var targets []graphNode
	for _, callee := range functionsBySignature[target] {
		if !directDeps[callee.Component] {
			continue
		}
		targets = append(targets, callee)
	}
	return targets
}

func applyImmediateEdgePolicy(
	key ComponentKey,
	edges []callEdge,
	resolve edgeResolver,
	adjacency map[graphNode][]adjacencyEdge,
	suppressed *[]SuppressedEdge,
) map[dispatchGroupKey][]callEdge {
	// Interface-dispatch candidates are deferred and grouped per call site so
	// ambiguity (>1 impl in closure) is detected across all sibling edges,
	// including siblings that cross the internal/external boundary.
	dispatchGroups := make(map[dispatchGroupKey][]callEdge)
	for _, e := range edges {
		caller := graphNode{Component: key, Function: e.caller}
		switch e.resolution {
		case ResolutionExact:
			appendAdjacencyEdges(adjacency, caller, resolve(e), e.entryCall)
		case ResolutionInterfaceDispatch:
			gk := dispatchKey(key, e)
			dispatchGroups[gk] = append(dispatchGroups[gk], e)
		case ResolutionNameOnly:
			*suppressed = append(*suppressed, suppressedEdge(key, e, SuppressReasonNameOnly, candidateComponents(resolve(e))))
		case ResolutionUnknown:
			*suppressed = append(*suppressed, suppressedEdge(key, e, SuppressReasonUnknown, candidateComponents(resolve(e))))
		default: // Future unhandled kind: fail closed.
			*suppressed = append(*suppressed, suppressedEdge(key, e, SuppressReasonUnknown, candidateComponents(resolve(e))))
		}
	}
	return dispatchGroups
}

func dispatchKey(key ComponentKey, e callEdge) dispatchGroupKey {
	return dispatchGroupKey{
		Component:  key,
		Caller:     e.caller,
		CallSite:   e.callSite,
		MethodName: e.method,
		Arity:      e.arity,
	}
}

func applyDispatchGroups(
	key ComponentKey,
	groups map[dispatchGroupKey][]callEdge,
	resolve edgeResolver,
	ownerTypes map[graphNode]string,
	adjacency map[graphNode][]adjacencyEdge,
	suppressed *[]SuppressedEdge,
) {
	for _, gk := range sortedDispatchKeys(groups) {
		group := groups[gk]
		targets := distinctTargetEdges(group, resolve)
		caller := graphNode{Component: key, Function: gk.Caller}
		switch {
		case len(targets) == 1:
			adjacency[caller] = append(adjacency[caller], targets[0])
		case len(targets) > 1:
			if resolved, ok := disambiguateByReceiverType(group, targets, ownerTypes); ok {
				adjacency[caller] = append(adjacency[caller], resolved)
				continue
			}
			*suppressed = append(*suppressed, ambiguousDispatchEdge(key, gk, candidateComponentsFromEdges(targets)))
			// len(targets) == 0: no implementation in closure -> unreachable,
			// nothing to traverse and nothing to record.
		}
	}
}

// disambiguateByReceiverType narrows an ambiguous dispatch group (>1 candidate
// target) to a single edge when the call site carries resolved receiver-type
// provenance (see InternalEdge.ResolvedReceiverType) that matches EXACTLY ONE
// candidate's declaring type. This is the mine-time KB-contract/return-type
// inference paying off at stitch time: an interface call site the producer
// could not resolve structurally (name+arity expansion still finds every
// sibling implementation) is disambiguated using the concrete type inference
// already determined for that specific receiver.
//
// The match is by SIMPLE (unqualified) type name: ownerTypes indexes the full
// "<package>.<Type>" (from Function.FunctionName), while ResolvedReceiverType
// is typically the erased/simple name the producer's inference works with
// (e.g. FunctionDecl.ReturnType) — mirroring the same simple-name convention
// resolveParameterPassthroughDispatch already uses on the mine side.
//
// Returns ok=false — leaving the group to fail closed exactly as before — when:
//   - no candidate edge carries receiver-type provenance, or
//   - the resolved type matches zero candidates (stale/foreign type), or
//   - the resolved type matches more than one candidate (should not happen for
//     a well-formed KB, but never assumed).
//
// This never changes the fail-closed default for a call site inference did not
// resolve: it only ever narrows an already-ambiguous group to at most one
// survivor, never invents a candidate that resolve() did not already produce.
func disambiguateByReceiverType(group []callEdge, targets []adjacencyEdge, ownerTypes map[graphNode]string) (adjacencyEdge, bool) {
	resolvedType := simpleTypeName(firstResolvedReceiverType(group))
	if resolvedType == "" {
		return adjacencyEdge{}, false
	}

	var match adjacencyEdge
	matches := 0
	for _, t := range targets {
		if simpleTypeName(ownerTypes[t.target]) == resolvedType {
			match = t
			matches++
		}
	}
	if matches != 1 {
		return adjacencyEdge{}, false
	}
	return match, true
}

// simpleTypeName returns the trailing, unqualified segment of a (possibly
// fully-qualified) type name, e.g. "com.password4j.PBKDF2Function" ->
// "PBKDF2Function". A name with no dot is returned unchanged.
func simpleTypeName(typeName string) string {
	if idx := strings.LastIndex(typeName, "."); idx >= 0 {
		return typeName[idx+1:]
	}
	return typeName
}

func firstResolvedReceiverType(group []callEdge) string {
	for _, e := range group {
		if e.resolvedReceiverType != "" {
			return e.resolvedReceiverType
		}
	}
	return ""
}

func appendAdjacencyEdges(
	adjacency map[graphNode][]adjacencyEdge,
	caller graphNode,
	targets []graphNode,
	entryCall *CallSite,
) {
	for _, target := range targets {
		adjacency[caller] = append(adjacency[caller], adjacencyEdge{target: target, entryCall: entryCall})
	}
}

func distinctTargetEdges(edges []callEdge, resolve edgeResolver) []adjacencyEdge {
	distinct := map[graphNode]bool{}
	var targets []adjacencyEdge
	for _, e := range edges {
		for _, t := range resolve(e) {
			if distinct[t] {
				continue
			}
			distinct[t] = true
			targets = append(targets, adjacencyEdge{target: t, entryCall: e.entryCall})
		}
	}
	return targets
}

func ambiguousDispatchEdge(key ComponentKey, gk dispatchGroupKey, candidates []ComponentKey) SuppressedEdge {
	return SuppressedEdge{
		Caller:     CallFrame{Component: key, Signature: gk.Caller},
		MethodName: gk.MethodName,
		Arity:      gk.Arity,
		Reason:     SuppressReasonAmbiguousDispatch,
		Candidates: candidates,
	}
}

func candidateComponentsFromEdges(edges []adjacencyEdge) []ComponentKey {
	candidates := make([]ComponentKey, 0, len(edges))
	for _, edge := range edges {
		candidates = append(candidates, edge.target.Component)
	}
	return candidates
}

func candidateComponents(targets []graphNode) []ComponentKey {
	candidates := make([]ComponentKey, 0, len(targets))
	for _, t := range targets {
		candidates = append(candidates, t.Component)
	}
	return candidates
}

func suppressedEdge(from ComponentKey, e callEdge, reason string, candidates []ComponentKey) SuppressedEdge {
	return SuppressedEdge{
		Caller:     CallFrame{Component: from, Signature: e.caller},
		MethodName: e.method,
		Arity:      e.arity,
		Reason:     reason,
		Candidates: candidates,
	}
}

func sortedDispatchKeys(groups map[dispatchGroupKey][]callEdge) []dispatchGroupKey {
	keys := make([]dispatchGroupKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Caller != b.Caller {
			return a.Caller < b.Caller
		}
		if a.CallSite != b.CallSite {
			return a.CallSite < b.CallSite
		}
		if a.MethodName != b.MethodName {
			return a.MethodName < b.MethodName
		}
		return a.Arity < b.Arity
	})
	return keys
}

func indexCryptoOperations(closure []ComponentKey, fragments map[ComponentKey]Fragment) map[graphNode][]CryptoOperation {
	out := make(map[graphNode][]CryptoOperation)
	for _, key := range closure {
		fragment := fragments[key]
		for i := range fragment.CryptoOperations {
			node := graphNode{Component: key, Function: fragment.CryptoOperations[i].Function}
			out[node] = append(out[node], fragment.CryptoOperations[i])
		}
	}
	return out
}

func indexSupportingCalls(closure []ComponentKey, fragments map[ComponentKey]Fragment) map[graphNode][]SupportingCall {
	out := make(map[graphNode][]SupportingCall)
	for _, key := range closure {
		fragment := fragments[key]
		for i := range fragment.SupportingCalls {
			node := graphNode{Component: key, Function: fragment.SupportingCalls[i].Function}
			out[node] = append(out[node], fragment.SupportingCalls[i])
		}
	}
	return out
}

// stitchMaxFrontier caps the backward-BFS queue size as a safety valve against
// pathological graphs. It mirrors internal/callgraph.traceMaxFrontier: with the
// per-op graph-global frontier set each function is enqueued at most once, so the
// queue is bounded by the number of functions and this cap should never fire in
// practice — it exists purely to guarantee bounded memory if that invariant is
// ever violated.
const stitchMaxFrontier = 1_000_000

// stitchMaxDepth and stitchMaxChainsPerOp mirror the bounds the live exporter
// passes to TraceBackLimited (internal/scan/export.go buildBaseCallChains:
// maxDepth=32, maxChains=128). The served stitch MUST apply the same caps or it
// would emit deeper / more numerous chains than a live --export-callgraph run
// (live silently drops chains past these bounds), breaking the parity contract.
const (
	stitchMaxDepth       = 32
	stitchMaxChainsPerOp = 128
)

// reverseEdge is one backward step: from a node to one of its callers, carrying
// the entryCall of the FORWARD edge (caller -> node) so frame EntryCall stamping
// stays byte-identical to the old forward DFS.
type reverseEdge struct {
	caller    graphNode
	entryCall *CallSite
}

// backwardChain is the chain being grown by the BFS, in entry->...->op order.
// entryCalls[i] is the EntryCall to stamp on nodes[i] — i.e. the call site of the
// forward edge that ARRIVES at nodes[i] from nodes[i-1] (nil on the head/root
// frame), exactly as the previous forward DFS stamped CallFrame.EntryCall.
type backwardChain struct {
	nodes      []graphNode
	entryCalls []*CallSite
}

// traceBackward mirrors internal/callgraph.Tracer.TraceBackLimited: for each
// crypto-op node it runs a backward BFS over a reverse adjacency with a PER-OP
// graph-global frontier set (each function enqueued at most once -> O(V+E)).
// Re-convergent (diamond) branches collapse to the first caller reached; distinct
// entries are preserved (one chain per entry). This replaces the old forward DFS
// that enumerated all simple paths (O(paths)) and emitted the extra re-convergent
// chains live never produces.
func traceBackward(
	adjacency map[graphNode][]adjacencyEdge,
	opsByNode map[graphNode][]CryptoOperation,
	supportingByNode map[graphNode][]SupportingCall,
	fragments map[ComponentKey]Fragment,
	roots []graphNode,
	out *Result,
) {
	reverse := reverseAdjacency(adjacency)
	entrySet := make(map[graphNode]bool, len(roots))
	for _, r := range roots {
		entrySet[r] = true
	}

	// supportingSeen dedupes supporting-call emission across surviving chains so a
	// node shared by several chains emits its supporting calls once. On diamond-free
	// graphs each node appears on exactly one chain, so behavior is unchanged.
	supportingSeen := make(map[graphNode]bool)

	for _, opNode := range sortedNodes(opsByNode) {
		chains := backwardBFS(opNode, reverse, entrySet)
		if len(chains) == 0 {
			// No backward chain reached an entry (the op node has no callers, or none
			// of its callers are entries). Mirror live's buildBaseCallChains fallback:
			// emit a single-node chain so a self-contained crypto call is still
			// reported. The op node IS its own entry in this case.
			chains = []backwardChain{{nodes: []graphNode{opNode}, entryCalls: []*CallSite{nil}}}
		}
		for _, chain := range chains {
			emitChain(opNode, chain, opsByNode, supportingByNode, fragments, supportingSeen, out)
		}
	}
}

// reverseAdjacency inverts the forward adjacency: target node -> list of callers,
// each carrying the entryCall of the forward edge (caller -> target). Callers are
// stably sorted by signature so the BFS collapses re-convergent branches to the
// same representative as live (which we also sort — see enqueueCallers in
// internal/callgraph/tracer.go).
func reverseAdjacency(adjacency map[graphNode][]adjacencyEdge) map[graphNode][]reverseEdge {
	reverse := make(map[graphNode][]reverseEdge)
	for caller, edges := range adjacency {
		for _, edge := range edges {
			reverse[edge.target] = append(reverse[edge.target], reverseEdge{caller: caller, entryCall: edge.entryCall})
		}
	}
	for target := range reverse {
		edges := reverse[target]
		sort.SliceStable(edges, func(i, j int) bool {
			if edges[i].caller.Function != edges[j].caller.Function {
				return edges[i].caller.Function < edges[j].caller.Function
			}
			return edges[i].caller.Component.String() < edges[j].caller.Component.String()
		})
	}
	return reverse
}

// backwardBFS walks callers from opNode using a graph-global frontier set
// (enqueued) so each function is added at most once. A chain is complete when its
// head (backward-most node) is an entry; mirroring live, a chain is only collected
// when its length is > 1.
func backwardBFS(opNode graphNode, reverse map[graphNode][]reverseEdge, entrySet map[graphNode]bool) []backwardChain {
	var results []backwardChain

	enqueued := map[graphNode]bool{opNode: true}
	queue := []backwardChain{{nodes: []graphNode{opNode}, entryCalls: []*CallSite{nil}}}

	for len(queue) > 0 {
		if len(queue) >= stitchMaxFrontier {
			return results
		}

		current := queue[0]
		queue = queue[1:]

		// Depth cap mirroring live (maxDepth=32): neither collect nor expand a chain
		// longer than the bound — live drops it silently.
		if len(current.nodes) > stitchMaxDepth {
			continue
		}

		head := current.nodes[0]
		callers := reverse[head]

		// Collect when the head is an entry and the chain is non-trivial, mirroring
		// classifyTraceItem/rootChainIsComplete (len(chain) > 1).
		if entrySet[head] && len(current.nodes) > 1 {
			results = append(results, current)
			// Chain cap mirroring live (maxChains=128): stop once the op has enough
			// chains; live truncates here too.
			if len(results) >= stitchMaxChainsPerOp {
				return results
			}
			// An entry has no further callers to expand toward, just like live's
			// user-boundary stop. Even if it had callers we stop at the entry.
			continue
		}

		for _, edge := range callers {
			if enqueued[edge.caller] {
				continue
			}
			enqueued[edge.caller] = true

			// Prepend the caller. The entryCall of this reverse edge is the forward
			// edge (caller -> head), so it belongs to the OLD head frame, exactly as
			// the forward DFS stamped EntryCall on the node the edge arrived at.
			nodes := make([]graphNode, 0, len(current.nodes)+1)
			nodes = append(nodes, edge.caller)
			nodes = append(nodes, current.nodes...)

			entryCalls := make([]*CallSite, 0, len(current.entryCalls)+1)
			entryCalls = append(entryCalls, nil) // caller is the new head: no inbound edge yet
			entryCalls = append(entryCalls, current.entryCalls...)
			entryCalls[1] = edge.entryCall // stamp the (caller -> old head) call site on old head

			queue = append(queue, backwardChain{nodes: nodes, entryCalls: entryCalls})
		}
	}

	return results
}

// emitChain materializes one completed backward chain into a FindingChain and
// flushes the supporting calls of its nodes (entry->op order, deduped via
// supportingSeen). Frame construction is byte-identical to the previous forward
// DFS: same Function identity resolution, same EntryCall, same supporting-call
// field backfill.
func emitChain(
	opNode graphNode,
	chain backwardChain,
	opsByNode map[graphNode][]CryptoOperation,
	supportingByNode map[graphNode][]SupportingCall,
	fragments map[ComponentKey]Fragment,
	supportingSeen map[graphNode]bool,
	out *Result,
) {
	frames := make([]CallFrame, len(chain.nodes))
	for i, node := range chain.nodes {
		frames[i] = buildFrame(node, chain.entryCalls[i], fragments)
	}

	// Flush supporting calls in entry->op order so output ordering matches the old
	// forward (top-down) DFS on diamond-free graphs.
	for i, node := range chain.nodes {
		if supportingSeen[node] {
			continue
		}
		supportingSeen[node] = true
		flushSupportingCalls(node, &frames[i], supportingByNode, out)
	}

	for i := range opsByNode[opNode] {
		op := opsByNode[opNode][i]
		chainCopy := FindingChain{
			FindingID:  op.FindingID,
			RuleID:     op.RuleID,
			Symbol:     op.Symbol,
			Frames:     append([]CallFrame(nil), frames...),
			Confidence: ConfidenceHigh,
		}
		// Carry the full CryptoOperation so the converter can emit crypto_call
		// without re-reading the original fragments.
		opCopy := op
		chainCopy.CryptoOp = &opCopy
		out.Chains = append(out.Chains, chainCopy)
	}
}

// buildFrame resolves one node into a CallFrame, stamping the resolved Function
// identity from the fragment and the EntryCall of the edge that led to this frame.
func buildFrame(node graphNode, entryCall *CallSite, fragments map[ComponentKey]Fragment) CallFrame {
	frame := CallFrame{
		Component: node.Component,
		Signature: node.Function,
		EntryCall: entryCall,
	}
	if frag, ok := fragments[node.Component]; ok {
		frame.Module = frag.Module
		for i := range frag.Functions {
			if frag.Functions[i].Signature == node.Function {
				frame.Function = frag.Functions[i]
				break
			}
		}
	}
	return frame
}

// flushSupportingCalls appends the supporting calls of one node to out, stamping
// frame identity exactly as the previous forward DFS did.
func flushSupportingCalls(node graphNode, frame *CallFrame, supportingByNode map[graphNode][]SupportingCall, out *Result) {
	for i := range supportingByNode[node] {
		support := supportingByNode[node][i]
		support.Function = frame.Signature
		if support.FunctionName == "" {
			support.FunctionName = frame.Function.FunctionName
		}
		if support.CanonicalSignature == "" {
			support.CanonicalSignature = frame.Function.CanonicalSignature
		}
		if support.DisplaySymbol == "" {
			support.DisplaySymbol = frame.Function.DisplaySymbol
		}
		if len(support.Aliases) == 0 {
			support.Aliases = append([]string(nil), frame.Function.Aliases...)
		}
		out.SupportingCalls = append(out.SupportingCalls, support)
	}
}

// trace is the historical full-rooting forward DFS used only by Stitch
// (EntryRootedOnly=false). It enumerates root-to-crypto paths from each root,
// using a per-path visiting set for cycle prevention. The serving path uses
// traceBackward instead (see StitchWithOptions). Kept verbatim in behavior so the
// resolution fail-closed and parallel-edge tests stay byte-equivalent.
func trace(
	current graphNode,
	adjacency map[graphNode][]adjacencyEdge,
	opsByNode map[graphNode][]CryptoOperation,
	supportingByNode map[graphNode][]SupportingCall,
	fragments map[ComponentKey]Fragment,
	traversedEdgeEntryCall *CallSite,
	path []CallFrame,
	visiting map[graphNode]bool,
	out *Result,
) {
	if visiting[current] {
		return
	}
	visiting[current] = true
	defer delete(visiting, current)

	frame := buildFrame(current, traversedEdgeEntryCall, fragments)

	path = append(path, frame)
	flushSupportingCalls(current, &frame, supportingByNode, out)
	for i := range opsByNode[current] {
		op := opsByNode[current][i]
		chain := FindingChain{
			FindingID:  op.FindingID,
			RuleID:     op.RuleID,
			Symbol:     op.Symbol,
			Frames:     append([]CallFrame(nil), path...),
			Confidence: ConfidenceHigh,
		}
		// Carry the full CryptoOperation so the converter can emit crypto_call
		// without re-reading the original fragments.
		opCopy := op
		chain.CryptoOp = &opCopy
		out.Chains = append(out.Chains, chain)
	}
	for _, edge := range adjacency[current] {
		// Carry the EntryCall from this edge to the next frame.
		trace(edge.target, adjacency, opsByNode, supportingByNode, fragments, edge.entryCall, path, visiting, out)
	}
}

// forwardEdgeKey dedupes forward-closure edges: the same (from,to) pair at
// distinct call sites (line) is a distinct edge (multi-edge, e.g. an
// overloaded call site invoked twice); the same (from,to,line) collapses.
type forwardEdgeKey struct {
	from graphNode
	to   graphNode
	line int
}

func entryCallLine(cs *CallSite) int {
	if cs == nil {
		return 0
	}
	return cs.Line
}

// sortedAdjacencyEdges returns a stable-sorted copy of edges (by target
// Function, then target Component, then entryCall line) so forward-BFS
// frontier expansion — and therefore discovery order/depth assignment — is
// deterministic regardless of the order buildAdjacency appended them in.
func sortedAdjacencyEdges(edges []adjacencyEdge) []adjacencyEdge {
	sorted := append([]adjacencyEdge(nil), edges...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.target.Function != b.target.Function {
			return a.target.Function < b.target.Function
		}
		if a.target.Component.String() != b.target.Component.String() {
			return a.target.Component.String() < b.target.Component.String()
		}
		return entryCallLine(a.entryCall) < entryCallLine(b.entryCall)
	})
	return sorted
}

// buildForwardClosures computes one memoized forward BFS per DISTINCT finding
// anchor (opsByNode key) — cross-finding dedup falls out of iterating the
// anchor set rather than the finding set. Iteration order is sortedNodes'
// deterministic order (irrelevant to output content — the memo is
// anchor-keyed — but kept for determinism-in-spirit with the rest of the
// package).
func buildForwardClosures(
	adjacency map[graphNode][]adjacencyEdge,
	opsByNode map[graphNode][]CryptoOperation,
	supportingByNode map[graphNode][]SupportingCall,
	fragments map[ComponentKey]Fragment,
	caps forwardCaps,
) map[graphNode]*forwardClosure {
	memo := make(map[graphNode]*forwardClosure, len(opsByNode))
	for _, anchor := range sortedNodes(opsByNode) {
		if _, ok := memo[anchor]; ok {
			continue
		}
		memo[anchor] = forwardBFS(anchor, adjacency, opsByNode, supportingByNode, fragments, caps)
	}
	return memo
}

// forwardBFS computes the rooted forward reachability graph from anchor: a
// breadth-first traversal of the SAME adjacency the backward pass uses (so
// the fail-closed edge-resolution policy applies for free — suppressed/
// ambiguous/name_only/unknown edges are already absent from adjacency), node-
// deduped via a visited set (cycle-safe: each node expands at most once), with
// explicit depth/node/edge caps. See design doc section 2 for the full
// contract; cap enforcement order is depth (gates expansion) > node (gates
// new-node admission) > edge.
func forwardBFS(
	anchor graphNode,
	adjacency map[graphNode][]adjacencyEdge,
	opsByNode map[graphNode][]CryptoOperation,
	supportingByNode map[graphNode][]SupportingCall,
	fragments map[ComponentKey]Fragment,
	caps forwardCaps,
) *forwardClosure {
	fc := &forwardClosure{
		anchor:   buildFrame(anchor, nil, fragments),
		maxDepth: caps.maxDepth,
	}

	st := &forwardBFSState{
		fc:               fc,
		caps:             caps,
		fragments:        fragments,
		opsByNode:        opsByNode,
		supportingByNode: supportingByNode,
		visited:          map[graphNode]bool{anchor: true},
		depth:            map[graphNode]int{anchor: 0},
		edgeSeen:         map[forwardEdgeKey]bool{},
	}
	queue := []graphNode{anchor}

	for len(queue) > 0 {
		// Safety valve mirroring the backward pass (stitch.go stitchMaxFrontier):
		// each node is enqueued at most once, bounded by caps.maxNodes, so this
		// should never fire in practice.
		if len(queue) >= stitchMaxFrontier {
			fc.truncated = true
			break
		}

		cur := queue[0]
		queue = queue[1:]
		d := st.depth[cur]

		if d >= caps.maxDepth {
			if len(adjacency[cur]) > 0 {
				// There was more forward story beyond the depth budget; we did not
				// walk it. Never silent.
				fc.truncated = true
			}
			continue
		}

		for _, edge := range sortedAdjacencyEdges(adjacency[cur]) {
			if target, enqueue := st.visitEdge(cur, d, edge); enqueue {
				queue = append(queue, target)
			}
		}
	}

	return fc
}

// forwardBFSState carries the mutable working set of one forwardBFS run so the
// per-edge admission logic can live in visitEdge, keeping the BFS driver loop
// flat.
type forwardBFSState struct {
	fc               *forwardClosure
	caps             forwardCaps
	fragments        map[ComponentKey]Fragment
	opsByNode        map[graphNode][]CryptoOperation
	supportingByNode map[graphNode][]SupportingCall
	visited          map[graphNode]bool
	depth            map[graphNode]int
	edgeSeen         map[forwardEdgeKey]bool
}

// visitEdge processes one cur->target edge at BFS depth d, enforcing the caps
// (node cap gates admission before any edge is emitted, so no edge ever points
// at an absent node). It returns (target, true) when target is newly admitted
// and must be enqueued; (_, false) otherwise (cap hit, or an
// already-visited target — cycle back-edge / diamond re-convergence — whose
// edge is recorded once but whose node is neither re-added nor re-expanded).
func (s *forwardBFSState) visitEdge(cur graphNode, d int, edge adjacencyEdge) (graphNode, bool) {
	target := edge.target
	key := forwardEdgeKey{from: cur, to: target, line: entryCallLine(edge.entryCall)}

	if !s.visited[target] {
		if len(s.fc.nodes) >= s.caps.maxNodes {
			s.fc.truncated = true
			return graphNode{}, false
		}
		if !s.edgeSeen[key] && len(s.fc.edges) >= s.caps.maxEdges {
			s.fc.truncated = true
			return graphNode{}, false
		}
		s.visited[target] = true
		s.depth[target] = d + 1
		s.fc.nodes = append(s.fc.nodes, buildForwardNode(target, d+1, s.fragments, s.opsByNode, s.supportingByNode))
		s.edgeSeen[key] = true
		s.fc.edges = append(s.fc.edges, forwardEdge{from: cur, to: target, entryCall: edge.entryCall})
		return target, true
	}

	if s.edgeSeen[key] {
		return graphNode{}, false
	}
	if len(s.fc.edges) >= s.caps.maxEdges {
		s.fc.truncated = true
		return graphNode{}, false
	}
	s.edgeSeen[key] = true
	s.fc.edges = append(s.fc.edges, forwardEdge{from: cur, to: target, entryCall: edge.entryCall})
	return graphNode{}, false
}

// buildForwardNode resolves one forward-reachable node into its annotated
// forwardNode shape: identity (via buildFrame), shortest-path depth, and the
// annotate-never-filter crypto relevance signals (Fork 2): cryptoRelevant is
// true when the node is itself a finding anchor OR has a non-empty
// supporting-call category; supportingCategory is the first non-empty
// Category among the node's supporting calls (stable fragment order).
func buildForwardNode(
	node graphNode,
	depth int,
	fragments map[ComponentKey]Fragment,
	opsByNode map[graphNode][]CryptoOperation,
	supportingByNode map[graphNode][]SupportingCall,
) forwardNode {
	category := firstSupportingCategory(supportingByNode[node])
	return forwardNode{
		node:               node,
		frame:              buildFrame(node, nil, fragments),
		depth:              depth,
		cryptoRelevant:     len(opsByNode[node]) > 0 || category != "",
		supportingCategory: category,
	}
}

func firstSupportingCategory(supports []SupportingCall) string {
	for i := range supports {
		if supports[i].Category != "" {
			return supports[i].Category
		}
	}
	return ""
}

// sortedNodes returns the op-bearing nodes in a deterministic order (by signature,
// then component) so chain emission is stable across runs and map iterations.
func sortedNodes(opsByNode map[graphNode][]CryptoOperation) []graphNode {
	nodes := make([]graphNode, 0, len(opsByNode))
	for node := range opsByNode {
		nodes = append(nodes, node)
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Function != nodes[j].Function {
			return nodes[i].Function < nodes[j].Function
		}
		return nodes[i].Component.String() < nodes[j].Component.String()
	})
	return nodes
}
