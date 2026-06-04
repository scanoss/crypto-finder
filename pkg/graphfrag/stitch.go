// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "sort"

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
	for _, start := range roots {
		trace(start, adjacency, opsByNode, supportingByNode, fragments, nil, nil, map[graphNode]bool{}, &out)
	}
	return &out, nil
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
	caller     string
	target     string
	resolution ResolutionKind
	method     string
	arity      int
	callSite   int
	internal   bool
	entryCall  *CallSite
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

	for _, key := range closure {
		fragment := fragments[key]
		componentSigs := indexComponentSignatures(key, fragment, out)
		edges := collectCallEdges(fragment)
		resolve := callEdgeResolver(key, componentSigs, componentSet(deps[key]), functionsBySignature)

		dispatchGroups := applyImmediateEdgePolicy(key, edges, resolve, out, &suppressed)
		applyDispatchGroups(key, dispatchGroups, resolve, out, &suppressed)
	}
	return out, suppressed
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
		})
	}
	for i := range fragment.ExternalCalls {
		c := &fragment.ExternalCalls[i]
		edges = append(edges, callEdge{
			caller: c.Caller, target: c.TargetSignature, resolution: c.Resolution,
			method: c.MethodName, arity: c.Arity, callSite: c.CallSite, internal: false, entryCall: c.EntryCall,
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
	adjacency map[graphNode][]adjacencyEdge,
	suppressed *[]SuppressedEdge,
) {
	for _, gk := range sortedDispatchKeys(groups) {
		targets := distinctTargetEdges(groups[gk], resolve)
		caller := graphNode{Component: key, Function: gk.Caller}
		switch {
		case len(targets) == 1:
			adjacency[caller] = append(adjacency[caller], targets[0])
		case len(targets) > 1:
			*suppressed = append(*suppressed, ambiguousDispatchEdge(key, gk, candidateComponentsFromEdges(targets)))
			// len(targets) == 0: no implementation in closure -> unreachable,
			// nothing to traverse and nothing to record.
		}
	}
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

	// Build the frame for this node: stamp the resolved Function identity from
	// the fragment and carry the EntryCall from the edge that led here.
	frame := CallFrame{
		Component: current.Component,
		Signature: current.Function,
		EntryCall: traversedEdgeEntryCall,
	}
	if frag, ok := fragments[current.Component]; ok {
		frame.Module = frag.Module
		for i := range frag.Functions {
			if frag.Functions[i].Signature == current.Function {
				frame.Function = frag.Functions[i]
				break
			}
		}
	}

	path = append(path, frame)
	for i := range supportingByNode[current] {
		support := supportingByNode[current][i]
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
	for i := range opsByNode[current] {
		op := opsByNode[current][i]
		frames := append([]CallFrame(nil), path...)
		chain := FindingChain{
			FindingID:  op.FindingID,
			RuleID:     op.RuleID,
			Symbol:     op.Symbol,
			Frames:     frames,
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
