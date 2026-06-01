// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "sort"

// Stitch composes reusable component graph fragments into root-to-crypto
// reachability chains for root.
//
// This is the pure graph algorithm. It deliberately does not know about
// storage, compression, or HTTP response DTOs.
func Stitch(root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment) (*Result, error) {
	closure := dependencyClosure(root, deps)
	missing := missingFragments(closure, fragments)
	if len(missing) > 0 {
		return nil, &ErrMissingFragment{Components: missing}
	}

	functionsBySignature := indexFunctions(closure, fragments)
	adjacency, suppressed := buildAdjacency(closure, deps, fragments, functionsBySignature)
	opsByNode := indexCryptoOperations(closure, fragments)

	rootFragment := fragments[root]
	out := Result{Suppressed: suppressed}
	for _, fn := range rootFragment.Functions {
		start := graphNode{Component: root, Function: fn.Signature}
		trace(start, adjacency, opsByNode, fragments, nil, nil, map[graphNode]bool{}, &out)
	}
	return &out, nil
}

type graphNode struct {
	Component ComponentKey
	Function  string
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
		for _, fn := range fragment.Functions {
			node := graphNode{Component: key, Function: fn.Signature}
			out[fn.Signature] = append(out[fn.Signature], node)
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
) (map[graphNode][]graphNode, []SuppressedEdge) {
	out := make(map[graphNode][]graphNode)
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

func indexComponentSignatures(key ComponentKey, fragment Fragment, adjacency map[graphNode][]graphNode) map[string]bool {
	componentSigs := make(map[string]bool, len(fragment.Functions))
	for _, fn := range fragment.Functions {
		node := graphNode{Component: key, Function: fn.Signature}
		if _, ok := adjacency[node]; !ok {
			adjacency[node] = nil
		}
		componentSigs[fn.Signature] = true
	}
	return componentSigs
}

func collectCallEdges(fragment Fragment) []callEdge {
	edges := make([]callEdge, 0, len(fragment.InternalEdges)+len(fragment.ExternalCalls))
	for _, e := range fragment.InternalEdges {
		edges = append(edges, callEdge{
			caller: e.Caller, target: e.Callee, resolution: e.Resolution,
			method: e.MethodName, arity: e.Arity, callSite: e.CallSite, internal: true,
		})
	}
	for _, c := range fragment.ExternalCalls {
		edges = append(edges, callEdge{
			caller: c.Caller, target: c.TargetSignature, resolution: c.Resolution,
			method: c.MethodName, arity: c.Arity, callSite: c.CallSite, internal: false,
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
	adjacency map[graphNode][]graphNode,
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
			adjacency[caller] = append(adjacency[caller], resolve(e)...)
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
	adjacency map[graphNode][]graphNode,
	suppressed *[]SuppressedEdge,
) {
	for _, gk := range sortedDispatchKeys(groups) {
		targets := distinctTargets(groups[gk], resolve)
		caller := graphNode{Component: key, Function: gk.Caller}
		switch {
		case len(targets) == 1:
			adjacency[caller] = append(adjacency[caller], targets[0])
		case len(targets) > 1:
			*suppressed = append(*suppressed, ambiguousDispatchEdge(key, gk, targets))
			// len(targets) == 0: no implementation in closure -> unreachable,
			// nothing to traverse and nothing to record.
		}
	}
}

func distinctTargets(edges []callEdge, resolve edgeResolver) []graphNode {
	distinct := map[graphNode]bool{}
	var targets []graphNode
	for _, e := range edges {
		for _, t := range resolve(e) {
			if distinct[t] {
				continue
			}
			distinct[t] = true
			targets = append(targets, t)
		}
	}
	return targets
}

func ambiguousDispatchEdge(key ComponentKey, gk dispatchGroupKey, targets []graphNode) SuppressedEdge {
	return SuppressedEdge{
		Caller:     CallFrame{Component: key, Signature: gk.Caller},
		MethodName: gk.MethodName,
		Arity:      gk.Arity,
		Reason:     SuppressReasonAmbiguousDispatch,
		Candidates: candidateComponents(targets),
	}
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
		for _, op := range fragment.CryptoOperations {
			node := graphNode{Component: key, Function: op.Function}
			out[node] = append(out[node], op)
		}
	}
	return out
}

func trace(
	current graphNode,
	adjacency map[graphNode][]graphNode,
	opsByNode map[graphNode][]CryptoOperation,
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
	for _, next := range adjacency[current] {
		// Carry the EntryCall from this edge to the next frame.
		var nextEntryCall *CallSite
		nextEntryCall = resolveEdgeEntryCall(current, next, fragments)
		trace(next, adjacency, opsByNode, fragments, nextEntryCall, path, visiting, out)
	}
}

// resolveEdgeEntryCall finds the EntryCall on the edge from `from` to `to`
// within `from`'s component fragment. It searches both InternalEdges (same
// component) and ExternalCalls (cross-component). Returns nil when the edge
// carries no data-flow (legacy 1.0/1.1 fragments).
func resolveEdgeEntryCall(from, to graphNode, fragments map[ComponentKey]Fragment) *CallSite {
	frag, ok := fragments[from.Component]
	if !ok {
		return nil
	}
	if from.Component == to.Component {
		for i := range frag.InternalEdges {
			e := &frag.InternalEdges[i]
			if e.Caller == from.Function && e.Callee == to.Function {
				return e.EntryCall
			}
		}
		return nil
	}
	for i := range frag.ExternalCalls {
		e := &frag.ExternalCalls[i]
		if e.Caller == from.Function && e.TargetSignature == to.Function {
			return e.EntryCall
		}
	}
	return nil
}
