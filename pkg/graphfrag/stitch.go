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
	adjacency, suppressed := buildAdjacency(closure, fragments, functionsBySignature)
	opsByNode := indexCryptoOperations(closure, fragments)

	rootFragment := fragments[root]
	out := Result{Suppressed: suppressed}
	for _, fn := range rootFragment.Functions {
		start := graphNode{Component: root, Function: fn.Signature}
		trace(start, adjacency, opsByNode, nil, map[graphNode]bool{}, &out)
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
//     present in the dependency closure for that call site; >1 is ambiguous and
//     fails closed (recorded). 0-in-closure is simply unreachable.
//   - name_only          -> never traversed (recorded).
//   - unknown (zero)     -> never traversed (recorded); usually a producer bug.
func buildAdjacency(
	closure []ComponentKey,
	fragments map[ComponentKey]Fragment,
	functionsBySignature map[string][]graphNode,
) (map[graphNode][]graphNode, []SuppressedEdge) {
	out := make(map[graphNode][]graphNode)
	var suppressed []SuppressedEdge
	inClosure := make(map[ComponentKey]bool, len(closure))
	for _, key := range closure {
		inClosure[key] = true
	}

	for _, key := range closure {
		fragment := fragments[key]

		componentSigs := make(map[string]bool, len(fragment.Functions))
		for _, fn := range fragment.Functions {
			node := graphNode{Component: key, Function: fn.Signature}
			if _, ok := out[node]; !ok {
				out[node] = nil
			}
			componentSigs[fn.Signature] = true
		}

		// resolve maps one edge to the concrete target nodes it could reach.
		// Internal edges resolve within the component; external edges resolve to
		// other components in the dependency closure.
		resolve := func(e callEdge) []graphNode {
			if e.internal {
				if componentSigs[e.target] {
					return []graphNode{{Component: key, Function: e.target}}
				}
				return nil
			}
			var targets []graphNode
			for _, callee := range functionsBySignature[e.target] {
				if callee.Component == key || !inClosure[callee.Component] {
					continue
				}
				targets = append(targets, callee)
			}
			return targets
		}

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

		// Interface-dispatch candidates are deferred and grouped per call site so
		// ambiguity (>1 impl in closure) is detected across all sibling edges,
		// including siblings that cross the internal/external boundary.
		dispatchGroups := make(map[dispatchGroupKey][]callEdge)
		for _, e := range edges {
			caller := graphNode{Component: key, Function: e.caller}
			switch e.resolution {
			case ResolutionExact:
				for _, callee := range resolve(e) {
					out[caller] = append(out[caller], callee)
				}
			case ResolutionInterfaceDispatch:
				gk := dispatchGroupKey{Component: key, Caller: e.caller, CallSite: e.callSite, MethodName: e.method, Arity: e.arity}
				dispatchGroups[gk] = append(dispatchGroups[gk], e)
			case ResolutionNameOnly:
				suppressed = append(suppressed, suppressedEdge(key, e, SuppressReasonNameOnly, candidateComponents(resolve(e))))
			default: // ResolutionUnknown and any future unhandled kind: fail closed.
				suppressed = append(suppressed, suppressedEdge(key, e, SuppressReasonUnknown, candidateComponents(resolve(e))))
			}
		}

		for _, gk := range sortedDispatchKeys(dispatchGroups) {
			caller := graphNode{Component: key, Function: gk.Caller}
			distinct := map[graphNode]bool{}
			var targets []graphNode
			for _, e := range dispatchGroups[gk] {
				for _, t := range resolve(e) {
					if !distinct[t] {
						distinct[t] = true
						targets = append(targets, t)
					}
				}
			}
			switch {
			case len(targets) == 1:
				out[caller] = append(out[caller], targets[0])
			case len(targets) > 1:
				suppressed = append(suppressed, SuppressedEdge{
					Caller:     CallFrame{Component: key, Function: gk.Caller},
					MethodName: gk.MethodName,
					Arity:      gk.Arity,
					Reason:     SuppressReasonAmbiguousDispatch,
					Candidates: candidateComponents(targets),
				})
				// len(targets) == 0: no implementation in closure -> unreachable,
				// nothing to traverse and nothing to record.
			}
		}
	}
	return out, suppressed
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
		Caller:     CallFrame{Component: from, Function: e.caller},
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
	path []CallFrame,
	visiting map[graphNode]bool,
	out *Result,
) {
	if visiting[current] {
		return
	}
	visiting[current] = true
	defer delete(visiting, current)

	path = append(path, CallFrame{Component: current.Component, Function: current.Function})
	for _, op := range opsByNode[current] {
		frames := append([]CallFrame(nil), path...)
		out.Chains = append(out.Chains, FindingChain{
			FindingID:  op.FindingID,
			RuleID:     op.RuleID,
			Symbol:     op.Symbol,
			Frames:     frames,
			Confidence: ConfidenceHigh,
		})
	}
	for _, next := range adjacency[current] {
		trace(next, adjacency, opsByNode, path, visiting, out)
	}
}
