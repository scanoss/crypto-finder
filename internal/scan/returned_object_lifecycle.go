// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "github.com/scanoss/crypto-finder/internal/callgraph"

// maxReturnedObjectDepth bounds how many methods a crypto object is followed
// through when each one returns it to its caller. A helper that returns the
// object counts as one level; a helper that returns another helper's result
// counts as two.
const maxReturnedObjectDepth = 3

// objectSite is one call in the lifecycle of a crypto object, with the method
// it is written in.
type objectSite struct {
	fn   *callgraph.FunctionDecl
	call *callgraph.FunctionCall
}

// returnedObjectLifecycleCalls follows the object a terminal call produces out
// of its method when the method returns it, and collects the object's
// lifecycle in every caller that keeps it:
//
//	static KeyPairGenerator newKpg() { return KeyPairGenerator.getInstance("RSA"); }
//	KeyPairGenerator kpg = newKpg(); kpg.initialize(2048);
//
// Here kpg.initialize(2048) configures the generator getInstance created, so it
// is one of that finding's supporting calls. In each caller the call to the
// helper takes the place of the terminal call: the calls on the variable it is
// bound to, after the binding, and the links of its fluent chain. The call's
// own receiver is the helper's owner, not the object, so its calls are never
// selected.
//
// The walk is deterministic (callers in key order, calls in source order) and
// stops after maxReturnedObjectDepth methods or at a method already visited.
func returnedObjectLifecycleCalls(ctx *exportBuildContext, fn *callgraph.FunctionDecl, terminal *callgraph.FunctionCall) []objectSite {
	visited := map[string]bool{}
	return collectReturnedObjectSites(ctx, fn, terminal, 0, visited)
}

func collectReturnedObjectSites(ctx *exportBuildContext, fn *callgraph.FunctionDecl, producer *callgraph.FunctionCall, depth int, visited map[string]bool) []objectSite {
	if ctx == nil || ctx.graph == nil || depth >= maxReturnedObjectDepth || !returnsCallResult(fn, producer) {
		return nil
	}
	fnKey := fn.ID.String()
	if visited[fnKey] {
		return nil
	}
	visited[fnKey] = true

	var out []objectSite
	for _, callerKey := range ctx.reverseCallersOf(fnKey) {
		caller := ctx.graph.Functions[callerKey]
		if caller == nil {
			continue
		}
		for i := range caller.Calls {
			if caller.Calls[i].Callee.String() != fnKey {
				continue
			}
			for _, j := range returnedObjectCallIndices(caller, i) {
				out = append(out, objectSite{fn: caller, call: &caller.Calls[j]})
			}
			out = append(out, collectReturnedObjectSites(ctx, caller, &caller.Calls[i], depth+1, visited)...)
		}
	}
	return out
}

// returnedObjectCallIndices returns the lifecycle of the object a call returns
// in its caller, the same selection a factory terminal gets.
func returnedObjectCallIndices(caller *callgraph.FunctionDecl, callIdx int) []int {
	identities := make([]objectIdentity, len(caller.Calls))
	for i := range caller.Calls {
		c := &caller.Calls[i]
		identities[i] = objectIdentity{ReceiverVar: c.ReceiverVar, AssignedVar: c.AssignedVar, ChainID: c.ChainID}
	}
	identities[callIdx].ReceiverVar = ""
	return lifecycleCallIndices(identities, callIdx)
}

// returnsCallResult reports whether fn returns the object call produces:
// `return f()`, or `x = f(); ... return x`. A return source names its producer
// by callee only, so the producer must be the one call to that callee in fn;
// with two, the returned object could be either.
func returnsCallResult(fn *callgraph.FunctionDecl, call *callgraph.FunctionCall) bool {
	if fn == nil || call == nil || len(fn.ReturnSources) == 0 {
		return false
	}
	callee := call.Callee.String()
	count := 0
	for i := range fn.Calls {
		if fn.Calls[i].Callee.String() == callee {
			count++
		}
	}
	if count != 1 {
		return false
	}
	for i := range fn.ReturnSources {
		if returnSourceIsCall(&fn.ReturnSources[i], call) {
			return true
		}
	}
	return false
}

func returnSourceIsCall(node *callgraph.SourceNode, call *callgraph.FunctionCall) bool {
	switch node.Type {
	case sourceNodeTypeCallResult:
		return node.CallTarget != nil && node.CallTarget.String() == call.Callee.String()
	case sourceNodeTypeVariable:
		if call.AssignedVar == "" || node.Name != call.AssignedVar {
			return false
		}
		for i := range node.SourceNodes {
			nested := &node.SourceNodes[i]
			if nested.Type == sourceNodeTypeCallResult && nested.CallTarget != nil && nested.CallTarget.String() == call.Callee.String() {
				return true
			}
		}
	}
	return false
}
