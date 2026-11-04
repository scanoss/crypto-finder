// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"sort"

	"github.com/scanoss/static-engine/callgraph"
)

// maxReturnedObjectDepth bounds how many methods a crypto object is followed
// through when each one returns it to its caller. A helper that returns the
// object counts as one level; a helper that returns another helper's result
// counts as two.
const maxReturnedObjectDepth = 3

// returnedObjectGraph is what the returned-object walk reads from a graph: the
// live call graph during a scan (liveReturnedObjectGraph), or the edges of a
// cached graph fragment during annotate (fragmentReturnedObjectGraph). Both
// run the same walk, so annotate follows a returned object exactly as a scan
// does.
type returnedObjectGraph interface {
	// callers returns the keys of the functions that call fnKey, in key order.
	callers(fnKey string) []string
	// calls returns the calls fnKey makes, in source order.
	calls(fnKey string) []returnedObjectCall
	// returnsCall reports whether fnKey returns the object its call at index
	// call produces.
	returnsCall(fnKey string, call int) bool
}

// returnedObjectCall is one call as the walk sees it: the function it calls
// and the object it is made on or bound to.
type returnedObjectCall struct {
	callee   string
	identity objectIdentity
}

// returnedObjectSite is one call in the lifecycle of a returned object: the
// call at index call in the function fnKey.
type returnedObjectSite struct {
	fnKey string
	call  int
}

// returnedObjectSites follows the object a terminal call produces out of its
// method when the method returns it, and collects the object's lifecycle in
// every caller that keeps it:
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
func returnedObjectSites(g returnedObjectGraph, fnKey string, terminal int) []returnedObjectSite {
	return collectReturnedObjectSites(g, fnKey, terminal, 0, map[string]bool{})
}

func collectReturnedObjectSites(g returnedObjectGraph, fnKey string, producer, depth int, visited map[string]bool) []returnedObjectSite {
	if depth >= maxReturnedObjectDepth || visited[fnKey] || !g.returnsCall(fnKey, producer) {
		return nil
	}
	visited[fnKey] = true

	var out []returnedObjectSite
	for _, callerKey := range g.callers(fnKey) {
		calls := g.calls(callerKey)
		for i := range calls {
			if calls[i].callee != fnKey {
				continue
			}
			for _, j := range returnedObjectCallIndices(calls, i) {
				out = append(out, returnedObjectSite{fnKey: callerKey, call: j})
			}
			out = append(out, collectReturnedObjectSites(g, callerKey, i, depth+1, visited)...)
		}
	}
	return out
}

// returnedObjectCallIndices returns the lifecycle of the object a call returns
// in its caller, the same selection a factory terminal gets.
func returnedObjectCallIndices(calls []returnedObjectCall, callIdx int) []int {
	identities := make([]objectIdentity, len(calls))
	for i := range calls {
		identities[i] = calls[i].identity
	}
	identities[callIdx].ReceiverVar = ""
	return lifecycleCallIndices(identities, callIdx)
}

// objectSite is one call in the lifecycle of a crypto object, with the method
// it is written in.
type objectSite struct {
	fn   *callgraph.FunctionDecl
	call *callgraph.FunctionCall
}

// returnedObjectLifecycleCalls runs returnedObjectSites on the live call graph.
func returnedObjectLifecycleCalls(ctx *exportBuildContext, fn *callgraph.FunctionDecl, terminal *callgraph.FunctionCall) []objectSite {
	if ctx == nil || ctx.graph == nil || fn == nil || terminal == nil {
		return nil
	}
	terminalIdx := -1
	for i := range fn.Calls {
		if &fn.Calls[i] == terminal {
			terminalIdx = i
		}
	}
	if terminalIdx < 0 {
		return nil
	}
	g := liveReturnedObjectGraph{ctx: ctx}
	sites := returnedObjectSites(g, fn.ID.String(), terminalIdx)
	out := make([]objectSite, 0, len(sites))
	for _, site := range sites {
		caller := ctx.graph.Functions[site.fnKey]
		out = append(out, objectSite{fn: caller, call: &caller.Calls[site.call]})
	}
	return out
}

// liveReturnedObjectGraph is the live call graph as a returnedObjectGraph.
type liveReturnedObjectGraph struct {
	ctx *exportBuildContext
}

func (g liveReturnedObjectGraph) callers(fnKey string) []string {
	var out []string
	for _, key := range g.ctx.reverseCallersOf(fnKey) {
		if g.ctx.graph.Functions[key] != nil {
			out = append(out, key)
		}
	}
	return out
}

func (g liveReturnedObjectGraph) calls(fnKey string) []returnedObjectCall {
	fn := g.ctx.graph.Functions[fnKey]
	if fn == nil {
		return nil
	}
	out := make([]returnedObjectCall, len(fn.Calls))
	for i := range fn.Calls {
		c := &fn.Calls[i]
		out[i] = returnedObjectCall{
			callee:   c.Callee.String(),
			identity: objectIdentity{ReceiverVar: c.ReceiverVar, AssignedVar: c.AssignedVar, ChainID: c.ChainID},
		}
	}
	return out
}

func (g liveReturnedObjectGraph) returnsCall(fnKey string, call int) bool {
	fn := g.ctx.graph.Functions[fnKey]
	return fn != nil && call >= 0 && call < len(fn.Calls) && returnsCallResult(fn, &fn.Calls[call])
}

// returnedCallees lists, sorted, the callees whose call result fn returns
// under returnsCallResult. Each names one call, since returnsCallResult only
// accepts a callee fn calls once. A graph fragment records the list on the
// function as returns_calls, which is all the walk needs to run on the
// fragment.
func returnedCallees(fn *callgraph.FunctionDecl) []string {
	if fn == nil || len(fn.ReturnSources) == 0 {
		return nil
	}
	var out []string
	for i := range fn.Calls {
		if returnsCallResult(fn, &fn.Calls[i]) {
			out = append(out, fn.Calls[i].Callee.String())
		}
	}
	sort.Strings(out)
	return out
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
