// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"regexp"
	"strings"
)

// A function handed to an API that runs it (a thread target, a sort
// comparator, a timer callback) is reached through no call expression of its
// own. The registering function gets an implicit reference edge to it, so the
// callback is as reachable as its registrar and no more: a registrar nothing
// calls leaves its callbacks unreachable. The edge is added only when the API
// is a known callback-invoking one at a known argument, and the argument names
// a function; the builder then keeps it only when that function is declared.

// callbackAPI is where a callback-invoking API takes its function: argument
// positions (0-based) and keyword names.
type callbackAPI struct {
	positions []int
	keywords  []string
}

func positional(positions ...int) callbackAPI { return callbackAPI{positions: positions} }

var (
	callbackIdentifier = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
	callbackKeyword    = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=([^=].*)?$`)
)

// callbackArguments returns the source text of the arguments the API takes a
// function in.
func callbackArguments(args []string, api callbackAPI) []string {
	var out []string
	for i, arg := range args {
		arg = strings.TrimSpace(arg)
		if m := callbackKeyword.FindStringSubmatch(arg); m != nil {
			for _, keyword := range api.keywords {
				if m[1] == keyword {
					out = append(out, strings.TrimSpace(m[2]))
				}
			}
			continue
		}
		for _, position := range api.positions {
			if position == i {
				out = append(out, arg)
			}
		}
	}
	return out
}

// callbackReference builds the reference edge from the call that registers a
// callback to the function it names.
func callbackReference(registrar *FunctionCall, callee FunctionID, arg string) *FunctionCall {
	return &FunctionCall{
		Callee:    callee,
		Raw:       arg,
		FilePath:  registrar.FilePath,
		Line:      registrar.Line,
		StartCol:  registrar.StartCol,
		EndCol:    registrar.EndCol,
		Reference: true,
	}
}

// appendCallbackReference adds a reference unless the same edge from the same
// call is already there.
func appendCallbackReference(out []FunctionCall, ref *FunctionCall) []FunctionCall {
	for i := range out {
		if out[i].Callee == ref.Callee && out[i].Line == ref.Line && out[i].StartCol == ref.StartCol {
			return out
		}
	}
	return append(out, *ref)
}

// indexCallbackReference records a reference edge as an exact call edge when
// its target is a declared function. A target that is not declared adds
// nothing: a reference never expands to overloads, subtypes or name matches.
func (b *Builder) indexCallbackReference(graph *CallGraph, callerKey string, call *FunctionCall, idx dispatchIndexes) {
	key := call.Callee.String()
	if _, declared := graph.Functions[key]; !declared {
		if b.ecosystem != ecosystemPython {
			return
		}
		public, ok := pythonPublicPathDeclaration(graph, call.Callee, key)
		if !ok {
			return
		}
		key = public
	}
	idx.addCallerIndexed(graph.Callers, key, callerKey)
	recordCallEdgeResolution(graph, callerKey, key, EdgeKindExact, "", call)
}
