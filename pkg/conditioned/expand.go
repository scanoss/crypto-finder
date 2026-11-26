// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package conditioned

import (
	"encoding/json"
	"strings"

	"github.com/scanoss/reach/graphfrag"
)

// Expanding a dependency closure: the miner specialized each component's
// generic findings with the values the component itself passes, but a library
// method that hands its parameter to a selector (bcprov's
// DefaultJcaJceHelper.createSecretKeyFactory(algorithm) ->
// SecretKeyFactory.getInstance(algorithm)) receives its values from the
// components that call it (bcpkix's "PBKDF-OpenSSL"). Over a pinned closure
// the values are known: NewPlan picks the generic findings whose call a
// catalog rule specializes and whose selector is still a parameter, the stitch
// traces their calls (graphfrag.StitchOptions.SelectorCalls), and Expand
// specializes each anchor with the values found, as a scan does with its own.

// Anchor is a generic finding of a closure component on a call that
// catalog rules specialize, with a selector the component leaves unresolved.
type Anchor struct {
	Component graphfrag.ComponentKey
	Operation *graphfrag.CryptoOperation
	Rules     []*Rule
	// call indexes Plan.Calls.
	call int
}

// Plan is the anchors of a closure and the calls the stitch traces for them,
// one per distinct call: several findings on one call share it.
type Plan struct {
	Anchors []Anchor
	Calls   []graphfrag.SelectorCall
}

// NewPlan finds the anchors among the crypto operations of every fragment but
// root's. An anchor is an operation without a parameterCondition of its own,
// on a call catalog rules name, with an argument whose provenance is a
// parameter of the function the call is made in.
func NewPlan(fragments map[graphfrag.ComponentKey]graphfrag.Fragment, root graphfrag.ComponentKey, catalog *Catalog) Plan {
	var plan Plan
	if catalog.Len() == 0 {
		return plan
	}
	type callKey struct {
		component graphfrag.ComponentKey
		function  string
		line      int
		callee    string
	}
	calls := make(map[callKey]int)
	for key := range fragments {
		if key == root {
			continue
		}
		ops := fragments[key].CryptoOperations
		for i := range ops {
			op := &ops[i]
			if op.CryptoCall == nil || hasParameterCondition(op.Metadata) || !parameterSelector(op.CryptoCall.Parameters) {
				continue
			}
			rules := catalog.RulesFor(op.CryptoCall.FunctionName)
			if len(rules) == 0 {
				continue
			}
			ck := callKey{component: key, function: op.Function, line: op.CryptoCall.Line, callee: op.CryptoCall.FunctionName}
			index, seen := calls[ck]
			if !seen {
				index = len(plan.Calls)
				calls[ck] = index
				plan.Calls = append(plan.Calls, graphfrag.SelectorCall{Component: key, Function: op.Function, Parameters: op.CryptoCall.Parameters})
			}
			plan.Anchors = append(plan.Anchors, Anchor{Component: key, Operation: op, Rules: rules, call: index})
		}
	}
	return plan
}

// hasParameterCondition reports that an operation's metadata names a
// parameterCondition: it is already a specialized asset.
func hasParameterCondition(metadata json.RawMessage) bool {
	if len(metadata) == 0 {
		return false
	}
	var fields map[string]any
	if json.Unmarshal(metadata, &fields) != nil {
		return false
	}
	value, ok := fields["parameterCondition"].(string)
	return ok && value != ""
}

// parameterSelector reports that some argument did not resolve and its
// provenance is a parameter of the enclosing function, which callers fill.
func parameterSelector(params []graphfrag.Parameter) bool {
	for i := range params {
		if strings.TrimSpace(params[i].ResolvedValue) != "" {
			continue
		}
		for j := range params[i].SourceNodes {
			if node := &params[i].SourceNodes[j]; node.Type == "PARAMETER" && node.ParameterIndex != nil {
				return true
			}
		}
	}
	return false
}

// Expansion is what one anchor yields over the closure.
type Expansion struct {
	Anchor *Anchor
	// Specializations hold one asset per rule and value, in value order.
	Specializations []ClosureSpecialization
	// Truncated says the value walk was cut, so a value may be missing.
	Truncated bool
}

// ClosureSpecialization is a Specialization with the verdict of the call
// sites that pass its value.
type ClosureSpecialization struct {
	Specialization
	Reachability     string
	UnresolvedReason string
}

// Expand specializes every anchor of p with values, the stitch's answer to
// p.Calls (graphfrag.Result.SelectorValues). An anchor's assets are its rules
// applied to each argument list the closure passes the call: the values are
// distinct, so each rule yields at most one asset per value.
func (p Plan) Expand(values []graphfrag.SelectorValues) []Expansion {
	out := make([]Expansion, 0, len(p.Anchors))
	for i := range p.Anchors {
		anchor := &p.Anchors[i]
		if anchor.call >= len(values) {
			continue
		}
		answer := values[anchor.call]
		expansion := Expansion{Anchor: anchor, Truncated: answer.Truncated}
		for _, variant := range answer.Variants {
			args := arguments(variant.Parameters)
			for _, rule := range anchor.Rules {
				spec, ok := rule.Specialize(args)
				if !ok {
					continue
				}
				expansion.Specializations = append(expansion.Specializations, ClosureSpecialization{
					Specialization: spec, Reachability: variant.Reachability, UnresolvedReason: variant.UnresolvedReason,
				})
			}
		}
		if len(expansion.Specializations) > 0 || expansion.Truncated {
			out = append(out, expansion)
		}
	}
	return out
}

func arguments(params []graphfrag.Parameter) []Argument {
	args := make([]Argument, len(params))
	for i := range params {
		args[i] = Argument{Value: params[i].ResolvedValue, Type: params[i].Type, Name: params[i].VariableName, Keyword: params[i].Keyword}
	}
	return args
}

// TerminalColumns are the columns of the call op is a finding on, read from
// the edges of fragment, op's component: the narrowest call made in op's
// function on its line whose span holds the asset's (startCol, endCol). Zero
// when no edge holds it.
func TerminalColumns(fragment *graphfrag.Fragment, op *graphfrag.CryptoOperation, startCol, endCol int) (start, end int) {
	if op.CryptoCall == nil {
		return 0, 0
	}
	consider := func(caller string, line, s, e int) {
		if caller != op.Function || line != op.CryptoCall.Line || s <= 0 || s > startCol || e < endCol {
			return
		}
		if start == 0 || e-s < end-start {
			start, end = s, e
		}
	}
	for i := range fragment.ExternalCalls {
		c := &fragment.ExternalCalls[i]
		consider(c.Caller, c.CallSite, c.StartCol, c.EndCol)
	}
	for i := range fragment.InternalEdges {
		e := &fragment.InternalEdges[i]
		consider(e.Caller, e.CallSite, e.StartCol, e.EndCol)
	}
	return start, end
}
