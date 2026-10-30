// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"maps"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// cppPassBound caps the rounds that propagate a variable's type into the next
// producer (`fam = Family::create()`, `ph = fam->from_params()`,
// `ph->derive_key()`). Each round can only add types learned from the previous
// one, so the bound only matters for chains deeper than any real code shows.
const cppPassBound = 8

// resolveCPPDeducedReceiverCallees types the receivers of calls on variables
// the source declares `auto` (or never declares in the function) from the
// contract KB return type of the call that produced them:
//
//	auto h = Botan::HashFunction::create("SHA-256");
//	h->update(x);  // auto.update -> std::unique_ptr<Botan::HashFunction>.update
//
// The C++ parser keys a receiver call on the declared type's text, which for
// `auto` is the keyword itself; the deduced type only exists here, where the
// KB is loaded. It is the C++ counterpart of resolveGoAssignedVarCallees.
//
// Conservative on two axes. The per-function variable map cannot see block
// scope, so a variable bound to two different producer types anywhere in the
// function is dropped, never guessed. And a call whose receiver carries an
// explicit declared type is never rewritten.
func resolveCPPDeducedReceiverCallees(graph *CallGraph, kb *contracts.KnowledgeBase, ecosystem string) {
	if kb == nil || ecosystem != ecosystemCPP {
		return
	}
	resolved := 0
	for callerKey, fn := range graph.Functions {
		resolved += resolveCPPDeducedReceiversInFunction(graph, callerKey, fn, kb)
	}
	if resolved > 0 {
		log.Info().Int("resolved", resolved).Msg("Resolved C++ auto receivers via contract KB")
	}
}

func resolveCPPDeducedReceiversInFunction(graph *CallGraph, callerKey string, fn *FunctionDecl, kb *contracts.KnowledgeBase) int {
	varTypes := cppAssignedVarContractTypes(fn, kb)
	if len(varTypes) == 0 {
		return 0
	}
	resolved := 0
	oldKeys := make(map[string]bool)
	for i := range fn.Calls {
		call := &fn.Calls[i]
		if call.ReceiverVar == "" || !cppDeducedType(call.Callee.Type) {
			continue
		}
		receiverType, ok := varTypes[call.ReceiverVar]
		if !ok {
			continue
		}
		oldKeys[call.Callee.String()] = true
		call.Callee.Type = receiverType
		addCaller(graph.Callers, call.Callee.String(), callerKey)
		recordCallEdgeResolution(graph, callerKey, call.Callee.String(), EdgeKindExact, "", call)
		resolved++
	}
	reconcileRewrittenCallers(graph, callerKey, fn, oldKeys)
	return resolved
}

// cppAssignedVarContractTypes maps each variable the function binds to a call
// result onto the receiver type of that call's unconditional KB return. A
// producer whose own receiver is a deduced variable is looked up under the
// type learned for that variable, so the map is grown to a fixed point before
// any call is rewritten: a later round that finds a conflicting binding can
// still drop a variable, and nothing was rewritten on its earlier guess.
func cppAssignedVarContractTypes(fn *FunctionDecl, kb *contracts.KnowledgeBase) map[string]string {
	conflicted := make(map[string]bool)
	var types map[string]string
	for range cppPassBound {
		next := make(map[string]string)
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if call.AssignedVar == "" || conflicted[call.AssignedVar] {
				continue
			}
			producer := call.Callee
			if call.ReceiverVar != "" && cppDeducedType(producer.Type) {
				producer.Type = types[call.ReceiverVar]
			}
			ret := cppReceiverTypeFromReturn(unconditionalContractReturn(kb.ContractsFor(cppContractMethod(&producer), len(call.Arguments))))
			if ret == "" {
				continue
			}
			if prev, seen := next[call.AssignedVar]; seen && prev != ret {
				conflicted[call.AssignedVar] = true
				delete(next, call.AssignedVar)
				continue
			}
			next[call.AssignedVar] = ret
		}
		if maps.Equal(types, next) {
			break
		}
		types = next
	}
	return types
}

// cppDeducedType reports whether a receiver's recorded type is one the source
// left to the compiler: `auto`, `decltype(auto)`, or no declaration in scope.
func cppDeducedType(typeName string) bool {
	switch typeName {
	case "", "auto", "decltype(auto)":
		return true
	}
	return false
}

// cppReceiverTypeFromReturn turns a KB return type into the type the C++
// parser would record for a variable declared with it: `const X&`, `X*` and
// `X&&` all declare a receiver typed `X`. Template arguments are kept
// (`std::unique_ptr<Botan::HashFunction>`), as the parser keeps them.
func cppReceiverTypeFromReturn(ret string) string {
	ret = strings.TrimSpace(ret)
	for {
		trimmed := strings.TrimSpace(strings.TrimRight(ret, "*&"))
		trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, " const"))
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "const "))
		if trimmed == ret {
			break
		}
		ret = trimmed
	}
	return cppCanonicalType(ret)
}
