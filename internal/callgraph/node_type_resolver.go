// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "github.com/scanoss/crypto-finder/internal/callgraph/contracts"

// NodeContractTypeResolver applies return types from the Node contracts KB.
type NodeContractTypeResolver struct {
	kb *contracts.KnowledgeBase
}

// NewNodeContractTypeResolver creates a resolver backed by the supplied KB.
func NewNodeContractTypeResolver(kb *contracts.KnowledgeBase) *NodeContractTypeResolver {
	return &NodeContractTypeResolver{kb: kb}
}

// NewNodeContractTypeResolverFromEmbedded loads the embedded Node KB. Contract
// load failures degrade to a no-op resolver.
func NewNodeContractTypeResolverFromEmbedded() *NodeContractTypeResolver {
	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		return NewNodeContractTypeResolver(nil)
	}
	return NewNodeContractTypeResolver(kb)
}

// ResolveTypes fills missing declaration return types from unconditional contracts.
func (r *NodeContractTypeResolver) ResolveTypes(graph *CallGraph, _ []PackageDir) error {
	if r.kb == nil || len(r.kb.Contracts) == 0 {
		return nil
	}
	for _, fn := range graph.Functions {
		if fn.ReturnType != "" {
			continue
		}
		matches := r.kb.ContractsFor(fn.ID.String(), len(fn.Parameters))
		for i := range matches {
			contract := &matches[i]
			if contract.When == nil && contract.Return.Type != "" {
				fn.ReturnType = contract.Return.Type
				break
			}
		}
	}
	return nil
}

// resolveNodeAssignedVarCallees types Node method calls on a variable bound to
// the result of a contracted call:
//
//	const ec = new EC('secp256k1');   // contract: returns elliptic.ec
//	const key = ec.genKeyPair();      // was <module>.genKeyPair, now elliptic.ec.genKeyPair
//	key.sign(msgHash);                // elliptic.KeyPair.sign
//
// JavaScript carries no type to read at the declaration, so the type exists
// only here, where the KB is loaded. This is the Node counterpart of the Go and
// Python assigned-var passes. A variable is typed only with a type the KB
// declares methods on, so a rewrite always lands on a contract key.
func resolveNodeAssignedVarCallees(graph *CallGraph, kb *contracts.KnowledgeBase) {
	if kb == nil || kb.Ecosystem != ecosystemNode {
		return
	}
	receivers := contractReceiverTypes(kb)
	// A module's <module> declaration binds the variables its functions share,
	// so each file's module declaration is typed first and seeds the others.
	moduleDecls := nodeModuleDecls(graph)
	// To a fixed point: typing a receiver can reveal the next variable's
	// producer, and a fluent chain rooted at a newly typed receiver
	// (md.digest().toHex()) resolves only once its root has a type.
	for range 4 {
		pass := 0
		moduleTypes := make(map[string]map[string]string, len(moduleDecls))
		for file, fn := range moduleDecls {
			resolved, types := resolveNodeAssignedVarCalleesInFunction(graph, fn.ID.String(), fn, kb, receivers, nil)
			pass += resolved
			moduleTypes[file] = types
		}
		for callerKey, fn := range graph.Functions {
			if fn == nil || fn.FunctionType == functionTypeModuleInit {
				continue
			}
			resolved, _ := resolveNodeAssignedVarCalleesInFunction(graph, callerKey, fn, kb, receivers, moduleVariableTypes(fn, moduleTypes[fn.FilePath]))
			pass += resolved
		}
		if pass == 0 {
			break
		}
		resolveFluentChainCalleesByContract(graph, kb)
	}
}

// contractReceiverTypes returns the types the KB declares methods on.
func contractReceiverTypes(kb *contracts.KnowledgeBase) map[string]bool {
	receivers := make(map[string]bool)
	for _, group := range kb.Contracts {
		for i := range group {
			if pkg, _ := splitQualifiedTypeName(group[i].Method); pkg != "" {
				receivers[pkg] = true
			}
		}
	}
	return receivers
}

// nodeModuleDecls indexes each file's <module> declaration by file.
func nodeModuleDecls(graph *CallGraph) map[string]*FunctionDecl {
	decls := make(map[string]*FunctionDecl)
	for _, fn := range graph.Functions {
		if fn != nil && fn.FunctionType == functionTypeModuleInit {
			decls[fn.FilePath] = fn
		}
	}
	return decls
}

// moduleVariableTypes returns the module variable types a function sees: the
// module's, less any name the function binds itself as a parameter or from a
// call. A local declared any other way, as in `const ec = opts.ec`, is not
// visible here and would still inherit the module's type for ec.
func moduleVariableTypes(fn *FunctionDecl, moduleTypes map[string]string) map[string]string {
	if len(moduleTypes) == 0 {
		return nil
	}
	seen := make(map[string]string, len(moduleTypes))
	for name, typ := range moduleTypes {
		seen[name] = typ
	}
	for _, param := range fn.Parameters {
		delete(seen, param.Name)
	}
	for i := range fn.Calls {
		delete(seen, fn.Calls[i].AssignedVar)
	}
	return seen
}

// resolveNodeAssignedVarCalleesInFunction walks one function's calls in
// document order, starting from the seeded variable types, and returns the
// types it ends with. Rebinding a variable to a value of unknown type drops
// what was known about it, so a later call on that name is left alone.
func resolveNodeAssignedVarCalleesInFunction(graph *CallGraph, callerKey string, fn *FunctionDecl, kb *contracts.KnowledgeBase, receivers map[string]bool, seed map[string]string) (int, map[string]string) {
	varTypes := make(map[string]string, len(seed))
	for name, typ := range seed {
		varTypes[name] = typ
	}
	oldKeys := make(map[string]bool)
	resolved := 0
	for _, i := range assignmentPropagationOrder(fn.Calls) {
		call := &fn.Calls[i]
		if receiverType, ok := varTypes[call.ReceiverVar]; ok && call.Callee.Type == "" {
			pkg, typ := splitQualifiedTypeName(receiverType)
			oldKeys[call.Callee.String()] = true
			call.Callee = FunctionID{Package: pkg, Type: typ, Name: call.Callee.Name}
			addCaller(graph.Callers, call.Callee.String(), callerKey)
			recordCallEdgeResolution(graph, callerKey, call.Callee.String(), EdgeKindExact, "", call)
			resolved++
		}
		if call.AssignedVar == "" {
			continue
		}
		fqn, arity := splitMethodArity(&call.Callee)
		if arity < 0 {
			arity = len(call.Arguments)
		}
		if ret := unconditionalContractReturn(kb.ContractsFor(fqn, arity)); receivers[ret] {
			varTypes[call.AssignedVar] = ret
		} else {
			delete(varTypes, call.AssignedVar)
		}
	}
	reconcileRewrittenCallers(graph, callerKey, fn, oldKeys)
	return resolved, varTypes
}
