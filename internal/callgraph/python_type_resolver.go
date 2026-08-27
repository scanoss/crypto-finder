// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

import (
	"strings"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// PythonContractTypeResolver is a thin, contract-only type resolver for the
// Python ecosystem. It annotates FunctionDecl.ReturnType with the return type
// declared in the Python contracts KB when:
//   - The function's fully-qualified name and arity match an unconditional
//     contract in the KB, AND
//   - The function's ReturnType is currently empty (parser did not set it).
//
// This resolver is NOT a general Python type inference engine. It does not
// infer types for arbitrary Python code and does not traverse import or
// assignment chains on its own. Chains through untyped intermediates are an
// accepted, documented limitation (see REQ-4.2, CC-4 in the spec).
//
// The resolver always returns nil error — contract gaps are never fatal.
type PythonContractTypeResolver struct {
	kb *contracts.KnowledgeBase
}

// NewPythonContractTypeResolver creates a resolver backed by the supplied KB.
// If kb is nil, the resolver is a safe no-op (produces no type resolutions).
func NewPythonContractTypeResolver(kb *contracts.KnowledgeBase) *PythonContractTypeResolver {
	return &PythonContractTypeResolver{kb: kb}
}

// NewPythonContractTypeResolverFromEmbedded creates a resolver by loading the
// embedded Python KB lazily. If the KB cannot be loaded, the resolver is a
// safe no-op. This is the constructor wired into NewTypeResolverForEcosystem.
func NewPythonContractTypeResolverFromEmbedded() *PythonContractTypeResolver {
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		// Graceful degradation: no KB → resolver is a no-op.
		return &PythonContractTypeResolver{kb: nil}
	}
	return &PythonContractTypeResolver{kb: kb}
}

// ResolveTypes iterates over each FunctionDecl in the graph and, for any
// function with an empty ReturnType whose FQN + arity match an unconditional
// contract in the KB, sets ReturnType to the contract's declared return type.
//
// sourceRoots is unused by this resolver (contract-only, no filesystem access).
func (r *PythonContractTypeResolver) ResolveTypes(graph *CallGraph, _ []PackageDir) error {
	if r.kb == nil || len(r.kb.Contracts) == 0 {
		return nil
	}

	for _, fn := range graph.Functions {
		if fn.ReturnType != "" {
			// Parser already set a return type — do not overwrite.
			continue
		}

		fqn := pythonFunctionFQN(fn)
		arity := len(fn.Parameters)
		contractList := r.kb.ContractsForTolerant(fqn, arity)

		// Find the first unconditional contract (When == nil) and apply it.
		for i := range contractList {
			c := &contractList[i]
			if c.When == nil && c.Return.Type != "" {
				fn.ReturnType = c.Return.Type
				break
			}
		}
	}

	return nil
}

// PythonTypeResolverChain composes the Python ecosystem's type resolvers in
// order (row 13, python-parser-parity-2, design.md D7): contract-KB
// resolution first (unconditional signature matches against the embedded
// KB), an optional dependency resolver second (row 14's
// PythonDependencyTypeResolver — nil until that row wires it in, a safe
// no-op), then propagatePythonAssignedVarTypes LAST — so the resolver-half
// receiver-type propagation can see any ReturnType either earlier step
// itself just filled in. Reverting row 14 (dependency nil) leaves rows A-C
// (including this chain's own propagation step) green; reverting this
// row's propagation step is a config change, not implemented here.
type PythonTypeResolverChain struct {
	contract   *PythonContractTypeResolver
	dependency TypeResolver
}

// NewPythonTypeResolverChain creates a chain backed by the embedded
// contract KB. dependency stays nil until row 14 wires
// NewPythonDependencyTypeResolver(...) in.
func NewPythonTypeResolverChain() *PythonTypeResolverChain {
	return &PythonTypeResolverChain{contract: NewPythonContractTypeResolverFromEmbedded()}
}

// ResolveTypes runs the contract resolver, the optional dependency
// resolver, then propagatePythonAssignedVarTypes, in that fixed order.
// Always returns nil — an inner resolver's own error is already absorbed
// by design (contract/dependency resolvers document a nil-error,
// graceful-degradation contract); propagation itself performs no I/O and
// cannot fail.
func (c *PythonTypeResolverChain) ResolveTypes(graph *CallGraph, sourceRoots []PackageDir) error {
	if c.contract != nil {
		if err := c.contract.ResolveTypes(graph, sourceRoots); err != nil {
			return err
		}
	}
	if c.dependency != nil {
		if err := c.dependency.ResolveTypes(graph, sourceRoots); err != nil {
			return err
		}
	}
	propagatePythonAssignedVarTypes(graph)
	return nil
}

// propagatePythonAssignedVarTypes performs one ordered pass over each
// Python-origin FunctionDecl's own Calls (row 13's resolver half): for a
// call with a non-empty AssignedVar whose Callee resolves (via
// graph.Functions, keyed by FunctionID.String()) to an in-graph
// FunctionDecl with a non-empty ReturnType, that var->type binding is
// recorded; a LATER call in the SAME decl whose ReceiverVar matches a
// tracked var has its Callee Package/Type rewritten to the tracked type
// (Package from the CALLING decl's own package — a Python type annotation
// is a bare name, never a fully qualified path) and ResolvedReceiverType
// set. Never crosses FunctionDecl boundaries, matching the parser's own
// scope-local bounding for partials/callables (row 11) and the parser-half
// varTypes (row 13 §10.2).
//
// Gated to `.py`/`.pyi`-sourced declarations ONLY (FunctionDecl.FilePath):
// AssignedVar/ReceiverVar are language-agnostic FunctionCall fields shared
// by every parser, so an ungated pass would risk mutating an unrelated
// ecosystem's calls on a coincidental variable-name match — unlike the
// contract resolver above, whose FQN+arity KB lookup is inherently
// self-limiting to the Python KB's own method names.
func propagatePythonAssignedVarTypes(graph *CallGraph) {
	for _, fn := range graph.Functions {
		if fn == nil || len(fn.Calls) == 0 || !isPythonSourceFile(fn.FilePath) {
			continue
		}
		propagatePythonAssignedVarTypesForDecl(fn, graph)
	}
}

// propagatePythonAssignedVarTypesForDecl runs propagatePythonAssignedVarTypes's
// document-order pass for exactly one FunctionDecl, extracted purely to
// keep the outer function's cyclomatic/cognitive complexity low.
func propagatePythonAssignedVarTypesForDecl(fn *FunctionDecl, graph *CallGraph) {
	var varTypes map[string]string
	for i := range fn.Calls {
		call := &fn.Calls[i]
		if call.ReceiverVar != "" && varTypes != nil {
			if typeName, ok := varTypes[call.ReceiverVar]; ok {
				call.Callee.Package = fn.ID.Package
				call.Callee.Type = typeName
				call.ResolvedReceiverType = typeName
			}
		}
		if call.AssignedVar == "" {
			continue
		}
		callee := graph.Functions[call.Callee.String()]
		if callee == nil || callee.ReturnType == "" {
			continue
		}
		if varTypes == nil {
			varTypes = make(map[string]string)
		}
		varTypes[call.AssignedVar] = callee.ReturnType
	}
}

// isPythonSourceFile reports whether filePath is a Python source/stub file
// — the same suffix test PythonParser.ParseDirectory itself uses to select
// files to parse.
func isPythonSourceFile(filePath string) bool {
	return strings.HasSuffix(filePath, ".py") || strings.HasSuffix(filePath, ".pyi")
}

// pythonFunctionFQN derives the fully-qualified method name for a FunctionDecl
// as it appears in the Python contracts KB: "Package.Type.Name" for methods,
// "Package.Name" for module-level functions.
//
// This must match the KB's `method:` field exactly.
func pythonFunctionFQN(fn *FunctionDecl) string {
	if fn.ID.Type != "" {
		return fn.ID.Package + "." + fn.ID.Type + "." + fn.ID.Name
	}
	return fn.ID.Package + "." + fn.ID.Name
}
