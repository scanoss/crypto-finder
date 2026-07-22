// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

import (
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
