// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "github.com/scanoss/crypto-finder/internal/callgraph/contracts"

// RustContractTypeResolver applies return types from the Rust contracts KB.
type RustContractTypeResolver struct {
	kb *contracts.KnowledgeBase
}

// NewRustContractTypeResolver creates a resolver backed by the supplied KB.
func NewRustContractTypeResolver(kb *contracts.KnowledgeBase) *RustContractTypeResolver {
	return &RustContractTypeResolver{kb: kb}
}

// NewRustContractTypeResolverFromEmbedded loads the embedded Rust KB. Contract
// load failures degrade to a no-op resolver.
func NewRustContractTypeResolverFromEmbedded() *RustContractTypeResolver {
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		return NewRustContractTypeResolver(nil)
	}
	return NewRustContractTypeResolver(kb)
}

// ResolveTypes fills missing declaration return types from unconditional contracts.
func (r *RustContractTypeResolver) ResolveTypes(graph *CallGraph, _ []PackageDir) error {
	if r.kb == nil || len(r.kb.Contracts) == 0 {
		return nil
	}
	for _, fn := range graph.Functions {
		if fn.ReturnType != "" {
			continue
		}
		for _, contract := range r.kb.ContractsForTolerant(rustFunctionFQN(fn), len(fn.Parameters)) {
			if contract.When == nil && contract.Return.Type != "" {
				fn.ReturnType = contract.Return.Type
				break
			}
		}
	}
	return nil
}

func rustFunctionFQN(fn *FunctionDecl) string {
	if fn.ID.Type != "" {
		return fn.ID.Package + "::" + fn.ID.Type + "." + fn.ID.Name
	}
	return fn.ID.Package + "::" + fn.ID.Name
}
