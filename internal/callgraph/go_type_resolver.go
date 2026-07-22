// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "github.com/scanoss/crypto-finder/internal/callgraph/contracts"

// GoContractTypeResolver applies return types from the Go contracts KB.
type GoContractTypeResolver struct {
	kb *contracts.KnowledgeBase
}

// NewGoContractTypeResolver creates a resolver backed by the supplied KB.
func NewGoContractTypeResolver(kb *contracts.KnowledgeBase) *GoContractTypeResolver {
	return &GoContractTypeResolver{kb: kb}
}

// NewGoContractTypeResolverFromEmbedded loads the embedded Go KB. Contract
// load failures degrade to a no-op resolver.
func NewGoContractTypeResolverFromEmbedded() *GoContractTypeResolver {
	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		return NewGoContractTypeResolver(nil)
	}
	return NewGoContractTypeResolver(kb)
}

// ResolveTypes fills missing declaration return types from unconditional contracts.
func (r *GoContractTypeResolver) ResolveTypes(graph *CallGraph, _ []PackageDir) error {
	if r.kb == nil || len(r.kb.Contracts) == 0 {
		return nil
	}
	for _, fn := range graph.Functions {
		if fn.ReturnType != "" {
			continue
		}
		matches := r.kb.ContractsForTolerant(fn.ID.String(), len(fn.Parameters))
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
