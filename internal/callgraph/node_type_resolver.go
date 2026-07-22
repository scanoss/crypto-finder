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
		for _, contract := range r.kb.ContractsFor(fn.ID.String(), len(fn.Parameters)) {
			if contract.When == nil && contract.Return.Type != "" {
				fn.ReturnType = contract.Return.Type
				break
			}
		}
	}
	return nil
}
