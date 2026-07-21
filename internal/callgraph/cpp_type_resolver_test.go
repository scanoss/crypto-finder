// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestCPPContractTypeResolver_UsesCanonicalFunctionIDs(t *testing.T) {
	kb := &contracts.KnowledgeBase{
		Ecosystem: "cpp",
		Contracts: map[string][]contracts.Contract{
			"example/crypto.Botan::HashFunction.create#1": {{
				Return: contracts.ContractReturn{Type: "Botan::HashFunction", Confidence: "high"},
			}},
		},
	}
	fn := &FunctionDecl{
		ID:         FunctionID{Package: "example/crypto", Type: "Botan::HashFunction", Name: "create"},
		Parameters: []FunctionParameter{{Name: "algorithm"}},
	}

	if err := NewCPPContractTypeResolver(kb).ResolveTypes(buildTestCallGraph(fn), nil); err != nil {
		t.Fatalf("ResolveTypes error: %v", err)
	}
	if fn.ReturnType != "Botan::HashFunction" {
		t.Fatalf("ReturnType = %q, want Botan::HashFunction", fn.ReturnType)
	}
}
