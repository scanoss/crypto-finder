// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestCPPContractRolesUseProjectIndependentQualifiedIdentity(t *testing.T) {
	t.Parallel()

	kb := &contracts.KnowledgeBase{Ecosystem: "cpp", Contracts: map[string][]contracts.Contract{
		"CryptoPP::SHA256.Update#2": {{
			Role: "config",
			Parameters: []contracts.ParameterContract{{
				Index: intPtr(1), Role: "metadata-contributing",
				Contributes: &contracts.Contribution{Property: "inputLength", Derivation: "argument_value"},
			}},
		}},
	}}
	call := &callgraph.FunctionCall{
		Callee:    callgraph.FunctionID{Package: "app", Type: "CryptoPP::SHA256", Name: "Update"},
		Arguments: []string{"input", "length"},
		FilePath:  "digest.cpp",
		Line:      3,
	}
	ctx := &exportBuildContext{kb: kb, graph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}}}

	support := buildDerivedSupportingCall(ctx, &callgraph.FunctionDecl{ID: callgraph.FunctionID{Package: "app", Name: "digest"}}, call)
	if support.Category != "config" || support.SupportingCall == nil || len(support.SupportingCall.ParameterRoles) != 1 {
		t.Fatalf("support = %#v, want role and parameter contract", support)
	}
}

func TestCPPContractRolesPreserveLocalQualifiedDeclaration(t *testing.T) {
	t.Parallel()

	kb := &contracts.KnowledgeBase{Ecosystem: "cpp", Contracts: map[string][]contracts.Contract{
		"CryptoPP::SHA256.Update#2": {{Role: "config"}},
	}}
	call := &callgraph.FunctionCall{Callee: callgraph.FunctionID{Package: "app", Type: "CryptoPP::SHA256", Name: "Update"}}
	ctx := &exportBuildContext{kb: kb, graph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		call.Callee.String(): {ID: call.Callee},
	}}}

	if matches := contractMatchesForCall(ctx, call, 2); len(matches) != 0 {
		t.Fatalf("matches = %#v, want local declaration to suppress library fallback", matches)
	}
}
