// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
)

// The export path builds its contract lookup key with fullFunctionName, which
// joins every FunctionID segment with ".". Rust KBs are authored with Rust's
// own module/type separator, so this pins that the export path still resolves
// the contract and its parameter roles.
func TestRustContractsResolveOnExportPath(t *testing.T) {
	t.Parallel()

	ctx := newExportBuildContext(&engine.DepScanResult{
		CallGraph: &callgraph.CallGraph{},
		Ecosystem: "rust",
	})
	if ctx.kb == nil {
		t.Fatal("rust knowledge base not loaded into the export context")
	}

	unboundKeyNew := callgraph.FunctionID{Package: "ring::aead", Type: "UnboundKey", Name: "new"}
	fqn := fullFunctionName(unboundKeyNew)
	if fqn != "ring::aead.UnboundKey.new" {
		t.Fatalf("fullFunctionName = %q, want ring::aead.UnboundKey.new", fqn)
	}

	call := &callgraph.FunctionCall{
		Callee:    unboundKeyNew,
		FilePath:  "src/seal.rs",
		Line:      5,
		Arguments: []string{"&aead::AES_256_GCM", "key"},
	}
	matches := contractMatchesForCall(ctx, call, len(call.Arguments))
	if len(matches) != 1 {
		t.Fatalf("contractMatchesForCall = %d contracts, want 1", len(matches))
	}
	if matches[0].Return.Type != "ring::aead::UnboundKey" {
		t.Fatalf("return type = %q, want ring::aead::UnboundKey", matches[0].Return.Type)
	}

	roles := parameterRolesFromKB(ctx.kb, fqn, len(call.Arguments))
	if len(roles) != 2 {
		t.Fatalf("parameter roles = %d, want 2", len(roles))
	}
	if roles[0].Role != "operation-determining" || roles[0].Contributes == nil || roles[0].Contributes.Property != "algorithm" {
		t.Errorf("role 0 = %#v, want operation-determining contributing algorithm", roles[0])
	}
	if roles[1].Role != "metadata-contributing" || roles[1].Contributes == nil || roles[1].Contributes.Property != "keySize" {
		t.Errorf("role 1 = %#v, want metadata-contributing contributing keySize", roles[1])
	}
}
