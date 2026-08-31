// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesSupranationalBlstContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	const m = "github.com/supranational/blst/bindings/go"
	tests := []struct {
		method string
		arity  int
		role   string
	}{
		{m + ".KeyGen", 2, "factory"},
		{m + ".(*P2Affine).Sign", 4, "operation"},
		{m + ".(*P1Affine).Verify", 6, "operation"},
		{m + ".(*P2Affine).FastAggregateVerify", 4, "operation"},
		{m + ".PairingCtx", 2, "factory"},
		{m + ".PairingCtx", 0, "factory"},
		{m + ".HashToG2", 3, "operation"},
		{m + ".(*P1Affine).Compress", 0, "output"},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].SourceLibrary != "supranational-blst" || got[0].Role != tt.role {
				t.Fatalf("contract = %#v, want supranational-blst/%s", got[0], tt.role)
			}
		})
	}
}
