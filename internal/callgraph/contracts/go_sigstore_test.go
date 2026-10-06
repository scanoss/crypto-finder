// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesSigstoreContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		method, role, property string
		arity                  int
	}{
		{"github.com/sigstore/sigstore/pkg/signature.LoadECDSASigner", "factory", "algorithm", 2},
		{"github.com/sigstore/sigstore/pkg/signature.NewRSAPSSSignerVerifier", "factory", "keySize", 3},
		{"github.com/sigstore/sigstore/pkg/signature.LoadSigner", "factory", "keyMaterial", 2},
		{"github.com/sigstore/sigstore/pkg/signature.(Signer).SignMessage", "operation", "", 2},
		{"github.com/sigstore/sigstore/pkg/cryptoutils.UnmarshalPEMToPublicKey", "factory", "keyMaterial", 1},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "sigstore" || contract.Role != tt.role || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want sigstore %s/high", contract, tt.role)
			}
			if tt.property == "" {
				return
			}
			for _, parameter := range contract.Parameters {
				if parameter.Contributes != nil && parameter.Contributes.Property == tt.property {
					return
				}
			}
			t.Fatalf("contract parameters = %#v, want contribution for %q", contract.Parameters, tt.property)
		})
	}
}
