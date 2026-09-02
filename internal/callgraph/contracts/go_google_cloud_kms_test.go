// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesGoogleCloudKMSContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		method, role string
		arity        int
	}{
		{"cloud.google.com/go/kms/apiv1.NewKeyManagementClient", "factory", 2},
		{"cloud.google.com/go/kms/apiv1.(*KeyManagementClient).Encrypt", "operation", 3},
		{"cloud.google.com/go/kms/apiv1.(*KeyManagementClient).AsymmetricSign", "operation", 3},
		{"cloud.google.com/go/kms/apiv1.(*KeyManagementClient).GetPublicKey", "output", 3},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "google-cloud-kms" || contract.Role != tt.role || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want google-cloud-kms %s/high", contract, tt.role)
			}
		})
	}
}
