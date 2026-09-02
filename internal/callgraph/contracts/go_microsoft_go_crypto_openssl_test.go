// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesMicrosoftOpenSSLContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	const m = "github.com/microsoft/go-crypto-openssl/openssl"
	tests := []struct {
		method string
		arity  int
	}{
		{m + ".NewAESCipher", 1},
		{m + ".NewGCMTLS13", 1},
		{m + ".PBKDF2", 5},
		{m + ".ExpandHKDF", 4},
		{m + ".EncryptRSAOAEP", 5},
		{m + ".EncryptRSAOAEP", 4},
		{m + ".SignMarshalECDSA", 2},
		{m + ".GenerateKeyMLDSA", 1},
		{m + ".SignDSA", 2},
		{m + ".ECDH", 2},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].SourceLibrary != "microsoft-go-crypto-openssl" || got[0].Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want microsoft-go-crypto-openssl/high", got[0])
			}
		})
	}
}
