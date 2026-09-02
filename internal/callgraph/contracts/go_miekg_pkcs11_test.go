// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesMiekgPkcs11Contracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	const m = "github.com/miekg/pkcs11"
	tests := []struct {
		method, role, returnType, property string
		arity                              int
	}{
		{m + ".New", "factory", "*" + m + ".Ctx", "", 1},
		{m + ".NewMechanism", "factory", "*" + m + ".Mechanism", "algorithm", 2},
		{m + ".(*Ctx).GenerateKeyPair", "operation", m + ".ObjectHandle", "algorithm", 4},
		{m + ".(*Ctx).DeriveKey", "operation", m + ".ObjectHandle", "algorithm", 4},
		{m + ".(*Ctx).UnwrapKey", "operation", m + ".ObjectHandle", "encryptedKeyMaterial", 5},
		{m + ".(*Ctx).EncryptInit", "config", "error", "algorithm", 3},
		{m + ".(*Ctx).Sign", "operation", "[]byte", "input", 2},
		{m + ".(*Ctx).Verify", "operation", "error", "signature", 3},
		{m + ".(*Ctx).DigestFinal", "output", "[]byte", "", 1},
		{m + ".(*Ctx).Login", "config", "error", "password", 3},
		{m + ".(*Ctx).GenerateRandom", "operation", "[]byte", "outputLength", 2},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "miekg-pkcs11" || contract.Role != tt.role ||
				contract.Return.Type != tt.returnType || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want miekg-pkcs11 %s -> %s/high", contract, tt.role, tt.returnType)
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
