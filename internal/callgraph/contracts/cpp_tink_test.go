// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedCPPIncludesTinkContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("cpp")
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	tests := []struct {
		method, role, returnType string
		arity                    int
	}{
		{"crypto::tink::AeadKeyTemplates.Aes256Gcm", "factory", "google::crypto::tink::KeyTemplate", 0},
		{"crypto::tink::AeadKeyTemplates.XChaCha20Poly1305", "factory", "google::crypto::tink::KeyTemplate", 0},
		{"crypto::tink::MacKeyTemplates.HmacSha256", "factory", "google::crypto::tink::KeyTemplate", 0},
		{"crypto::tink::SignatureKeyTemplates.Ed25519", "factory", "google::crypto::tink::KeyTemplate", 0},
		{"crypto::tink::KeysetHandle.GenerateNew", "factory", "crypto::tink::KeysetHandle", 1},
		{"crypto::tink::Aead.Encrypt", "operation", "std::string", 2},
		{"crypto::tink::Aead.Decrypt", "operation", "std::string", 2},
		{"crypto::tink::Mac.ComputeMac", "operation", "std::string", 1},
		{"crypto::tink::Mac.VerifyMac", "operation", "void", 2},
		{"crypto::tink::PublicKeySign.Sign", "operation", "std::string", 1},
		{"crypto::tink::PublicKeyVerify.Verify", "operation", "void", 2},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "tink" || contract.Role != tt.role || contract.Return.Type != tt.returnType || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want tink %s returning %s with high confidence", contract, tt.role, tt.returnType)
			}
		})
	}
}
