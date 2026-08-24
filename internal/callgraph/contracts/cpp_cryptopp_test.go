// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedCPPIncludesCryptoPPContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("cpp")
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	tests := []struct {
		method, role, returnType string
		arity                    int
	}{
		{"CryptoPP.SHA256", "factory", "CryptoPP::SHA256", 0},
		{"CryptoPP::SHA256.Update", "operation", "void", 2},
		{"CryptoPP::SHA256.Final", "operation", "void", 1},
		{"CryptoPP::SHA256.TruncatedFinal", "operation", "void", 2},
		{"CryptoPP::SHA256.CalculateDigest", "operation", "void", 3},
		{"CryptoPP::SHA256.CalculateTruncatedDigest", "operation", "void", 4},
		{"CryptoPP::SHA256.Verify", "operation", "bool", 1},
		{"CryptoPP::SHA256.VerifyDigest", "operation", "bool", 3},
		{"CryptoPP::SHA256.TruncatedVerify", "operation", "bool", 2},
		{"CryptoPP::SHA256.VerifyTruncatedDigest", "operation", "bool", 4},
		{"CryptoPP::SHA256.Restart", "config", "void", 0},
		{"CryptoPP::SHA256.DigestSize", "output", "unsigned int", 0},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "cryptopp" || contract.Role != tt.role || contract.Return.Type != tt.returnType || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want cryptopp %s returning %s with high confidence", contract, tt.role, tt.returnType)
			}
		})
	}
}

// The truncated digest length is the only argument carrying crypto metadata;
// SHA-256 itself is selected by the type, not by any argument.
func TestCryptoPPTruncatedDigestParameterDerivations(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("cpp")
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	for _, tt := range []struct {
		method string
		arity  int
	}{
		{"CryptoPP::SHA256.TruncatedFinal", 2},
		{"CryptoPP::SHA256.CalculateTruncatedDigest", 4},
	} {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			params := got[0].Parameters
			if len(params) != 1 {
				t.Fatalf("parameters = %#v, want the truncated-length parameter", params)
			}
			p := params[0]
			if p.Index == nil || *p.Index != 1 || p.Role != "metadata-contributing" ||
				p.Contributes == nil || p.Contributes.Property != "digestSize" ||
				p.Contributes.Derivation != "argument_value" {
				t.Fatalf("parameter = %#v, want index 1 contributing digestSize by argument_value", p)
			}
		})
	}
}
