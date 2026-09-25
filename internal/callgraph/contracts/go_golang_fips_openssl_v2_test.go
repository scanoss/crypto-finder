// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedGoIncludesGolangFIPSOpenSSLV2Contracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	tests := []struct {
		method, role, property string
		arity                  int
	}{
		{"github.com/golang-fips/openssl/v2.NewAESCipher", "factory", "keySize", 1},
		{"github.com/golang-fips/openssl/v2.NewGCMTLS13", "config", "", 1},
		{"github.com/golang-fips/openssl/v2.PBKDF2", "operation", "password", 5},
		{"github.com/golang-fips/openssl/v2.(*PrivateKeyEd25519).Public", "output", "", 0},
		{"github.com/golang-fips/openssl/v2.GenerateKeyMLDSA", "factory", "parameterSet", 1},
		{"github.com/golang-fips/openssl/v2.(*PrivateKeyMLDSA).Sign", "operation", "plaintext", 2},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", tt.method, tt.arity, len(got))
			}
			contract := got[0]
			if contract.SourceLibrary != "golang-fips-openssl-v2" || contract.Role != tt.role || contract.Return.Confidence != "high" {
				t.Fatalf("contract = %#v, want golang-fips-openssl-v2 %s/high", contract, tt.role)
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

// The crypto_rules golang-fips-openssl rules report these released-tag
// functions as their api. Each needs a contract under its v2.0.3 spelling,
// including the NewPrivateKeyEd25119 / NewPublicKeyEd25119 typo every tag ships.
func TestLoadEmbeddedGoCoversGolangFIPSOpenSSLV2RuleAPIs(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("go")
	if err != nil {
		t.Fatalf("LoadEmbedded(go): %v", err)
	}

	const pkg = "github.com/golang-fips/openssl/v2."
	tests := []struct {
		function, role, returnType string
		arity                      int
	}{
		{"NewSHA1", "factory", "hash.Hash", 0},
		{"SHA1", "operation", "[20]byte", 1},
		{"NewMD5", "factory", "hash.Hash", 0},
		{"MD5", "operation", "[16]byte", 1},
		{"NewMD4", "factory", "hash.Hash", 0},
		{"MD4", "operation", "[16]byte", 1},
		{"GenerateKeyRSA", "factory", pkg + "BigInt", 1},
		{"GenerateKeyECDSA", "factory", pkg + "BigInt", 1},
		{"GenerateKeyECDH", "factory", "*" + pkg + "PrivateKeyECDH", 1},
		{"GenerateKeyEd25519", "factory", "*" + pkg + "PrivateKeyEd25519", 0},
		{"NewPublicKeyECDSA", "factory", "*" + pkg + "PublicKeyECDSA", 3},
		{"NewPublicKeyECDH", "factory", "*" + pkg + "PublicKeyECDH", 2},
		{"NewPrivateKeyEd25119", "factory", "*" + pkg + "PrivateKeyEd25519", 1},
		{"NewPublicKeyEd25119", "factory", "*" + pkg + "PublicKeyEd25519", 1},
		{"NewPrivateKeyEd25519FromSeed", "factory", "*" + pkg + "PrivateKeyEd25519", 1},
		{"EncryptRSAPKCS1", "operation", "[]byte", 2},
		{"DecryptRSAPKCS1", "operation", "[]byte", 2},
		{"EncryptRSANoPadding", "operation", "[]byte", 2},
		{"DecryptRSANoPadding", "operation", "[]byte", 2},
		{"SignRSAPKCS1v15", "operation", "[]byte", 3},
		{"HashSignRSAPKCS1v15", "operation", "[]byte", 3},
		{"VerifyRSAPKCS1v15", "operation", "error", 4},
		{"HashVerifyRSAPKCS1v15", "operation", "error", 4},
		{"HashSignECDSA", "operation", "[]byte", 3},
		{"VerifyECDSA", "operation", "bool", 3},
		{"HashVerifyECDSA", "operation", "bool", 4},
		{"VerifyEd25519", "operation", "error", 3},
	}
	for _, tt := range tests {
		t.Run(tt.function, func(t *testing.T) {
			got := kb.ContractsFor(pkg+tt.function, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d, want 1", pkg+tt.function, tt.arity, len(got))
			}
			if c := got[0]; c.SourceLibrary != "golang-fips-openssl-v2" || c.Role != tt.role || c.Return.Type != tt.returnType {
				t.Fatalf("contract = %s %s -> %s, want golang-fips-openssl-v2 %s -> %s", c.SourceLibrary, c.Role, c.Return.Type, tt.role, tt.returnType)
			}
		})
	}
}
