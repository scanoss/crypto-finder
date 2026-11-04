// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package contracts_test

import (
	"fmt"
	"testing"

	"github.com/scanoss/static-engine/callgraph/contracts"
)

// The RustCrypto SM2, SM3, SM4, ARIA and Camellia crates. sm2 exports the same
// SigningKey/VerifyingKey/SecretKey names as the NIST curve crates, so each key
// must resolve to the sm2 library and not to a sibling.
func TestLoadEmbeddedRustIncludesEastAsianCipherContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load("rust")
	if err != nil {
		t.Fatalf("Load(rust): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		lib    string
		role   string
		ret    string
	}{
		{"sm4::Sm4.new", 1, "sm4", "factory", "sm4::Sm4"},
		{"sm4::Sm4.new_from_slice", 1, "sm4", "factory", "core::result::Result"},
		{"sm4::Sm4.new_varkey", 1, "sm4", "factory", "core::result::Result"},
		{"sm4::Sm4.encrypt_block", 1, "sm4", "operation", "()"},
		{"sm4::Sm4.decrypt_blocks", 1, "sm4", "operation", "()"},
		{"aria::Aria128.new", 1, "aria", "factory", "aria::Aria128"},
		{"aria::Aria192.new_from_slice", 1, "aria", "factory", "core::result::Result"},
		{"aria::Aria256.decrypt_block", 1, "aria", "operation", "()"},
		{"camellia::Camellia128.new", 1, "camellia", "factory", "camellia::Camellia128"},
		{"camellia::Camellia256.encrypt_blocks", 1, "camellia", "operation", "()"},

		{"sm3::Sm3.new", 0, "sm3", "factory", "sm3::Sm3"},
		{"sm3::Sm3.digest", 1, "sm3", "output", "digest::Output"},
		{"sm3::Sm3.update", 1, "sm3", "operation", "void"},
		// digest 0.8 spelling, used by sm3 0.1.0.
		{"sm3::Sm3.result", 0, "sm3", "output", "digest::Output"},

		{"sm2::SecretKey.random", 1, "sm2", "factory", "sm2::SecretKey"},
		{"sm2::SecretKey.generate", 0, "sm2", "factory", "sm2::SecretKey"},
		{"sm2::dsa::SigningKey.new", 2, "sm2", "factory", "core::result::Result"},
		{"sm2::dsa::SigningKey.verifying_key", 0, "sm2", "output", "&sm2::dsa::VerifyingKey"},
		{"sm2::dsa::SigningKey.sign", 1, "sm2", "operation", "sm2::dsa::Signature"},
		{"sm2::dsa::SigningKey.sign_prehash", 1, "sm2", "operation", "core::result::Result"},
		{"sm2::dsa::VerifyingKey.from_sec1_bytes", 2, "sm2", "factory", "core::result::Result"},
		{"sm2::dsa::VerifyingKey.verify", 2, "sm2", "operation", "core::result::Result"},
		{"sm2::pke::EncryptingKey.new_with_mode", 2, "sm2", "factory", "sm2::pke::EncryptingKey"},
		{"sm2::pke::EncryptingKey.encrypt", 2, "sm2", "operation", "core::result::Result"},
		{"sm2::pke::EncryptingKey.encrypt_digest", 2, "sm2", "operation", "core::result::Result"},
		{"sm2::pke::DecryptingKey.from_slice", 1, "sm2", "factory", "core::result::Result"},
		{"sm2::pke::DecryptingKey.decrypt_der", 1, "sm2", "operation", "core::result::Result"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s#%d", tt.method, tt.arity), func(t *testing.T) {
			t.Parallel()
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("%s#%d contracts = %d, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].SourceLibrary != tt.lib || got[0].Role != tt.role || got[0].Return.Type != tt.ret {
				t.Fatalf("%s#%d = lib %q role %q return %q, want %q %q %q",
					tt.method, tt.arity, got[0].SourceLibrary, got[0].Role, got[0].Return.Type, tt.lib, tt.role, tt.ret)
			}
		})
	}
}

// Call sites dot the receiver-type separator and usually carry no arity.
func TestEastAsianCipherContractsResolveFromCallSiteKeys(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load("rust")
	if err != nil {
		t.Fatalf("Load(rust): %v", err)
	}

	for _, emitted := range []string{
		"sm4.Sm4.new",
		"aria.Aria128.encrypt_block",
		"camellia.Camellia192.new_from_slice",
		"sm3.Sm3.new_with_prefix",
		"sm2.SecretKey.random",
		"sm2::dsa.SigningKey.new",
		"sm2::dsa.VerifyingKey.verify",
		"sm2::pke.EncryptingKey.encrypt",
		"sm2::pke.DecryptingKey.decrypt",
	} {
		t.Run(emitted, func(t *testing.T) {
			t.Parallel()
			got := kb.ContractsFor(emitted, -1)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, -1) = %d contracts, want 1", emitted, len(got))
			}
		})
	}
}

// Every block-cipher constructor reads its key size from the key material, never
// from a byte count, so a 16-byte key reports 128 bits.
func TestEastAsianBlockCipherConstructorsMeasureTheKey(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load("rust")
	if err != nil {
		t.Fatalf("Load(rust): %v", err)
	}

	types := []string{
		"sm4::Sm4",
		"aria::Aria128", "aria::Aria192", "aria::Aria256",
		"camellia::Camellia128", "camellia::Camellia192", "camellia::Camellia256",
	}
	for _, typ := range types {
		for _, ctor := range []string{"new", "new_from_slice"} {
			method := typ + "." + ctor
			got := kb.ContractsFor(method, 1)
			if len(got) != 1 || len(got[0].Parameters) != 1 {
				t.Fatalf("%s: want one contract with one parameter role, got %#v", method, got)
			}
			p := got[0].Parameters[0]
			if p.Contributes == nil || p.Contributes.Property != "keySize" || p.Contributes.Derivation != "argument_bit_length" {
				t.Fatalf("%s parameter role = %#v, want keySize from argument_bit_length", method, p)
			}
		}
	}
}
