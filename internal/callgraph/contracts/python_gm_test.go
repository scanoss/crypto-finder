// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// gmssl and gmssl-python both install a module named gmssl. gmssl's API lives in
// the submodules gmssl.sm2/sm3/sm4; gmssl-python's is top-level classes. Neither
// library may contribute a key in the other's namespace.
func TestLoadEmbeddedPythonGmsslPackagesDoNotShareKeys(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}
	for key, cs := range kb.Contracts {
		for _, c := range cs {
			submodule := strings.HasPrefix(key, "gmssl.sm2.") || strings.HasPrefix(key, "gmssl.sm3.") || strings.HasPrefix(key, "gmssl.sm4.")
			switch c.SourceLibrary {
			case "gmssl":
				if !submodule {
					t.Errorf("gmssl contributes %q outside gmssl.sm2/sm3/sm4", key)
				}
			case "gmssl-python":
				if submodule || !strings.HasPrefix(key, "gmssl.") {
					t.Errorf("gmssl-python contributes %q, which is not a top-level gmssl name", key)
				}
			}
		}
	}
	assertLibraryOwnsItsKeys(t, kb, "snowland-smx", "pysmx.")
}

func TestLoadEmbeddedPythonGmContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}

	tests := []struct {
		library, method, role, want, property string
		arity                                 int
	}{
		{"gmssl", "gmssl.sm2.CryptSM2.<init>", "factory", "gmssl.sm2.CryptSM2", "privateKey", 2},
		{"gmssl", "gmssl.sm2.CryptSM2.sign_with_sm3", "operation", "builtins.str", "", 1},
		{"gmssl", "gmssl.sm2.CryptSM2.verify", "operation", "builtins.bool", "", 2},
		{"gmssl", "gmssl.sm3.sm3_hash", "operation", "builtins.str", "", 1},
		{"gmssl", "gmssl.sm4.CryptSM4.<init>", "factory", "gmssl.sm4.CryptSM4", "padding", 2},
		{"gmssl", "gmssl.sm4.CryptSM4.set_key", "config", "builtins.NoneType", "operation", 2},
		{"gmssl", "gmssl.sm4.CryptSM4.crypt_cbc", "operation", "builtins.bytes", "", 2},
		{"gmssl-python", "gmssl.Sm4Cbc.<init>", "factory", "gmssl.Sm4Cbc", "operation", 3},
		{"gmssl-python", "gmssl.Sm4Gcm.<init>", "factory", "gmssl.Sm4Gcm", "keyMaterial", 3},
		{"gmssl-python", "gmssl.Sm4Gcm.finish", "output", "builtins.bytes", "", 0},
		{"gmssl-python", "gmssl.Sm3Hmac.<init>", "factory", "gmssl.Sm3Hmac", "keyMaterial", 1},
		{"gmssl-python", "gmssl.sm3_pbkdf2", "operation", "builtins.bytes", "iterations", 4},
		{"gmssl-python", "gmssl.Sm2Key.generate_key", "factory", "builtins.NoneType", "", 0},
		{"gmssl-python", "gmssl.Sm2Signature.<init>", "factory", "gmssl.Sm2Signature", "operation", 3},
		{"gmssl-python", "gmssl.Sm9EncMasterKey.extract_key", "factory", "gmssl.Sm9EncKey", "", 1},
		{"gmssl-python", "gmssl.Zuc.update", "operation", "builtins.bytes", "", 1},
		{"snowland-smx", "pysmx.SM2.Sign", "operation", "builtins.bytes", "keyMaterial", 4},
		{"snowland-smx", "pysmx.SM2._SM2.Sign", "operation", "builtins.bytes", "keyMaterial", 4},
		{"snowland-smx", "pysmx.SM3.SM3.<init>", "factory", "pysmx.SM3._SM3.SM3Type", "", 0},
		{"snowland-smx", "pysmx.SM4.Sm4.<init>", "factory", "pysmx.SM4._SM4.Sm4", "", 0},
		{"snowland-smx", "pysmx.SM4._SM4.Sm4.sm4_set_key", "config", "builtins.NoneType", "operation", 2},
		{"snowland-smx", "pysmx.SM4.sm4_crypt_cbc", "operation", "builtins.bytes", "operation", 4},
		{"snowland-smx", "pysmx.SM9.KEM_Encapsulate", "operation", "builtins.tuple", "", 3},
		{"snowland-smx", "pysmx.ZUC.zuc_encrypt", "operation", "builtins.bytes", "keyMaterial", 3},
	}
	for _, tt := range tests {
		got := kb.ContractsFor(tt.method, tt.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", tt.method, tt.arity, len(got))
		}
		c := got[0]
		if c.SourceLibrary != tt.library || c.Role != tt.role || c.Return.Type != tt.want || c.Return.Confidence != "high" {
			t.Errorf("%s/%d = %s %s %s/%s, want %s %s %s/high", tt.method, tt.arity, c.SourceLibrary, c.Role, c.Return.Type, c.Return.Confidence, tt.library, tt.role, tt.want)
		}
		if tt.property != "" && !gmContributes(c, tt.property) {
			t.Errorf("%s/%d parameters = %#v, want a %q contribution", tt.method, tt.arity, c.Parameters, tt.property)
		}
	}

	// Sm4's crypt_* methods are inherited from BlockCyphers.
	parents := kb.Hierarchy["pysmx.SM4._SM4.Sm4"]
	if len(parents) != 1 || parents[0] != "pysmx.block_cyphers._block_cyphers.BlockCyphers" {
		t.Errorf("pysmx Sm4 parents = %v, want BlockCyphers", parents)
	}
}
