// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package contracts_test

import (
	"testing"

	"github.com/scanoss/static-engine/callgraph/contracts"
)

// sm-crypto exports sm2 and sm4 as objects and sm3 as a function, so the keys are
// sm-crypto.sm2.<fn>, sm-crypto.sm4.<fn> and sm-crypto.sm3 itself.
func TestLoadEmbeddedNodeSmCrypto(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load("node")
	if err != nil {
		t.Fatalf("Load(node): %v", err)
	}
	assertLibraryOwnsItsKeys(t, kb, "sm-crypto", "sm-crypto.")

	tests := []struct {
		method, role, want, property string
		arity                        int
	}{
		{"sm-crypto.sm2.generateKeyPairHex", "factory", "sm-crypto.sm2.KeyPair", "", 0},
		{"sm-crypto.sm2.doEncrypt", "operation", "string", "keyMaterial", 3},
		{"sm-crypto.sm2.doDecrypt", "operation", "string", "keyMaterial", 4},
		{"sm-crypto.sm2.doSignature", "operation", "string", "keyMaterial", 2},
		{"sm-crypto.sm2.doVerifySignature", "operation", "boolean", "keyMaterial", 4},
		{"sm-crypto.sm3", "operation", "string", "", 1},
		{"sm-crypto.sm3", "operation", "string", "keyMaterial", 2},
		{"sm-crypto.sm4.encrypt", "operation", "string", "mode", 3},
		{"sm-crypto.sm4.decrypt", "operation", "string", "mode", 3},
	}
	for _, tt := range tests {
		got := kb.ContractsFor(tt.method, tt.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", tt.method, tt.arity, len(got))
		}
		c := got[0]
		if c.SourceLibrary != "sm-crypto" || c.Role != tt.role || c.Return.Type != tt.want || c.Return.Confidence != "high" {
			t.Errorf("%s/%d = %s %s %s/%s, want sm-crypto %s %s/high", tt.method, tt.arity, c.SourceLibrary, c.Role, c.Return.Type, c.Return.Confidence, tt.role, tt.want)
		}
		if tt.property != "" && !gmContributes(c, tt.property) {
			t.Errorf("%s/%d parameters = %#v, want a %q contribution", tt.method, tt.arity, c.Parameters, tt.property)
		}
	}

	// The SM4 mode is read from the options object literal, e.g. { mode: 'cbc' }.
	for _, p := range kb.ContractsFor("sm-crypto.sm4.encrypt", 3)[0].Parameters {
		if p.Index != nil && *p.Index == 2 && (p.Contributes == nil || p.Contributes.ArgumentProperty != "mode") {
			t.Errorf("sm4.encrypt options parameter = %#v, want argument_property mode", p)
		}
	}
}

func gmContributes(c contracts.Contract, property string) bool {
	for _, p := range c.Parameters {
		if p.Contributes != nil && p.Contributes.Property == property {
			return true
		}
	}
	return false
}
