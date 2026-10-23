// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Both the v3 and the v4/v5 API generations resolve; optional trailing
// arguments are declared at every arity.
func TestLoadEmbeddedNodeSecp256k1(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	type want struct {
		method string
		arity  int
		typ    string
		role   string
	}
	for _, w := range []want{
		{"secp256k1.ecdsaSign", 2, "secp256k1.RecoverableSignature", "operation"},
		{"secp256k1.ecdsaSign", 4, "secp256k1.RecoverableSignature", "operation"},
		{"secp256k1.sign", 3, "secp256k1.RecoverableSignature", "operation"},
		{"secp256k1.ecdsaVerify", 3, "boolean", "operation"},
		{"secp256k1.ecdhUnsafe", 3, "builtins.bytes", "operation"},
		{"secp256k1.signatureImportLax", 1, "builtins.bytes", "output"},
		{"secp256k1.publicKeyConvert", 3, "builtins.bytes", "output"},
	} {
		got := kb.ContractsFor(w.method, w.arity)
		if len(got) == 0 {
			t.Errorf("%s#%d resolved nothing", w.method, w.arity)
			continue
		}
		if got[0].Return.Type != w.typ || got[0].Role != w.role {
			t.Errorf("%s#%d = (%q, %q), want (%q, %q)", w.method, w.arity, got[0].Return.Type, got[0].Role, w.typ, w.role)
		}
	}

	for _, unwanted := range []string{
		"secp256k1.ecdsaVerify#4",
		"secp256k1.verify#4",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "secp256k1", "secp256k1.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "secp256k1.") {
			n++
		}
	}
	if n != 34 {
		t.Errorf("secp256k1 contributes %d keys, want 34", n)
	}
}
