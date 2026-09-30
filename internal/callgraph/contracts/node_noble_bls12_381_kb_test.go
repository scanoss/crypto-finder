// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeNobleBLS12381(t *testing.T) {
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
		{"@noble/bls12-381.sign", 2, "Uint8Array", "operation"},
		{"@noble/bls12-381.verify", 3, "boolean", "operation"},
		{"@noble/bls12-381.verifyBatch", 3, "boolean", "operation"},
		{"@noble/bls12-381.getPublicKey", 1, "Uint8Array", "operation"},
		{"@noble/bls12-381.aggregateSignatures", 1, "Uint8Array", "operation"},
		{"@noble/bls12-381.pairing", 2, "@noble/bls12-381.Fp12", "operation"},
		{"@noble/bls12-381.pairing", 3, "@noble/bls12-381.Fp12", "operation"},
		{"@noble/bls12-381.utils.randomPrivateKey", 0, "Uint8Array", "operation"},
		// The statics that type a point, so its methods resolve.
		{"@noble/bls12-381.PointG2.hashToCurve", 1, "@noble/bls12-381.PointG2", "operation"},
		{"@noble/bls12-381.PointG1.hashToCurve", 2, "@noble/bls12-381.PointG1", "operation"},
		{"@noble/bls12-381.PointG1.fromHex", 1, "@noble/bls12-381.PointG1", "factory"},
		{"@noble/bls12-381.PointG2.fromSignature", 1, "@noble/bls12-381.PointG2", "factory"},
		{"@noble/bls12-381.PointG2.toSignature", 0, "Uint8Array", "output"},
		{"@noble/bls12-381.PointG1.toRawBytes", 1, "Uint8Array", "output"},
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

	// Arity is exact: sign takes the message and the key, nothing else.
	if got := kb.ContractsFor("@noble/bls12-381.sign", 1); len(got) != 0 {
		t.Error("sign#1 resolved; the library's sign takes two arguments")
	}

	// verify returns a boolean. Typing it as a signature would let a consumer's
	// `ok` variable flow on as key material.
	if got := kb.ContractsFor("@noble/bls12-381.verify", 3); len(got) != 0 && got[0].Return.Type == "Uint8Array" {
		t.Error("verify must return boolean")
	}

	// Field arithmetic, encoding helpers and the domain-tag setter compute
	// nothing and must not be declared.
	for _, unwanted := range []string{
		"@noble/bls12-381.utils.bytesToHex#1",
		"@noble/bls12-381.utils.setDSTLabel#1",
		"@noble/bls12-381.Fp.<init>#1",
		"@noble/bls12-381.utils.mod#2",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q computes nothing and must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "noble-bls12-381", "@noble/bls12-381.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "@noble/bls12-381.") {
			n++
		}
	}
	if n != 29 {
		t.Errorf("noble-bls12-381 contributes %d keys, want 29", n)
	}
}
