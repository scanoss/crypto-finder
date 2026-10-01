// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeNobleSecp256k1(t *testing.T) {
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
		// ECDSA and Schnorr share method names; the schnorr object keeps them apart.
		{"@noble/secp256k1.sign", 2, "Uint8Array", "operation"},
		{"@noble/secp256k1.signSync", 3, "Uint8Array", "operation"},
		{"@noble/secp256k1.signAsync", 2, "Uint8Array", "operation"},
		{"@noble/secp256k1.verify", 3, "boolean", "operation"},
		{"@noble/secp256k1.schnorr.sign", 2, "Uint8Array", "operation"},
		{"@noble/secp256k1.schnorr.verify", 3, "boolean", "operation"},
		{"@noble/secp256k1.getPublicKey", 2, "Uint8Array", "operation"},
		{"@noble/secp256k1.getSharedSecret", 2, "Uint8Array", "operation"},
		{"@noble/secp256k1.recoverPublicKey", 4, "Uint8Array", "operation"},
		{"@noble/secp256k1.utils.randomPrivateKey", 0, "Uint8Array", "operation"},
		// Parsed objects type their result so the encoders resolve.
		{"@noble/secp256k1.Signature.fromDER", 1, "@noble/secp256k1.Signature", "factory"},
		{"@noble/secp256k1.Signature.toCompactHex", 0, "string", "output"},
		{"@noble/secp256k1.Point.fromHex", 1, "@noble/secp256k1.Point", "factory"},
		{"@noble/secp256k1.Point.fromSignature", 3, "@noble/secp256k1.Point", "operation"},
		{"@noble/secp256k1.Point.toRawBytes", 1, "Uint8Array", "output"},
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

	// Schnorr verification takes exactly signature, message and public key.
	if got := kb.ContractsFor("@noble/secp256k1.schnorr.verify", 4); len(got) != 0 {
		t.Error("schnorr.verify#4 resolved; BIP-340 verify takes three arguments")
	}

	// Validation, byte helpers and the hash hooks compute nothing.
	for _, unwanted := range []string{
		"@noble/secp256k1.utils.isValidPrivateKey#1",
		"@noble/secp256k1.utils.sha256Sync#1",
		"@noble/secp256k1.utils.concatBytes#2",
		"@noble/secp256k1.utils.mod#2",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q computes nothing and must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "noble-secp256k1", "@noble/secp256k1.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "@noble/secp256k1.") {
			n++
		}
	}
	if n != 52 {
		t.Errorf("noble-secp256k1 contributes %d keys, want 52", n)
	}
}
