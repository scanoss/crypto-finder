// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeNobleCurves(t *testing.T) {
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
		// ECDSA sign returns the signature object in 0.x/1.x (bare only) and
		// bytes in 2.x (`.js` only).
		{"@noble/curves/secp256k1.secp256k1.sign", 3, "@noble/curves.Signature", "operation"},
		{"@noble/curves/secp256k1.js.secp256k1.sign", 3, "Uint8Array", "operation"},
		{"@noble/curves/p256.p256.sign", 2, "@noble/curves.Signature", "operation"},
		{"@noble/curves/nist.js.p384.sign", 2, "Uint8Array", "operation"},
		{"@noble/curves/misc.js.brainpoolP256r1.verify", 3, "boolean", "operation"},
		{"@noble/curves/secp256k1.secp256k1.Signature.fromCompact", 1, "@noble/curves.Signature", "factory"},
		{"@noble/curves/secp256k1.js.secp256k1.Point.fromHex", 1, "@noble/curves.Point", "factory"},
		{"@noble/curves/secp256k1.schnorr.sign", 3, "Uint8Array", "operation"},
		{"@noble/curves/ed25519.js.ed25519.sign", 2, "Uint8Array", "operation"},
		{"@noble/curves/ed448.x448.getSharedSecret", 2, "Uint8Array", "operation"},
		{"@noble/curves/bls12-381.bls12_381.aggregateSignatures", 1, "Uint8Array", "operation"},
		{"@noble/curves/bls12-381.js.bls12_381.longSignatures.sign", 2, "@noble/curves.Point", "operation"},
		{"@noble/curves/bn254.js.bn254.pairing", 2, "@noble/curves.Fp12", "operation"},
		{"@noble/curves/webcrypto.js.p256.sign", 2, "Uint8Array", "operation"},
		// The signature object and the points.
		{"@noble/curves.Signature.addRecoveryBit", 1, "@noble/curves.Signature", "config"},
		{"@noble/curves.Signature.recoverPublicKey", 1, "@noble/curves.Point", "operation"},
		{"@noble/curves.Signature.toCompactRawBytes", 0, "Uint8Array", "output"},
		{"@noble/curves.Point.toHex", 1, "string", "output"},
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

	// 2.x-only modules have no bare spelling, and internals stay undeclared.
	for key := range kb.Contracts {
		bareWebcrypto := strings.HasPrefix(key, "@noble/curves/webcrypto.") && !strings.HasPrefix(key, "@noble/curves/webcrypto.js.")
		if strings.HasPrefix(key, "@noble/curves/abstract") || strings.HasPrefix(key, "@noble/curves/utils") ||
			bareWebcrypto || strings.HasPrefix(key, "@noble/curves/misc.brainpool") {
			t.Errorf("contract %q names an internal export or a spelling the package never shipped", key)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "noble-curves", "@noble/curves")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "@noble/curves") {
			n++
		}
	}
	if n != 1387 {
		t.Errorf("noble-curves contributes %d keys, want 1387", n)
	}
}
