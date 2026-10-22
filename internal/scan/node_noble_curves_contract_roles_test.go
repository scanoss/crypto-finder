// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// A bare 0.x/1.x import types sign's result as the signature object, so its
// encoder carries a role. The 2.x `.js` sign returns bytes, which have none.
const nodeNobleCurvesConsumer = `import { secp256k1 } from '@noble/curves/secp256k1';
import { p256 } from '@noble/curves/nist.js';

export async function signCompact(hash, key) {
  const sig = await secp256k1.sign(hash, key, { lowS: true });
  return sig.toCompactRawBytes();
}

export function signBytes(msg, key) {
  const sig = p256.sign(msg, key);
  return sig.slice(0, 64);
}
`

func TestNodeNobleCurvesSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		asset entities.CryptographicAsset
		want  map[string]string
	}{
		{
			name: "1.x sign returns the signature object",
			asset: cAsset(5, 5, 21, 61, "const sig = await secp256k1.sign(hash, key, { lowS: true });",
				"javascript.noble-curves.algorithm.signature.secp256k1-ecdsa-sign",
				map[string]string{"assetType": "algorithm", "api": "@noble/curves/secp256k1.secp256k1.sign"}),
			want: map[string]string{"@noble/curves.Signature.toCompactRawBytes": "output"},
		},
		{
			name: "2.x sign returns bytes",
			asset: cAsset(10, 10, 15, 34, "const sig = p256.sign(msg, key);",
				"javascript.noble-curves.algorithm.signature.p256-ecdsa-sign",
				map[string]string{"assetType": "algorithm", "api": "@noble/curves/nist.p256.sign"}),
			want: map[string]string{"curves.slice": ""},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertNodeSupportingRoles(t, "curves.mjs", nodeNobleCurvesConsumer, tc.asset, tc.want)
		})
	}
}
