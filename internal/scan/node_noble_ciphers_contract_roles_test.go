// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// The constructor names the algorithm and the returned cipher does the work.
// The 2.x `.js` subpath and the bare subpath key differently, and both must
// type the cipher so its encrypt and decrypt carry a role.
const nodeNobleCiphersConsumer = `import { gcm } from '@noble/ciphers/aes.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';

export function seal(key, nonce, data) {
  const cipher = gcm(key, nonce);
  return cipher.encrypt(data);
}

export function open(key, nonce, data) {
  const c = xchacha20poly1305(key, nonce);
  return c.decrypt(data);
}
`

func TestNodeNobleCiphersSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		asset entities.CryptographicAsset
		want  map[string]string
	}{
		{
			name: "gcm from the .js subpath",
			asset: cAsset(5, 5, 18, 33, "const cipher = gcm(key, nonce);",
				"javascript.noble-ciphers.algorithm.ae.aes-gcm",
				map[string]string{"assetType": "algorithm", "api": "@noble/ciphers/aes.gcm"}),
			want: map[string]string{"@noble/ciphers.Cipher.encrypt": "operation"},
		},
		{
			name: "xchacha20poly1305 from the bare subpath",
			asset: cAsset(10, 10, 13, 42, "const c = xchacha20poly1305(key, nonce);",
				"javascript.noble-ciphers.algorithm.ae.xchacha20-poly1305",
				map[string]string{"assetType": "algorithm", "api": "@noble/ciphers/chacha.xchacha20poly1305"}),
			want: map[string]string{"@noble/ciphers.Cipher.decrypt": "operation"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertNodeSupportingRoles(t, "cipher.mjs", nodeNobleCiphersConsumer, tc.asset, tc.want)
		})
	}
}
