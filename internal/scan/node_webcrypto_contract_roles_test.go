// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// WebCrypto reached three ways in one consumer: the global crypto object,
// Node's webcrypto export, and a subtle object held in a variable.
const nodeWebCryptoConsumer = `import { webcrypto } from 'node:crypto';

export async function seal(data) {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return crypto.subtle.exportKey('raw', key);
}

export async function mac(raw, data, tag) {
  const subtle = webcrypto.subtle;
  const key = await subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  await subtle.sign('HMAC', key, data);
  return subtle.verify('HMAC', key, tag, data);
}
`

func TestNodeWebCryptoSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		asset entities.CryptographicAsset
		want  map[string]string
	}{
		{
			name: "generateKey on the global crypto object",
			asset: cAsset(4, 4, 21, 99, "crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt'])",
				"javascript.webcrypto.algorithm.block-cipher.aes.generate-key",
				map[string]string{"assetType": "algorithm", "api": "SubtleCrypto.generateKey"}),
			want: map[string]string{
				"SubtleCrypto.encrypt":   "operation",
				"SubtleCrypto.exportKey": "output",
			},
		},
		{
			name: "importKey through a subtle variable from node:crypto",
			asset: cAsset(12, 12, 21, 111, "subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])",
				"javascript.webcrypto.algorithm.mac.hmac.import-key",
				map[string]string{"assetType": "algorithm", "api": "SubtleCrypto.importKey"}),
			want: map[string]string{
				"SubtleCrypto.sign":   "operation",
				"SubtleCrypto.verify": "operation",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertNodeSupportingRoles(t, "seal.mjs", nodeWebCryptoConsumer, tc.asset, tc.want)
		})
	}
}
