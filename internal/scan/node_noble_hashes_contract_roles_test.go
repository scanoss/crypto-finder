// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// The hash's create() builds the hasher and the hasher does the work. The
// awaited eskdf object derives the keys.
const nodeNobleHashesConsumer = `import * as sha3 from '@noble/hashes/sha3';
import { eskdf } from '@noble/hashes/eskdf.js';

export function digest(a, b) {
  const h = sha3.keccak_256.create();
  h.update(a);
  h.update(b);
  return h.digest();
}

export async function child(user, password) {
  const kdf = await eskdf(user, password);
  return kdf.deriveChildKey('aes', 0);
}
`

func TestNodeNobleHashesSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		asset entities.CryptographicAsset
		want  map[string]string
	}{
		{
			name: "keccak_256.create on a namespace import",
			asset: cAsset(5, 5, 13, 37, "const h = sha3.keccak_256.create();",
				"javascript.noble-hashes.algorithm.hash.keccak-256-create",
				map[string]string{"assetType": "algorithm", "api": "@noble/hashes/sha3.keccak_256.create"}),
			want: map[string]string{
				"@noble/hashes.Hash.update": "operation",
				"@noble/hashes.Hash.digest": "output",
			},
		},
		{
			name: "awaited eskdf from the .js subpath",
			asset: cAsset(12, 12, 21, 41, "const kdf = await eskdf(user, password);",
				"javascript.noble-hashes.algorithm.kdf.eskdf",
				map[string]string{"assetType": "algorithm", "api": "@noble/hashes/eskdf.eskdf"}),
			want: map[string]string{"@noble/hashes.ESKDF.deriveChildKey": "operation"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertNodeSupportingRoles(t, "hashes.mjs", nodeNobleHashesConsumer, tc.asset, tc.want)
		})
	}
}
