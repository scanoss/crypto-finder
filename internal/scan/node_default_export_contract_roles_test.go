// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "testing"

// A call of the module binding itself is keyed by the module's default export,
// whatever the consumer names it, so the factory types the chain.
const nodeKeccakConsumer = `const createKeccakHash = require('keccak');

function digest(data) {
  return createKeccakHash('keccak256').update(data).digest('hex');
}

module.exports = { digest };
`

func TestNodeModuleCallFactoryCarriesItsContractRole(t *testing.T) {
	t.Parallel()

	asset := cAsset(4, 4, 10, 67, "return createKeccakHash('keccak256').update(data).digest('hex');",
		"fixture.javascript.keccak.keccak256",
		map[string]string{"assetType": "algorithm", "api": "keccak.Hash.digest"})
	want := map[string]string{
		"keccak.default":     "factory",
		"keccak.Hash.update": "operation",
	}
	assertNodeSupportingRoles(t, "hash.js", nodeKeccakConsumer, asset, want)
}
