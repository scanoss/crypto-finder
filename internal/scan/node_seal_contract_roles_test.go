// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "testing"

// node-seal's own example, with the require at module scope: the runtime is
// the awaited result of the factory, and every constructor is a member of it.
const nodeSealConsumer = `const SEAL = require('node-seal');

async function run(parms, plainText) {
  const seal = await SEAL();
  const context = seal.Context(parms, true, seal.SecurityLevel.tc128);
  const keyGenerator = seal.KeyGenerator(context);
  const publicKey = keyGenerator.createPublicKey();
  const secretKey = keyGenerator.secretKey();
  const encryptor = seal.Encryptor(context, publicKey);
  return encryptor.encrypt(plainText);
}

module.exports = { run };
`

func TestNodeSealSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	asset := cAsset(6, 6, 24, 50, "const keyGenerator = seal.KeyGenerator(context);",
		"javascript.node-seal.algorithm.pke.key-generator",
		map[string]string{"assetType": "algorithm", "api": "node-seal.KeyGenerator"})
	want := map[string]string{
		"node-seal.SEAL":                         "factory",
		"node-seal.KeyGenerator.createPublicKey": "operation",
		"node-seal.KeyGenerator.secretKey":       "output",
	}
	assertNodeSupportingRoles(t, "seal.js", nodeSealConsumer, asset, want)
}
