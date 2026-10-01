// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "testing"

// A sealed box: the facade is built with the awaited factory, a keypair is
// generated and split, and the message is encrypted to the public half.
const nodeSodiumPlusConsumer = `const { SodiumPlus } = require('sodium-plus');

async function seal(message) {
  const sodium = await SodiumPlus.auto();
  const keypair = await sodium.crypto_box_keypair();
  const publicKey = await sodium.crypto_box_publickey(keypair);
  const sealed = await sodium.crypto_box_seal(message, publicKey);
  return sealed;
}

module.exports = { seal };
`

func TestNodeSodiumPlusSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	asset := cAsset(7, 7, 20, 62, "await sodium.crypto_box_seal(message, publicKey);",
		"javascript.sodium-plus.algorithm.aead.box-seal",
		map[string]string{"assetType": "algorithm", "api": "sodium-plus.SodiumPlus.crypto_box_seal"})
	want := map[string]string{
		"sodium-plus.SodiumPlus.auto":                 "factory",
		"sodium-plus.SodiumPlus.crypto_box_keypair":   "operation",
		"sodium-plus.SodiumPlus.crypto_box_publickey": "output",
	}
	assertNodeSupportingRoles(t, "seal.js", nodeSodiumPlusConsumer, asset, want)
}
