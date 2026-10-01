// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "testing"

// The two objects the default sjcl build hands a consumer: an AES key schedule
// used through a mode and directly, and an HMAC used as a prf and read back.
const nodeSJCLConsumer = `var sjcl = require('sjcl');

function seal(key, plain, iv) {
  var aes = new sjcl.cipher.aes(key);
  var block = aes.encrypt(plain);
  return sjcl.mode.gcm.encrypt(aes, plain, iv, [], 128).concat(block);
}

function tag(key, data) {
  var mac = new sjcl.misc.hmac(key, sjcl.hash.sha256);
  mac.update(data);
  return mac.digest();
}

module.exports = { seal, tag };
`

func TestNodeSJCLSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	aes := cAsset(4, 4, 13, 38, "var aes = new sjcl.cipher.aes(key);",
		"javascript.sjcl.algorithm.block-cipher.aes",
		map[string]string{"assetType": "algorithm", "api": "sjcl.cipher.aes"})
	assertNodeSupportingRoles(t, "seal.js", nodeSJCLConsumer, aes,
		map[string]string{"sjcl.cipher.aes.encrypt": "operation"})

	hmac := cAsset(10, 10, 13, 59, "var mac = new sjcl.misc.hmac(key, sjcl.hash.sha256);",
		"javascript.sjcl.algorithm.mac.hmac",
		map[string]string{"assetType": "algorithm", "api": "sjcl.misc.hmac"})
	assertNodeSupportingRoles(t, "seal.js", nodeSJCLConsumer, hmac,
		map[string]string{
			"sjcl.misc.hmac.update": "operation",
			"sjcl.misc.hmac.digest": "operation",
		})
}
