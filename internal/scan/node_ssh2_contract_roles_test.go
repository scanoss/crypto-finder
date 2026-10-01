// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "testing"

// A client built from the named export and connected, then a private key
// parsed with its passphrase, used to sign and read back as a public key. The
// constructor types the client; parseKey types the key whose methods follow.
const nodeSSH2Consumer = `const { Client, utils } = require('ssh2');

function login(config, pem, challenge) {
  const conn = new Client();
  conn.connect(config);
  const key = utils.parseKey(pem, config.passphrase);
  const signature = key.sign(challenge);
  const publicKey = key.getPublicSSH();
  return { signature, publicKey };
}

module.exports = { login };
`

func TestNodeSSH2SupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	connect := cAsset(5, 5, 3, 24, "conn.connect(config);",
		"javascript.ssh2.protocol.ssh.client-connect",
		map[string]string{"assetType": "protocol", "api": "ssh2.Client.connect"})
	assertNodeSupportingRoles(t, "login.js", nodeSSH2Consumer, connect,
		map[string]string{"ssh2.Client.<init>": "factory"})

	parse := cAsset(6, 6, 15, 56, "const key = utils.parseKey(pem, config.passphrase);",
		"javascript.ssh2.related-crypto-material.key.parse-key",
		map[string]string{"assetType": "related-crypto-material", "api": "ssh2.utils.parseKey"})
	assertNodeSupportingRoles(t, "login.js", nodeSSH2Consumer, parse,
		map[string]string{
			"ssh2.ParsedKey.sign":         "operation",
			"ssh2.ParsedKey.getPublicSSH": "output",
		})
}
