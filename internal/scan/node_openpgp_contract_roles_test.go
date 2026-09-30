// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "testing"

// lpgp's shape: a private key unlocked with its passphrase, then read. Every
// call is awaited, and the accessors on the decrypted key are its outputs.
const nodeOpenPGPConsumer = `import * as openpgp from 'openpgp';

export async function unlock(armoredKey, passphrase) {
  const locked = await openpgp.readPrivateKey({ armoredKey });
  const privateKey = await openpgp.decryptKey({ privateKey: locked, passphrase });
  const fingerprint = privateKey.getFingerprint();
  const expires = await privateKey.getExpirationTime();
  return { privateKey, fingerprint, expires };
}
`

func TestNodeOpenPGPSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	asset := cAsset(5, 5, 28, 83, "const privateKey = await openpgp.decryptKey({ privateKey: locked, passphrase });",
		"javascript.openpgp.protocol.openpgp.decrypt-key",
		map[string]string{"assetType": "protocol", "api": "openpgp.decryptKey"})
	want := map[string]string{
		"openpgp.PrivateKey.getFingerprint":    "output",
		"openpgp.PrivateKey.getExpirationTime": "output",
	}
	assertNodeSupportingRoles(t, "unlock.mjs", nodeOpenPGPConsumer, asset, want)
}
