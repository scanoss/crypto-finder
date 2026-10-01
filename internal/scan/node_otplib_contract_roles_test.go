// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "testing"

// The 13.x shape: a TOTP object built once, then generating and verifying. The
// finding is its construction, so the calls made on the object are its
// supporting calls.
const nodeOTPLibClassConsumer = `import { TOTP, generateSecret } from 'otplib';

export async function check(token) {
  const secret = generateSecret();
  const totp = new TOTP({ secret, digits: 8 });
  const expected = await totp.generate();
  const result = await totp.verify(token);
  return { expected, result };
}
`

// The 12.x engine used directly, with the consumer's own plugins.
const nodeOTPLibCoreConsumer = `const { Authenticator } = require('@otplib/core');

function enroll(options) {
  const auth = new Authenticator(options);
  const secret = auth.generateSecret();
  return auth.generate(secret);
}

module.exports = { enroll };
`

func TestNodeOTPLibSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	class := cAsset(5, 5, 16, 52, "const totp = new TOTP({ secret, digits: 8 });",
		"javascript.otplib.protocol.otp.totp-class",
		map[string]string{"assetType": "protocol", "api": "otplib.TOTP.<init>"})
	assertNodeSupportingRoles(t, "check.mjs", nodeOTPLibClassConsumer, class,
		map[string]string{
			"otplib.TOTP.generate": "operation",
			"otplib.TOTP.verify":   "operation",
		})

	engine := cAsset(4, 4, 15, 41, "const auth = new Authenticator(options);",
		"javascript.otplib-core.protocol.otp.authenticator-class",
		map[string]string{"assetType": "protocol", "api": "@otplib/core.Authenticator.<init>"})
	assertNodeSupportingRoles(t, "enroll.js", nodeOTPLibCoreConsumer, engine,
		map[string]string{
			"@otplib/core.Authenticator.generateSecret": "operation",
			"@otplib/core.Authenticator.generate":       "operation",
		})
}
