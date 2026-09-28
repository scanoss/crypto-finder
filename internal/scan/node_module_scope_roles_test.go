// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import "testing"

// Much Node code keeps its library object at module scope, declares its
// functions by assignment, and does its work in callbacks. eccrypto's derive
// has all three.
const nodeCommonJSDerive = `var EC = require('elliptic').ec;
var ec = new EC('secp256k1');

exports.derive = function (privateKeyA, publicKeyB) {
  return new Promise(function (resolve) {
    var keyA = ec.keyFromPrivate(privateKeyA);
    var keyB = ec.keyFromPublic(publicKeyB);
    resolve(keyA.derive(keyB.getPublic()));
  });
};
`

// A method declared on a prototype, as hash.js and elliptic declare their own.
const nodePrototypeMethod = `const hash = require('hash.js');

function Signer() {}

Signer.prototype.digest = function (msg) {
  const h = hash.sha256();
  h.update(msg);
  return h.digest('hex');
};

module.exports = Signer;
`

// A script does its work at module scope, outside any function.
const nodeModuleScript = `const EC = require('elliptic').ec;

const ec = new EC('secp256k1');
const key = ec.genKeyPair();
console.log(key.getPublic('hex'));
`

// Functions stored rather than run in place: an object literal's methods and
// two route handlers. Each is a function of its own, so one method's key calls
// are never another's supporting calls.
const nodeObjectLiteralMethods = `const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

module.exports = {
  sign: function (msgHash) {
    const key = ec.genKeyPair();
    return key.sign(msgHash);
  },
  verify: function (msgHash, sig, pub) {
    const key = ec.keyFromPublic(pub, 'hex');
    return key.verify(msgHash, sig);
  }
};
`

const nodeRouteHandlers = `const EC = require('elliptic').ec;
const router = require('express').Router();

router.post('/sign', function (req, res) {
  const ec = new EC('secp256k1');
  const key = ec.genKeyPair();
  res.json(key.sign(req.body.hash));
});

router.post('/verify', function (req, res) {
  const ec = new EC('secp256k1');
  const key = ec.keyFromPublic(req.body.pub, 'hex');
  res.json(key.verify(req.body.hash, req.body.sig));
});

module.exports = router;
`

func TestNodeSupportingCallsReachModuleScopeAndCallbacks(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, file, src string
		line, startCol  int
		endCol          int
		match, rule     string
		api             string
		want            map[string]string
	}{
		{
			name: "commonjs export whose callback uses a module-scope context",
			file: "derive.js", src: nodeCommonJSDerive,
			line: 8, startCol: 13, endCol: 42,
			match: "resolve(keyA.derive(keyB.getPublic()));",
			rule:  "javascript.elliptic.algorithm.key-agree.derive", api: "elliptic.KeyPair.derive",
			want: map[string]string{"elliptic.ec.keyFromPrivate": "factory"},
		},
		{
			name: "method assigned to a prototype",
			file: "signer.js", src: nodePrototypeMethod,
			line: 6, startCol: 13, endCol: 26,
			match: "const h = hash.sha256();",
			rule:  "javascript.hash-js.algorithm.hash.sha256", api: "hash.js.sha256",
			want: map[string]string{"hash.js.SHA256.update": "operation", "hash.js.SHA256.digest": "output"},
		},
		{
			name: "module-scope script",
			file: "script.js", src: nodeModuleScript,
			line: 3, startCol: 12, endCol: 31,
			match: "const ec = new EC('secp256k1');",
			rule:  "javascript.elliptic.algorithm.signature.curve-secp256k1", api: "elliptic.ec",
			want: map[string]string{"elliptic.ec.genKeyPair": "factory", "elliptic.KeyPair.getPublic": "output"},
		},
		{
			name: "object literal methods stay separate",
			file: "objlit.js", src: nodeObjectLiteralMethods,
			line: 7, startCol: 12, endCol: 29,
			match: "return key.sign(msgHash);",
			rule:  "javascript.elliptic.algorithm.signature.sign", api: "elliptic.KeyPair.sign",
			want: map[string]string{"elliptic.ec.genKeyPair": "factory"},
		},
		{
			name: "route handlers stay separate",
			file: "routes.js", src: nodeRouteHandlers,
			line: 7, startCol: 12, endCol: 35,
			match: "res.json(key.sign(req.body.hash));",
			rule:  "javascript.elliptic.algorithm.signature.sign", api: "elliptic.KeyPair.sign",
			want: map[string]string{"elliptic.ec.<init>": "factory", "elliptic.ec.genKeyPair": "factory"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			asset := cAsset(tc.line, tc.line, tc.startCol, tc.endCol, tc.match, tc.rule,
				map[string]string{"assetType": "algorithm", "api": tc.api})
			assertNodeSupportingRoles(t, tc.file, tc.src, asset, tc.want)
		})
	}
}
