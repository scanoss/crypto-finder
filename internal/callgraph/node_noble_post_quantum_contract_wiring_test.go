// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// Every call goes through the parameter-set object and returns bytes or a plain
// object, so the contract's visible effect is the type a consumer function
// returns through it, under the 0.5+ `.js` and the 0.1-0.4 bare subpath.
func TestNodeNoblePostQuantumContractTypesFunctionsThatReturnItsResults(t *testing.T) {
	t.Parallel()

	graph := buildNodeGraph(t, `import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { falcon512 } from '@noble/post-quantum/falcon.js';

function newKemKeys(seed) {
  return ml_kem768.keygen(seed);
}

function encapsulateTo(publicKey) {
  return ml_kem768.encapsulate(publicKey);
}

function openShared(cipherText, secretKey) {
  return ml_kem768.decapsulate(cipherText, secretKey);
}

function signLegacy(secretKey, msg) {
  return ml_dsa65.sign(secretKey, msg);
}

function checkFalcon(sig, msg, publicKey) {
  return falcon512.verify(sig, msg, publicKey);
}
`)
	want := map[string]string{
		"newKemKeys":    "@noble/post-quantum.KeyPair",
		"encapsulateTo": "@noble/post-quantum.Encapsulation",
		"openShared":    "Uint8Array",
		"signLegacy":    "Uint8Array",
		"checkFalcon":   "boolean",
	}
	for name, typ := range want {
		var got *InferredReturn
		found := false
		for _, fn := range graph.Functions {
			if fn.ID.Name == name {
				got, found = fn.InferredReturn, true
			}
		}
		if !found {
			t.Fatalf("function %s not found", name)
		}
		if got == nil || got.Type != typ || got.Origin != "kb-direct" {
			t.Errorf("%s: inferred return = %+v, want %s from the knowledge base", name, got, typ)
		}
	}
}
