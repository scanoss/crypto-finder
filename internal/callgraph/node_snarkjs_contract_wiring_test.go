// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// Calls under a module namespace have no receiver variable, so the contract's
// visible effect is the type a function returns through one: a prover helper
// that returns the proof reports it as its inferred return.
func TestNodeSnarkjsContractTypesFunctionsThatReturnItsResults(t *testing.T) {
	t.Parallel()

	graph := buildNodeGraph(t, `const snarkjs = require('snarkjs');
const { groth16, zKey } = require('snarkjs');

async function prove(input, wasm, zkey) {
  return snarkjs.groth16.fullProve(input, wasm, zkey);
}

async function check(vKey, publicSignals, proof) {
  return groth16.verify(vKey, publicSignals, proof);
}

async function verificationKey(zkey) {
  return zKey.exportVerificationKey(zkey);
}

async function solidity(vKey) {
  return snarkjs.zKey.exportSolidityVerifier(vKey);
}
`)
	want := map[string]string{
		"prove":           "snarkjs.ProofResult",
		"check":           "boolean",
		"verificationKey": "snarkjs.VerificationKey",
		"solidity":        "",
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
		switch {
		case typ == "" && got != nil:
			t.Errorf("%s: inferred return %q, want none (exportSolidityVerifier is not contracted)", name, got.Type)
		case typ != "" && (got == nil || got.Type != typ || got.Origin != "kb-direct"):
			t.Errorf("%s: inferred return = %+v, want %s from the knowledge base", name, got, typ)
		}
	}
}
