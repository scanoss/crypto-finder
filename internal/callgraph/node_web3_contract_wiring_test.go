// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// The utilities are reached by name through the module, so the contract types a
// function that returns one of them. A utility reached through an instance, and
// the accounts chain, stay untyped receivers.
func TestNodeWeb3ContractTypesFunctionsThatReturnTheUtilities(t *testing.T) {
	t.Parallel()

	graph := buildNodeGraph(t, `const Web3 = require('web3');
const { utils } = require('web3');

function digest(data) {
  return Web3.utils.keccak256(data);
}

function packed(a, b) {
  return utils.soliditySha3(a, b);
}

function viaInstance(provider, data) {
  const web3 = new Web3(provider);
  return web3.utils.keccak256(data);
}

function account(provider, data, privateKey) {
  const web3 = new Web3(provider);
  return web3.eth.accounts.sign(data, privateKey);
}
`)
	want := map[string]string{
		"digest":      "string",
		"packed":      "string",
		"viaInstance": "",
		"account":     "",
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
			t.Errorf("%s: inferred return %q, want none (an instance member chain is not typed)", name, got.Type)
		case typ != "" && (got == nil || got.Type != typ || got.Origin != "kb-direct"):
			t.Errorf("%s: inferred return = %+v, want %s from the knowledge base", name, got, typ)
		}
	}
}
