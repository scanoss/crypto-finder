// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A module-function call has no receiver variable, so the contract's visible
// effect is the type a function returns through it: the certificate bundle
// reaches the export as the function's inferred return, whatever name the
// consumer bound the module to.
func TestNodeSelfsignedContractTypesFunctionsThatReturnTheBundle(t *testing.T) {
	t.Parallel()

	graph := buildNodeGraph(t, `const selfsigned = require('selfsigned');
const { generate } = require('selfsigned');

function certificate(attrs) {
  return selfsigned.generate(attrs, { algorithm: 'sha256' });
}

async function modern(attrs) {
  return generate(attrs, { keyType: 'ec' });
}

function withCallback(attrs, done) {
  return selfsigned.generate(attrs, {}, done);
}
`)
	want := map[string]string{
		"certificate":  "selfsigned.Pems",
		"modern":       "selfsigned.Pems",
		"withCallback": "void",
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
