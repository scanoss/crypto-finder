// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestNodeContractTypeResolver_UsesCanonicalFunctionIDs(t *testing.T) {
	kb, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: node
library:
  name: test-node
contracts:
  - method: node-forge.md.sha256.create
    arity: 0
    return:
      type: node-forge.md.MessageDigest
      confidence: high
`))
	if err != nil {
		t.Fatalf("load test KB: %v", err)
	}
	create := &FunctionDecl{ID: FunctionID{Package: "node-forge.md.sha256", Name: "create"}}

	if err := NewNodeContractTypeResolver(kb).ResolveTypes(buildTestCallGraph(create), nil); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}
	if create.ReturnType != "node-forge.md.MessageDigest" {
		t.Fatalf("ReturnType = %q, want node-forge.md.MessageDigest", create.ReturnType)
	}

	create.ReturnType = "ExistingType"
	if err := NewNodeContractTypeResolver(kb).ResolveTypes(buildTestCallGraph(create), nil); err != nil {
		t.Fatalf("ResolveTypes with existing return type: %v", err)
	}
	if create.ReturnType != "ExistingType" {
		t.Fatalf("existing ReturnType was overwritten: %q", create.ReturnType)
	}
}
