// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestGoContractTypeResolver_UsesCanonicalFunctionIDs(t *testing.T) {
	kb, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: go
library:
  name: test-go
contracts:
  - method: crypto/aes.NewCipher
    arity: 1
    return:
      type: crypto/cipher.Block
      confidence: high
  - method: crypto/aes.(*Block).Encrypt
    arity: 2
    return:
      type: "[]byte"
      confidence: high
`))
	if err != nil {
		t.Fatalf("load test KB: %v", err)
	}
	newCipher := &FunctionDecl{
		ID:         FunctionID{Package: "crypto/aes", Name: "NewCipher"},
		Parameters: []FunctionParameter{{Type: "[]byte"}},
	}
	encrypt := &FunctionDecl{
		ID:         FunctionID{Package: "crypto/aes", Type: "*Block", Name: "Encrypt"},
		Parameters: []FunctionParameter{{Type: "[]byte"}, {Type: "[]byte"}},
	}

	if err := NewGoContractTypeResolver(kb).ResolveTypes(buildTestCallGraph(newCipher, encrypt), nil); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}
	if newCipher.ReturnType != "crypto/cipher.Block" {
		t.Fatalf("NewCipher ReturnType = %q, want crypto/cipher.Block", newCipher.ReturnType)
	}
	if encrypt.ReturnType != "[]byte" {
		t.Fatalf("Encrypt ReturnType = %q, want []byte", encrypt.ReturnType)
	}

	newCipher.ReturnType = "existing.Type"
	if err := NewGoContractTypeResolver(kb).ResolveTypes(buildTestCallGraph(newCipher), nil); err != nil {
		t.Fatalf("ResolveTypes with existing return type: %v", err)
	}
	if newCipher.ReturnType != "existing.Type" {
		t.Fatalf("existing ReturnType was overwritten: %q", newCipher.ReturnType)
	}
}
