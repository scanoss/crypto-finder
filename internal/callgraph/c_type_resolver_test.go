// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestCContractTypeResolver_MatchesGlobalSymbolAcrossProjectPackage(t *testing.T) {
	kb, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: c
library:
  name: test-c
contracts:
  - method: EVP_CIPHER_CTX_new
    arity: 0
    return:
      type: EVP_CIPHER_CTX*
      confidence: high
`))
	if err != nil {
		t.Fatalf("load test KB: %v", err)
	}
	fn := &FunctionDecl{ID: FunctionID{Package: "example/crypto", Name: "EVP_CIPHER_CTX_new"}}

	if err := NewCContractTypeResolver(kb).ResolveTypes(buildTestCallGraph(fn), nil); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}
	if fn.ReturnType != "EVP_CIPHER_CTX*" {
		t.Fatalf("ReturnType = %q, want EVP_CIPHER_CTX*", fn.ReturnType)
	}

	fn.ReturnType = "existing_type"
	if err := NewCContractTypeResolver(kb).ResolveTypes(buildTestCallGraph(fn), nil); err != nil {
		t.Fatalf("ResolveTypes with existing return type: %v", err)
	}
	if fn.ReturnType != "existing_type" {
		t.Fatalf("existing ReturnType was overwritten: %q", fn.ReturnType)
	}
}

func TestCContractTypeResolver_MissingKBIsNoOp(t *testing.T) {
	fn := &FunctionDecl{ID: FunctionID{Package: "example/crypto", Name: "factory"}}
	if err := NewCContractTypeResolver(nil).ResolveTypes(buildTestCallGraph(fn), nil); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}
	if fn.ReturnType != "" {
		t.Fatalf("ReturnType = %q, want empty", fn.ReturnType)
	}
}
