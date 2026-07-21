// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
	"github.com/scanoss/crypto-finder/internal/javaruntime"
)

func TestNewTypeResolverForEcosystem_Rust(t *testing.T) {
	if _, ok := NewTypeResolverForEcosystem("rust", javaruntime.Config{}).(*RustContractTypeResolver); !ok {
		t.Fatal("expected RustContractTypeResolver")
	}
}

func TestRustContractTypeResolver_SetsReturnTypeFromKB(t *testing.T) {
	kb, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: rust
library:
  name: test-rust
contracts:
  - method: ring::aead::LessSafeKey.new
    arity: 1
    return:
      type: ring::aead::LessSafeKey
      confidence: high
`))
	if err != nil {
		t.Fatalf("load test KB: %v", err)
	}
	fn := &FunctionDecl{
		ID:         FunctionID{Package: "ring::aead", Type: "LessSafeKey", Name: "new"},
		Parameters: []FunctionParameter{{Type: "UnboundKey"}},
	}

	if err := NewRustContractTypeResolver(kb).ResolveTypes(buildTestCallGraph(fn), nil); err != nil {
		t.Fatalf("ResolveTypes: %v", err)
	}
	if fn.ReturnType != "ring::aead::LessSafeKey" {
		t.Fatalf("ReturnType = %q, want ring::aead::LessSafeKey", fn.ReturnType)
	}

	fn.ReturnType = "ExistingType"
	if err := NewRustContractTypeResolver(kb).ResolveTypes(buildTestCallGraph(fn), nil); err != nil {
		t.Fatalf("ResolveTypes with existing return type: %v", err)
	}
	if fn.ReturnType != "ExistingType" {
		t.Fatalf("existing ReturnType was overwritten: %q", fn.ReturnType)
	}
}
