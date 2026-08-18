// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Both the type-import form (`use ring::aead::UnboundKey;`) and the fully
// qualified call form resolve to the same callee, so both must reach the same
// Rust contract through the lookup key the inference path builds.
//
// The module-import form (`use ring::digest;` then `digest::Context::new(..)`)
// is deliberately absent: the parser folds the receiver type into the package
// path there, so the callee carries no Type and no lookup key can match. That
// is a separate parser defect tracked in #280, upstream of this key shape.
func TestRustCallSiteContractLookup_ImportedAndFullyQualifiedForms(t *testing.T) {
	src := `use ring::aead::UnboundKey;
use ring::digest;

fn seal(key: &[u8], data: &[u8]) {
    let imported = UnboundKey::new(&ring::aead::AES_256_GCM, key);
    let qualified = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key);
    let mut ctx = ring::digest::Context::new(&digest::SHA256);
    ctx.update(data);
    let free = digest::digest(&digest::SHA256, data);
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "seal.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "myproject")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// method name -> number of call sites that must resolve a contract.
	wantSites := map[string]int{"new": 3, "update": 1, "digest": 1}
	gotSites := map[string]int{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			for j := range analysis.Functions[i].Calls {
				call := &analysis.Functions[i].Calls[j]
				fqn, arity := splitMethodArity(&call.Callee)
				matches := kb.ContractsFor(fqn, arity)
				if len(matches) == 0 {
					t.Errorf("no contract for call %q (fqn %q, arity %d)", call.Callee.Name, fqn, arity)
					continue
				}
				gotSites[BaseFunctionName(call.Callee.Name)]++
			}
		}
	}
	for name, want := range wantSites {
		if gotSites[name] != want {
			t.Errorf("resolved %q call sites = %d, want %d", name, gotSites[name], want)
		}
	}
}

// parameter_roles reach the export only if the contract resolves, so pin the
// roles a resolved Rust contract carries.
func TestRustCallSiteContractLookup_CarriesParameterRoles(t *testing.T) {
	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	id := FunctionID{Package: "ring::aead", Type: "UnboundKey", Name: "new"}
	fqn, arity := splitMethodArity(&id)
	matches := kb.ContractsFor(fqn, arity)
	if len(matches) != 1 {
		t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", fqn, arity, len(matches))
	}
	params := matches[0].Parameters
	if len(params) != 2 {
		t.Fatalf("parameters = %d, want 2", len(params))
	}
	if params[0].Role != "operation-determining" || params[0].Contributes == nil || params[0].Contributes.Property != "algorithm" {
		t.Errorf("parameter 0 = %#v, want operation-determining contributing algorithm", params[0])
	}
	if params[1].Role != "metadata-contributing" || params[1].Contributes == nil || params[1].Contributes.Property != "keySize" {
		t.Errorf("parameter 1 = %#v, want metadata-contributing contributing keySize", params[1])
	}
}
