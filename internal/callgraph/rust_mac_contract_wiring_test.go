// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The MAC KBs are keyed on what the Rust parser emits, so a parser identity
// change must fail here rather than leaving the contracts silently unmatched.
// Both crates are exercised through the forms their own documentation uses: a
// turbofish construction and an aliased generic instantiation.
func TestMacContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, SimpleHmac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn hmac_through_alias(key: &[u8], msg: &[u8], tag: &[u8]) {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(msg);
    let _t = mac.finalize();
    mac.verify_slice(tag).unwrap();
}

fn hmac_simple(key: &[u8], msg: &[u8]) {
    let mut mac = SimpleHmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(msg);
    let _t = mac.finalize();
}

fn cmac_turbofish(key: &[u8], msg: &[u8], tag: &[u8]) {
    let mut mac = Cmac::<Aes128>::new_from_slice(key).unwrap();
    mac.update(msg);
    let _t = mac.finalize();
    mac.verify(tag.into()).unwrap();
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	// Call-site keys join segments with "."; the KBs keep Rust's "::" module
	// separator and ContractsFor bridges the two.
	want := map[string]struct{ role, library string }{
		"hmac.Hmac.new_from_slice":       {"factory", "hmac"},
		"hmac.Hmac.update":               {"operation", "hmac"},
		"hmac.Hmac.finalize":             {"output", "hmac"},
		"hmac.Hmac.verify_slice":         {"operation", "hmac"},
		"hmac.SimpleHmac.new_from_slice": {"factory", "hmac"},
		"hmac.SimpleHmac.update":         {"operation", "hmac"},
		"hmac.SimpleHmac.finalize":       {"output", "hmac"},
		"cmac.Cmac.new_from_slice":       {"factory", "cmac"},
		"cmac.Cmac.update":               {"operation", "cmac"},
		"cmac.Cmac.finalize":             {"output", "cmac"},
		"cmac.Cmac.verify":               {"operation", "cmac"},
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				expect, ok := want[method]
				if !ok {
					continue
				}
				got := kb.ContractsFor(method, len(call.Arguments))
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one contract",
						method, len(call.Arguments), len(got))
				}
				if got[0].Role != expect.role || got[0].SourceLibrary != expect.library {
					t.Fatalf("contract for %q = %#v, want %s %s", method, got[0], expect.library, expect.role)
				}
				seen[method] = true
			}
		}
	}

	for method := range want {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover %q; seen = %v", method, seen)
		}
	}
}

// The key-material argument must carry its size derivation, which is what a
// consumer of the exported supporting call keys on.
func TestMacContractsDeclareKeySizeOnConstruction(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	for _, method := range []string{"hmac.Hmac.new_from_slice", "cmac.Cmac.new_from_slice"} {
		got := kb.ContractsFor(method, 1)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, 1) = %d, want exactly one", method, len(got))
		}
		params := got[0].Parameters
		if len(params) != 1 || params[0].Contributes == nil {
			t.Fatalf("%s: want one metadata-contributing parameter, got %#v", method, params)
		}
		if params[0].Contributes.Property != "keySize" {
			t.Errorf("%s: property = %q, want keySize", method, params[0].Contributes.Property)
		}
	}
}
