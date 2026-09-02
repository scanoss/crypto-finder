// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The tfhe KB is keyed on what the Rust parser emits for the crate's THREE
// layers, which a consumer reaches through different spellings: the high-level
// API (crate-root re-exports, so no module segment in the key), the 0.1.x-era
// `gen_keys` free functions, and the integer layer's ClientKey methods. A parser
// identity change must fail here rather than leaving the contracts silently
// unmatched, which is the state the family started in — an exported graph
// showed `tfhe.generate_keys(?)` with empty parameter_types.
func TestTfheContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use tfhe::integer::RadixClientKey;
use tfhe::prelude::*;
use tfhe::{generate_keys, gen_keys_radix, set_server_key, ConfigBuilder, FheUint32};

fn high_level_api(value: u32) {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);
    let ct = FheUint32::encrypt(value, &client_key);
    let _clear: u32 = ct.decrypt(&client_key);
}

fn integer_layer(params: u8, value: u64) {
    let (ck, _sk): (RadixClientKey, _) = gen_keys_radix(params, 4);
    let ct = ck.encrypt_radix(value, 4);
    let _clear: u64 = ck.decrypt_radix(&ct);
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	// Call-site keys join segments with "."; the KB keeps Rust's "::" module
	// separator and ContractsFor bridges the two. The high-level names carry no
	// module segment because lib.rs re-exports them from the crate root.
	want := map[string]string{
		"tfhe.generate_keys":                         "factory",
		"tfhe.set_server_key":                        "config",
		"tfhe.ConfigBuilder.build":                   "factory",
		"tfhe.FheUint32.encrypt":                     "operation",
		"tfhe.FheUint32.decrypt":                     "output",
		"tfhe.gen_keys_radix":                        "factory",
		"tfhe::integer.RadixClientKey.encrypt_radix": "operation",
		"tfhe::integer.RadixClientKey.decrypt_radix": "output",
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				role, ok := want[method]
				if !ok {
					continue
				}
				got := kb.ContractsFor(method, len(call.Arguments))
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one contract",
						method, len(call.Arguments), len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "tfhe" {
					t.Fatalf("contract for %q = %#v, want tfhe %s", method, got[0], role)
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

// tfhe 0.0.0 is a NAME PLACEHOLDER: its whole crate is `pub fn placeholder() {}`.
// The contract's version_range starts at 0.1.0 for that reason, and this pins
// that nothing in the KB claims to type a crate that has no API — a mined 0.0.0
// row is an honest zero, not a coverage gap.
func TestTfheContractRangeExcludesThePlaceholderRelease(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	got := kb.ContractsFor("tfhe.placeholder", 0)
	if len(got) != 0 {
		t.Fatalf("ContractsFor(tfhe.placeholder) = %#v, want none", got)
	}
}
