// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The sodiumoxide KB is keyed on what the Rust parser emits, so a parser
// identity change must fail here rather than leaving the contracts unmatched.
// Covers both call shapes a consumer writes: the imported module path and the
// fully qualified one.
func TestSodiumoxideContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::hash::sha256;

fn roundtrip(plaintext: &[u8]) {
    let key = secretbox::gen_key();
    let nonce = secretbox::gen_nonce();
    let cipher = secretbox::seal(plaintext, &nonce, &key);
    let _ = sha256::hash(plaintext);
    let _ = sodiumoxide::crypto::sign::sign_detached(plaintext, &key);
    let _ = cipher;
}`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	// Call-site keys join every identifier segment with ".", while the KB is
	// authored with Rust's own "::" module separator; ContractsFor bridges the
	// two. Assert on what the parser emits, so a change to either side fails.
	want := map[string]string{
		"sodiumoxide::crypto.secretbox.gen_key":   "factory",
		"sodiumoxide::crypto.secretbox.gen_nonce": "factory",
		"sodiumoxide::crypto.secretbox.seal":      "operation",
		"sodiumoxide::crypto::hash.sha256.hash":   "operation",
		"sodiumoxide::crypto::sign.sign_detached": "operation",
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				// The KB is looked up with the same key the inference engine builds.
				method, _ := splitMethodArity(&callee)
				role, expected := want[method]
				if !expected {
					continue
				}
				got := kb.ContractsFor(method, len(call.Arguments))
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one sodiumoxide contract",
						method, len(call.Arguments), len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "sodiumoxide" {
					t.Fatalf("contract for %q = %#v, want sodiumoxide %s", method, got[0], role)
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
