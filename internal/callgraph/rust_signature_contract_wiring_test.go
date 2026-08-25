// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The signature-crate KBs are keyed on what the Rust parser emits, so a parser
// identity change must fail here rather than leaving the contracts unmatched.
func TestSignatureContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use dsa::SigningKey;
use ed25519::Signature;

fn build(components: u8, bytes: &[u8; 64]) {
    let _a = SigningKey::generate(&mut rand::thread_rng(), components);
    let _b = ecdsa::SigningKey::generate(&mut rand::thread_rng());
    let _c = Signature::from_bytes(bytes);
}`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"dsa.SigningKey.generate":      "dsa",
		"ecdsa.SigningKey.generate":    "ecdsa",
		"ed25519.Signature.from_bytes": "ed25519",
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				library, ok := want[method]
				if !ok {
					continue
				}
				got := kb.ContractsFor(method, len(call.Arguments))
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one contract",
						method, len(call.Arguments), len(got))
				}
				if got[0].SourceLibrary != library || got[0].Role != "factory" {
					t.Fatalf("contract for %q = %#v, want %s factory", method, got[0], library)
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
