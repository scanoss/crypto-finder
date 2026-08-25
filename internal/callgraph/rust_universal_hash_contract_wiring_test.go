// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The universal-hash KBs are keyed on what the Rust parser emits, so a parser
// identity change must fail here rather than leaving the contracts unmatched.
func TestUniversalHashContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use ghash::GHash;
use poly1305::Poly1305;

fn authenticate(k16: &[u8; 16], k32: &[u8; 32], data: &[u8]) {
    let mut a = GHash::new(k16.into());
    a.update_padded(data);
    let _t = a.finalize();
    let mut b = Poly1305::new(k32.into());
    b.update_padded(data);
    let _u = b.finalize();
}`
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
		"ghash.GHash.new":                 {"factory", "ghash"},
		"ghash.GHash.update_padded":       {"operation", "ghash"},
		"ghash.GHash.finalize":            {"output", "ghash"},
		"poly1305.Poly1305.new":           {"factory", "poly1305"},
		"poly1305.Poly1305.update_padded": {"operation", "poly1305"},
		"poly1305.Poly1305.finalize":      {"output", "poly1305"},
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
