// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"testing"
)

// resolveFluentChainsByReturnType re-qualifies a chain link from the previous
// link's return type. It did so through normalizeLookupTypeName, which reduces
// `ed25519_dalek::Keypair` to the bare `Keypair`, and then looked that bare name
// up in an index built ONLY from types the scanned source declares. A wrapper
// crate that names its own type after the one it wraps therefore had a
// correctly-resolved dependency callee overwritten with its own same-named
// method.
//
// Measured on tlfs-crdt 0.1.0 src/crypto.rs:39 (published on crates.io):
// `self.to_keypair().sign(msg)` inside the crate's own `impl Keypair`. The
// parser resolved the second link to ed25519_dalek.(Keypair).sign; this pass
// rewrote it to tlfs_crdt::crypto.(Keypair).sign. The consequence is not
// cosmetic — the call then joins the wrapper's contract instead of the crate's,
// and anything asking the graph which crate the call belongs to is told the
// wrapper.
//
// The wrapper naming its type differently is the control: the same rewrite
// cannot fire there, so both cases must agree on the callee.
func TestRustFluentChain_QualifiedReturnTypeIsNotRequalifiedToALocalType(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		localType string
	}{
		{"wrapper shares the dependency's type name", "Keypair"},
		{"wrapper uses its own type name", "MyKeypair"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := `use ed25519_dalek::{PublicKey, SecretKey, Signature};

pub struct ` + tc.localType + `([u8; 32]);

impl ` + tc.localType + ` {
    fn to_keypair(self) -> ed25519_dalek::Keypair {
        let secret = SecretKey::from_bytes(&self.0).unwrap();
        let public = PublicKey::from(&secret);
        ed25519_dalek::Keypair { secret, public }
    }
    pub fn sign(self, msg: &[u8]) -> Signature {
        self.to_keypair().sign(msg)
    }
}
`
			got := parseRustCalleeFQNsBuilt(t, src)
			const raw = "self.to_keypair().sign"
			key, ok := got[raw]
			if !ok {
				t.Fatalf("no call node for %q; got %v", raw, got)
			}
			if key != "ed25519_dalek.(Keypair).sign" {
				t.Errorf("%q resolved to %q, want ed25519_dalek.(Keypair).sign", raw, key)
			}
		})
	}
}

// parseRustCalleeFQNsBuilt is parseRustCalleeFQNs run through the FULL builder,
// not the parser alone. The distinction matters here: the parser resolved the
// case above correctly and a post-build pass undid it, so a parser-only helper
// asserts nothing about this defect.
func parseRustCalleeFQNsBuilt(t *testing.T, src string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	writeRustTestFile(t, dir, src)
	b := NewBuilderForEcosystem("rust", NewRustParser())
	graph, err := b.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	got := map[string]string{}
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			if c := &fn.Calls[i]; c.Raw != "" {
				got[c.Raw] = c.Callee.String()
			}
		}
	}
	return got
}

// declaredTypeQualifier is what separates "the return type was written with a
// module path" from "the return type was a bare name", which is the whole basis
// of the guard above.
func TestRustFluentChain_DeclaredTypeQualifier(t *testing.T) {
	t.Parallel()
	for typeName, want := range map[string]string{
		"ed25519_dalek::Keypair":          "ed25519_dalek",
		"ed25519_dalek::keypair::Keypair": "ed25519_dalek.keypair",
		"Keypair":                         "",
		"":                                "",
		"io.jsonwebtoken.JwtBuilder":      "io.jsonwebtoken",
		"Vec<ed25519_dalek::Keypair>":     "",
		"*ed25519_dalek::Keypair":         "ed25519_dalek",
	} {
		if got := declaredTypeQualifier(typeName); got != want {
			t.Errorf("declaredTypeQualifier(%q) = %q, want %q", typeName, got, want)
		}
	}
}
