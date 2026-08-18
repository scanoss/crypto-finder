// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Rust KBs are authored with Rust's own module/type separator
// ("ring::aead::UnboundKey.new") while call-site FQNs join every FunctionID
// segment with "." and carry no encoded arity. Both shapes must resolve.
func TestContractsFor_RustCallSiteKeyShapes(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		name   string
		method string
		arity  int
		want   string
	}{
		{
			name:   "authored key with known arity",
			method: "ring::aead::UnboundKey.new",
			arity:  2,
			want:   "ring::aead::UnboundKey",
		},
		{
			name:   "dot-joined call-site key with known arity",
			method: "ring::aead.UnboundKey.new",
			arity:  2,
			want:   "ring::aead::UnboundKey",
		},
		{
			name:   "dot-joined call-site key with unknown arity",
			method: "ring::aead.UnboundKey.new",
			arity:  -1,
			want:   "ring::aead::UnboundKey",
		},
		{
			name:   "authored key with unknown arity",
			method: "ring::aead::UnboundKey.new",
			arity:  -1,
			want:   "ring::aead::UnboundKey",
		},
		{
			name:   "free function keeps the module separator",
			method: "ring.digest.digest",
			arity:  2,
			want:   "ring::digest::Digest",
		},
		{
			name:   "zero-arity method with unknown arity",
			method: "ring::digest.Context.finish",
			arity:  -1,
			want:   "ring::digest::Digest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := kb.ContractsFor(tt.method, tt.arity)
			if len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", tt.method, tt.arity, len(got))
			}
			if got[0].Return.Type != tt.want {
				t.Fatalf("ContractsFor(%q, %d) return type = %q, want %q", tt.method, tt.arity, got[0].Return.Type, tt.want)
			}
		})
	}
}

// A wrong arity must still miss: normalization only rewrites the separator, it
// never relaxes an arity the caller actually knows.
func TestContractsFor_RustWrongArityStillMisses(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	if got := kb.ContractsFor("ring::aead.UnboundKey.new", 5); len(got) != 0 {
		t.Fatalf("ContractsFor(ring::aead.UnboundKey.new, 5) = %d contracts, want 0", len(got))
	}
}

// The normalization is Rust-only: a Java-shaped KB keeps exact-key semantics.
func TestContractsFor_NonRustEcosystemKeysUnchanged(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: java
library:
  name: test-java
contracts:
  - method: javax.crypto.Cipher.getInstance
    arity: 1
    return: { type: javax.crypto.Cipher, confidence: high }
    role: factory
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := kb.ContractsFor("javax.crypto.Cipher.getInstance", 1); len(got) != 1 {
		t.Fatalf("exact Java lookup = %d contracts, want 1", len(got))
	}
	for _, method := range []string{"javax.crypto::Cipher.getInstance", "javax::crypto.Cipher.getInstance"} {
		if got := kb.ContractsFor(method, 1); len(got) != 0 {
			t.Fatalf("ContractsFor(%q, 1) = %d contracts, want 0", method, len(got))
		}
	}
	if got := kb.ContractsFor("javax.crypto.Cipher.getInstance", -1); len(got) != 0 {
		t.Fatalf("Java unknown-arity lookup = %d contracts, want 0", len(got))
	}
}
