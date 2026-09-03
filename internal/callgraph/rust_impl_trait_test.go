// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"testing"
)

// `impl <Trait> for <Type>` gives every method inside it two identities: the
// receiver is the TYPE, but the API is the TRAIT's, and the trait frequently
// belongs to another crate. apple-codesign 0.16.0 writes
// `impl EncodePrivateKey for InMemoryPrivateKey` under
// `use pkcs8::EncodePrivateKey` — its own type, pkcs8's `to_pkcs8_der`. The
// parser read the impl header's trait field and discarded it, so nothing
// downstream could tell that apart from a same-named inherent method.
//
// OwnerTraits records the trait with its path resolved through the file's
// imports. An inherent impl leaves it nil, and a trait the crate declares itself
// stays a bare name — which is what it means: not another crate's API.
func TestRustParser_ImplBlockRecordsItsTrait(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		src    string
		method string
		want   string
	}{
		{
			name: "trait imported by name",
			src: `use pkcs8::EncodePrivateKey;
pub struct MyKey;
impl EncodePrivateKey for MyKey {
    fn to_pkcs8_der(&self) -> Vec<u8> { vec![] }
}`,
			method: "to_pkcs8_der",
			want:   "pkcs8::EncodePrivateKey",
		},
		{
			name: "trait imported in a braced group",
			src: `use pkcs8::{der::Decodable, EncodePrivateKey, PrivateKeyDocument};
pub struct MyKey;
impl EncodePrivateKey for MyKey {
    fn to_pkcs8_der(&self) -> Vec<u8> { vec![] }
}`,
			method: "to_pkcs8_der",
			want:   "pkcs8::EncodePrivateKey",
		},
		{
			name: "path written in the header",
			src: `pub struct MyKey;
impl pkcs8::EncodePrivateKey for MyKey {
    fn to_pkcs8_der(&self) -> Vec<u8> { vec![] }
}`,
			method: "to_pkcs8_der",
			want:   "pkcs8::EncodePrivateKey",
		},
		{
			name: "generic arguments are not part of the trait identity",
			src: `use signature::Signer;
pub struct MyKey;
impl Signer<Signature> for MyKey {
    fn sign(&self, m: &[u8]) -> Vec<u8> { m.to_vec() }
}`,
			method: "sign",
			want:   "signature::Signer",
		},
		{
			name: "a trait the crate declares itself stays bare",
			src: `pub trait MySigner { fn sign(&self, m: &[u8]) -> Vec<u8>; }
pub struct MyKey;
impl MySigner for MyKey {
    fn sign(&self, m: &[u8]) -> Vec<u8> { m.to_vec() }
}`,
			method: "sign",
			want:   "MySigner",
		},
		{
			name: "an inherent impl records no trait",
			src: `pub struct MyKey;
impl MyKey {
    pub fn sign(&self, m: &[u8]) -> Vec<u8> { m.to_vec() }
}`,
			method: "sign",
			want:   "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeRustTestFile(t, dir, tc.src+"\n")
			b := NewBuilderForEcosystem("rust", NewRustParser())
			graph, err := b.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
			if err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
			found := false
			for _, fn := range graph.Functions {
				if fn.ID.Name != tc.method {
					continue
				}
				found = true
				got := ""
				if len(fn.OwnerTraits) > 0 {
					got = fn.OwnerTraits[0]
				}
				if got != tc.want {
					t.Errorf("OwnerTraits = %v, want %q", fn.OwnerTraits, tc.want)
				}
			}
			if !found {
				t.Fatalf("no declaration of %q in the graph", tc.method)
			}
		})
	}
}

// A braced group nested inside a braced group now reaches the Imports map, so
// the trait is qualified. This was a known gap, pinned by an earlier revision of
// this test with the note "if this now resolves to pkcs8::EncodePrivateKey the
// gap is fixed and this test should assert that instead" -- which is what it
// does now. The gap closed when processUseDecl learned to descend into a BARE
// `use { .. };` group; before that the whole declaration was skipped and none of
// its items were recorded as imports at all.
// apple-codesign 0.16.0 src/cryptography.rs imports pkcs8 this way.
func TestRustParser_NestedBracedImportGroupQualifiesTheTrait(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeRustTestFile(t, dir, `use {
    der::{asn1, Document},
    pkcs8::{der::Decodable, EncodePrivateKey},
};

pub struct MyKey;
impl EncodePrivateKey for MyKey {
    fn to_pkcs8_der(&self) -> Vec<u8> { vec![] }
}
`)
	b := NewBuilderForEcosystem("rust", NewRustParser())
	graph, err := b.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	for _, fn := range graph.Functions {
		if fn.ID.Name != "to_pkcs8_der" {
			continue
		}
		if len(fn.OwnerTraits) != 1 || fn.OwnerTraits[0] != "pkcs8::EncodePrivateKey" {
			t.Errorf("OwnerTraits = %v, want [pkcs8::EncodePrivateKey]; a bare "+
				"`use { .. }` group must bind its items like the one-per-line form",
				fn.OwnerTraits)
		}
	}
}
