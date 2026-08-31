// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"strings"
	"testing"
)

// A generic parameter bound to a cataloged trait (`C: KeyInit`) already
// carries that trait's identity. `C::KeySize` names KeyInit's associated
// type, not KeyInit itself, and the KB's trait_associated_types resolves it
// to what the trait declares -- the same way a call resolves past its
// receiver, not to the receiver's own name.
func TestRustParser_GenericAssociatedTypeResolvesThroughCatalogedTrait(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		trait string
		assoc string
	}{
		{"KeyInit::KeySize", "KeyInit", "KeySize"},
		{"Digest::OutputSize", "Digest", "OutputSize"},
		{"BlockSizeUser::BlockSize", "BlockSizeUser", "BlockSize"},
		{"AeadCore::NonceSize", "AeadCore", "NonceSize"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := "fn use_it<C: " + tc.trait + ">(size: C::" + tc.assoc + ") {\n    size.as_slice();\n}\n"
			got := parseRustCalleeFQNs(t, src)
			asserted := 0
			for raw, key := range got {
				if !strings.HasSuffix(raw, "as_slice") {
					continue
				}
				asserted++
				if key != "generic_array.GenericArray.as_slice" {
					t.Errorf("%s resolved to %q, want %q", raw, key, "generic_array.GenericArray.as_slice")
				}
			}
			if asserted == 0 {
				t.Fatalf("no as_slice call parsed; got %v", got)
			}
		})
	}
}

// A generic bound to an uncataloged trait keeps the trait as its identity: no
// associated-type entry exists to resolve past it, and guessing one would be
// a wrong identity, not a missing one.
func TestRustParser_GenericAssociatedTypeOfUncatalogedTraitKeepsTraitIdentity(t *testing.T) {
	t.Parallel()

	src := `fn use_it<C: SomeUnknownTrait>(size: C::SomeAssoc) {
    size.as_slice();
}
`
	got := parseRustCalleeFQNs(t, src)
	asserted := 0
	for raw, key := range got {
		if !strings.HasSuffix(raw, "as_slice") {
			continue
		}
		asserted++
		if key == "generic_array.GenericArray.as_slice" {
			t.Errorf("%s resolved to a cataloged type from an uncataloged trait bound; got %q", raw, key)
		}
	}
	if asserted == 0 {
		t.Fatalf("no as_slice call parsed; got %v", got)
	}
}
