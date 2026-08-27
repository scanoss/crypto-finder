// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The block-mode KBs are keyed on what the Rust parser emits for a turbofish
// call through a type alias, so a parser identity change must fail here rather
// than leaving the contracts silently unmatched.
func TestBlockModeContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use aes::Aes128;
use cbc::{Decryptor, Encryptor};

fn cbc_roundtrip(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    let enc = Encryptor::<Aes128>::new(key.into(), iv.into());
    let _ct = enc.encrypt_padded_mut(buf, 16);
    let dec = cbc::Decryptor::<Aes128>::new(key.into(), iv.into());
    let _pt = dec.decrypt_padded_mut(buf);
}

fn cfb_roundtrip(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    let enc = cfb_mode::Encryptor::<Aes128>::new(key.into(), iv.into());
    enc.encrypt(buf);
    let dec = cfb_mode::Decryptor::<Aes128>::new(key.into(), iv.into());
    dec.decrypt(buf);
    let buffered = cfb_mode::BufEncryptor::<Aes128>::new(key.into(), iv.into());
    let _ = buffered;
}

fn ctr_stream(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    let mut c = ctr::Ctr128BE::<Aes128>::new(key.into(), iv.into());
    c.apply_keystream(buf);
    let mut d = ctr::Ctr64LE::<Aes128>::new(key.into(), iv.into());
    d.apply_keystream(buf);
    let mut e = ctr::Ctr32BE::<Aes128>::new(key.into(), iv.into());
    e.try_apply_keystream(buf);
    let mut g = ctr::Ctr128LE::<Aes128>::new_from_slices(key, iv).unwrap();
    g.apply_keystream(buf);
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
		"cbc.Encryptor.new":                {"factory", "cbc"},
		"cbc.Decryptor.new":                {"factory", "cbc"},
		"cbc.Encryptor.encrypt_padded_mut": {"operation", "cbc"},
		"cbc.Decryptor.decrypt_padded_mut": {"operation", "cbc"},
		"cfb_mode.Encryptor.new":           {"factory", "cfb-mode"},
		"cfb_mode.Decryptor.new":           {"factory", "cfb-mode"},
		"cfb_mode.BufEncryptor.new":        {"factory", "cfb-mode"},
		"ctr.Ctr128BE.new":                 {"factory", "ctr"},
		"ctr.Ctr64LE.new":                  {"factory", "ctr"},
		"ctr.Ctr128BE.apply_keystream":     {"operation", "ctr"},
		"ctr.Ctr32BE.new":                  {"factory", "ctr"},
		"ctr.Ctr32BE.try_apply_keystream":  {"operation", "ctr"},
		"ctr.Ctr128LE.new_from_slices":     {"factory", "ctr"},
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
					t.Fatalf("contract for %q = role %q library %q, want %s %s",
						method, got[0].Role, got[0].SourceLibrary, expect.role, expect.library)
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

// A contract that declares parameter_types is what fills the exported canonical
// signature; without it the export carries "cbc.Encryptor.new(?, ?)" and empty
// parameter types. Pin the declared shape so a regression is visible.
func TestBlockModeContractsDeclareCanonicalSignatures(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	cases := []struct {
		method     string
		arity      int
		paramTypes []string
		returnType string
	}{
		{
			method:     "cbc::Encryptor.new",
			arity:      2,
			paramTypes: []string{"&cipher::Key<cbc::Encryptor>", "&cipher::Iv<cbc::Encryptor>"},
			returnType: "cbc::Encryptor",
		},
		{
			method:     "cfb_mode::Decryptor.new",
			arity:      2,
			paramTypes: []string{"&cipher::Key<cfb_mode::Decryptor>", "&cipher::Iv<cfb_mode::Decryptor>"},
			returnType: "cfb_mode::Decryptor",
		},
		{
			method:     "ctr::Ctr128BE.new",
			arity:      2,
			paramTypes: []string{"&cipher::Key<ctr::Ctr128BE>", "&cipher::Iv<ctr::Ctr128BE>"},
			returnType: "ctr::Ctr128BE",
		},
	}

	for _, tc := range cases {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", tc.method, tc.arity, len(got))
		}
		c := got[0]
		if c.CanonicalReturnType != tc.returnType {
			t.Errorf("%s canonical_return_type = %q, want %q", tc.method, c.CanonicalReturnType, tc.returnType)
		}
		if len(c.ParameterTypes) != len(tc.paramTypes) {
			t.Fatalf("%s parameter_types = %v, want %v", tc.method, c.ParameterTypes, tc.paramTypes)
		}
		for i, want := range tc.paramTypes {
			if c.ParameterTypes[i] != want {
				t.Errorf("%s parameter_types[%d] = %q, want %q", tc.method, i, c.ParameterTypes[i], want)
			}
		}
		// The IV width is the inner cipher's block size, so it is derived from
		// the argument rather than asserted as a constant.
		if len(c.Parameters) != 2 {
			t.Fatalf("%s parameters = %d, want 2", tc.method, len(c.Parameters))
		}
		if c.Parameters[1].Contributes == nil || c.Parameters[1].Contributes.Property != "ivSize" {
			t.Errorf("%s parameter 1 must contribute ivSize, got %#v", tc.method, c.Parameters[1].Contributes)
		}
	}
}
