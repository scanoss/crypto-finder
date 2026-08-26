// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The RustCrypto block-cipher KBs (aes, blowfish, des) are keyed on what the
// Rust parser emits, so a parser identity change must fail here rather than
// leaving the contracts silently unmatched. A wrong key is worse than a missing
// one: a dropped call reads as zero coverage, while a polluted identity looks
// like data and joins nothing. Every key below is asserted exactly, and the
// fixture is written so that every contract in the three KBs is exercised.
func TestBlockCipherContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	// Both constructor spellings appear: `new_varkey` is the slice constructor
	// of block-cipher-trait 0.6 / block-cipher 0.8 / cipher 0.2, covering the
	// older half of the Tier 0 range, and `new_from_slice` is its replacement
	// from cipher 0.3 onwards.
	src := `use aes::{Aes128, Aes192, Aes256};
use blowfish::{Blowfish, BlowfishLE};
use des::{Des, TdesEde2, TdesEde3, TdesEee2, TdesEee3};

fn aes_combined(k16: &[u8; 16], k24: &[u8; 24], k32: &[u8; 32], b: &mut [u8; 16]) {
    let a = Aes128::new(k16.into());
    a.encrypt_block(b.into());
    a.decrypt_block(b.into());
    let c = Aes128::new_varkey(k16).unwrap();
    c.encrypt_blocks(b.into());
    c.decrypt_blocks(b.into());
    let d = Aes192::new_from_slice(k24).unwrap();
    d.encrypt_block(b.into());
    d.decrypt_block(b.into());
    let e = Aes192::new_varkey(k24).unwrap();
    e.encrypt_blocks(b.into());
    e.decrypt_blocks(b.into());
    let f = Aes256::new(k32.into());
    f.encrypt_block(b.into());
    f.decrypt_block(b.into());
    let g = Aes256::new_from_slice(k32).unwrap();
    g.encrypt_blocks(b.into());
    g.decrypt_blocks(b.into());
    let h = Aes128::new_from_slice(k16).unwrap();
    let i = Aes192::new(k24.into());
    let j = Aes256::new_varkey(k32).unwrap();
    let _ = (h, i, j);
}

fn aes_split_roles(k16: &[u8; 16], k24: &[u8; 24], k32: &[u8; 32], b: &mut [u8; 16]) {
    let a = aes::Aes128Enc::new(k16.into());
    a.encrypt_block(b.into());
    a.encrypt_blocks(b.into());
    let c = aes::Aes128Enc::new_from_slice(k16).unwrap();
    let d = aes::Aes128Enc::new(k16.into());
    let e = aes::Aes128Dec::new(k16.into());
    e.decrypt_block(b.into());
    e.decrypt_blocks(b.into());
    let f = aes::Aes128Dec::new_from_slice(k16).unwrap();
    let g = aes::Aes128Dec::new(k16.into());
    let h = aes::Aes192Enc::new(k24.into());
    h.encrypt_block(b.into());
    h.encrypt_blocks(b.into());
    let i = aes::Aes192Enc::new_from_slice(k24).unwrap();
    let j = aes::Aes192Enc::new(k24.into());
    let l = aes::Aes192Dec::new(k24.into());
    l.decrypt_block(b.into());
    l.decrypt_blocks(b.into());
    let m = aes::Aes192Dec::new_from_slice(k24).unwrap();
    let n = aes::Aes192Dec::new(k24.into());
    let o = aes::Aes256Enc::new(k32.into());
    o.encrypt_block(b.into());
    o.encrypt_blocks(b.into());
    let p = aes::Aes256Enc::new_from_slice(k32).unwrap();
    let q = aes::Aes256Enc::new(k32.into());
    let r = aes::Aes256Dec::new(k32.into());
    r.decrypt_block(b.into());
    r.decrypt_blocks(b.into());
    let s = aes::Aes256Dec::new_from_slice(k32).unwrap();
    let u = aes::Aes256Dec::new(k32.into());
    let _ = (c, d, f, g, i, j, m, n, p, q, s, u);
}

fn blowfish_ops(key: &[u8], b: &mut [u8; 8]) {
    let a: Blowfish = Blowfish::new_from_slice(key).unwrap();
    a.encrypt_block(b.into());
    a.decrypt_block(b.into());
    let c = Blowfish::new_varkey(key).unwrap();
    c.encrypt_blocks(b.into());
    c.decrypt_blocks(b.into());
    let d = Blowfish::new(key.into());
    let e = BlowfishLE::new_from_slice(key).unwrap();
    e.encrypt_block(b.into());
    e.decrypt_block(b.into());
    let f = BlowfishLE::new_varkey(key).unwrap();
    f.encrypt_blocks(b.into());
    f.decrypt_blocks(b.into());
    let g = BlowfishLE::new(key.into());
    let _ = (d, g);
}

fn des_ops(k8: &[u8; 8], k16: &[u8; 16], k24: &[u8; 24], b: &mut [u8; 8]) {
    let a = Des::new(k8.into());
    a.encrypt_block(b.into());
    a.decrypt_block(b.into());
    let c = Des::new_from_slice(k8).unwrap();
    c.encrypt_blocks(b.into());
    c.decrypt_blocks(b.into());
    let d = Des::new_varkey(k8).unwrap();
    let e = TdesEde3::new(k24.into());
    e.encrypt_block(b.into());
    e.decrypt_block(b.into());
    let f = TdesEde3::new_from_slice(k24).unwrap();
    f.encrypt_blocks(b.into());
    f.decrypt_blocks(b.into());
    let g = TdesEde3::new_varkey(k24).unwrap();
    let h = TdesEee3::new(k24.into());
    h.encrypt_block(b.into());
    h.decrypt_block(b.into());
    let i = TdesEee3::new_from_slice(k24).unwrap();
    i.encrypt_blocks(b.into());
    i.decrypt_blocks(b.into());
    let j = TdesEee3::new_varkey(k24).unwrap();
    let l = TdesEde2::new(k16.into());
    l.encrypt_block(b.into());
    l.decrypt_block(b.into());
    let m = TdesEde2::new_from_slice(k16).unwrap();
    m.encrypt_blocks(b.into());
    m.decrypt_blocks(b.into());
    let n = TdesEde2::new_varkey(k16).unwrap();
    let o = TdesEee2::new(k16.into());
    o.encrypt_block(b.into());
    o.decrypt_block(b.into());
    let p = TdesEee2::new_from_slice(k16).unwrap();
    p.encrypt_blocks(b.into());
    p.decrypt_blocks(b.into());
    let q = TdesEee2::new_varkey(k16).unwrap();
    let _ = (d, g, j, n, q);
}

fn legacy_des_ops(message: &[u8], key: &[u8; 8]) {
    let ct = des::encrypt(message, key);
    let _pt = des::decrypt(&ct, key);
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	// Call-site keys join segments with "."; the KBs keep Rust's "::" module
	// separator and ContractsFor bridges the two. `des` is a single-segment
	// crate, so its free functions have no module/type separator to bridge and
	// are authored in the dot form.
	want := map[string]struct{ role, library string }{}
	ctors := []string{"new", "new_from_slice", "new_varkey"}
	addType := func(pkg, typ string, ops []string, ctors []string) {
		for _, c := range ctors {
			want[pkg+"."+typ+"."+c] = struct{ role, library string }{"factory", pkg}
		}
		for _, o := range ops {
			want[pkg+"."+typ+"."+o] = struct{ role, library string }{"operation", pkg}
		}
	}
	both := []string{"encrypt_block", "decrypt_block", "encrypt_blocks", "decrypt_blocks"}
	encOnly := []string{"encrypt_block", "encrypt_blocks"}
	decOnly := []string{"decrypt_block", "decrypt_blocks"}
	// The split-role types are public only from aes 0.8, which uses cipher 0.4,
	// so they never had new_varkey and no contract declares it for them.
	splitRoleCtors := []string{"new", "new_from_slice"}
	for _, t := range []string{"Aes128", "Aes192", "Aes256"} {
		addType("aes", t, both, ctors)
		addType("aes", t+"Enc", encOnly, splitRoleCtors)
		addType("aes", t+"Dec", decOnly, splitRoleCtors)
	}
	addType("blowfish", "Blowfish", both, ctors)
	addType("blowfish", "BlowfishLE", both, ctors)
	for _, t := range []string{"Des", "TdesEde3", "TdesEee3", "TdesEde2", "TdesEee2"} {
		addType("des", t, both, ctors)
	}
	want["des.encrypt"] = struct{ role, library string }{"operation", "des"}
	want["des.decrypt"] = struct{ role, library string }{"operation", "des"}

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
			t.Errorf("parsed calls did not cover %q", method)
		}
	}
	if len(seen) != len(want) {
		t.Errorf("covered %d of %d contract keys", len(seen), len(want))
	}
}

// Key size is fixed per type for aes and des but genuinely variable for
// blowfish (4 to 56 bytes). Pin that the key argument is metadata-contributing
// on every constructor spelling in all three, so a call site's actual key
// length reaches the export instead of a default invented from the algorithm
// family.
func TestBlockCipherContractsCarryKeySizeParameterRoles(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	types := map[string][]string{
		"aes":      {"Aes128", "Aes192", "Aes256"},
		"blowfish": {"Blowfish", "BlowfishLE"},
		"des":      {"Des", "TdesEde3", "TdesEee3", "TdesEde2", "TdesEee2"},
	}
	// Split-role types carry only the two constructors they ever had.
	splitRole := []string{"Aes128Enc", "Aes128Dec", "Aes192Enc", "Aes192Dec", "Aes256Enc", "Aes256Dec"}
	for _, typ := range splitRole {
		for _, method := range []string{"new", "new_from_slice"} {
			id := FunctionID{Package: "aes", Type: typ, Name: method}
			fqn, arity := splitMethodArity(&id)
			matches := kb.ContractsFor(fqn, arity)
			if len(matches) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", fqn, arity, len(matches))
			}
		}
		id := FunctionID{Package: "aes", Type: typ, Name: "new_varkey"}
		fqn, arity := splitMethodArity(&id)
		if got := kb.ContractsFor(fqn, arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) = %d contracts, want 0: %s is public only from "+
				"aes 0.8, which has no new_varkey", fqn, arity, len(got), typ)
		}
	}
	for pkg, idents := range types {
		for _, typ := range idents {
			for _, method := range []string{"new", "new_from_slice", "new_varkey"} {
				id := FunctionID{Package: pkg, Type: typ, Name: method}
				fqn, arity := splitMethodArity(&id)
				matches := kb.ContractsFor(fqn, arity)
				if len(matches) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", fqn, arity, len(matches))
				}
				params := matches[0].Parameters
				if len(params) != 1 {
					t.Fatalf("%s: parameters = %d, want 1", fqn, len(params))
				}
				if params[0].Role != "metadata-contributing" || params[0].Contributes == nil ||
					params[0].Contributes.Property != "keySize" ||
					params[0].Contributes.Derivation != "argument_bit_length" {
					t.Errorf("%s: parameter 0 = %#v, want metadata-contributing keySize/argument_bit_length",
						fqn, params[0])
				}
			}
		}
	}
}
