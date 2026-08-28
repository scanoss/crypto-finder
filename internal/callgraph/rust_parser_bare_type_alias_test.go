// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// A local `type X = Ccm<..>;` names `Ccm` by its bare imported name, and the
// callee identity has to carry the crate. Before the import-qualification fix
// this produced `Ccm.new` with an empty type segment, which matched no
// contract; `type X = ccm::Ccm<..>;` already worked. Both spellings are pinned
// here so a regression on either fails.
func TestRustBareTypeAliasCarriesItsCrate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `use aes::Aes256;
use ccm::{consts::{U10, U13}, Ccm};
use cbc::Encryptor;
use aes_gcm::aes;
use aes as blk;

type BareCcm = Ccm<Aes256, U10, U13>;
type QualifiedCcm = ccm::Ccm<Aes256, U10, U13>;
type BareCbcEnc = Encryptor<Aes256>;
type QualifiedCbcEnc = cbc::Encryptor<Aes256>;
struct LocalGeneric<T>(T);
type LocalAlias = LocalGeneric<u8>;

fn build(key: &[u8], iv: &[u8]) {
    let _ = BareCcm::new(key.into());
    let _ = QualifiedCcm::new(key.into());
    let _ = BareCbcEnc::new(key.into(), iv.into());
    let _ = QualifiedCbcEnc::new(key.into(), iv.into());
    let _ = LocalAlias::new();
    let _ = blk::Aes256::new(key.into());
    blk::helper(key);
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				got[call.Raw] = method
			}
		}
	}

	want := map[string]string{
		"BareCcm::new":         "ccm.Ccm.new",
		"QualifiedCcm::new":    "ccm.Ccm.new",
		"BareCbcEnc::new":      "cbc.Encryptor.new",
		"QualifiedCbcEnc::new": "cbc.Encryptor.new",
		// An alias whose right-hand side names a generic type this crate
		// declares resolves to that type IN THIS CRATE.
		//
		// The expectation changed with the scoped-callee fix. It used to be
		// "LocalGeneric.new" — the type name sitting in the key's PACKAGE
		// field with an empty type field, on the reasoning that a name in no
		// import map has "no crate to name". But `struct LocalGeneric<T>` is
		// declared in this very fixture, so the crate to name is the local
		// one, and a type in the package field is unqueryable: nothing indexes
		// a type as a package. 290 edges in openssl 0.10.81 and 190 in russh
		// 0.54.6 carried that shape.
		"LocalAlias::new": "app.LocalGeneric.new",
		// A renaming import records a bare target too, but that target is
		// already a real path. The fixture makes the collision real:
		// `use aes_gcm::aes;` maps `aes -> aes_gcm`, and `use aes as blk;`
		// records `blk -> aes`. Without the type-name guard the crate root
		// would be rewritten to `aes_gcm::aes` on both of these.
		"blk::Aes256::new": "aes.Aes256.new",
		"blk::helper":      "aes.helper",
	}
	for raw, wantKey := range want {
		if got[raw] != wantKey {
			t.Errorf("%s -> %q, want %q", raw, got[raw], wantKey)
		}
	}
}
