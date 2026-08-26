// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The AEAD KBs are keyed on what the Rust parser emits, so a parser identity
// change must fail here rather than leaving the contracts silently unmatched.
// The exact key is asserted, not merely that a call was produced: a wrong key
// looks like data and matches nothing.
//
// `ccm` is the reason this test exists. That crate exposes only
// `Ccm<C, M, N>` and documents its use through an alias the CONSUMER names
// (`pub type Aes256Ccm = Ccm<Aes256, U10, U13>;`), so every call a real
// consumer writes reaches the crate through a local type alias whose
// right-hand side names `Ccm` by its bare imported name.
func TestAeadContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `use aes::{Aes128, Aes256};
use aes_gcm::{aead::{Generate, Key, consts::U13}, Aes128Gcm, Aes256Gcm, AesGcm, KeyInit, Nonce};
use aes_gcm_siv::Aes256GcmSiv;
use ccm::{consts::{U10, U13 as CcmNonce}, Ccm};
use chacha20poly1305::{ChaCha8Poly1305, XChaCha12Poly1305};

pub type Aes256Ccm = Ccm<Aes256, U10, CcmNonce>;
pub type WideNonceGcm = AesGcm<Aes256, U13>;

fn roundtrip(key: &[u8], nonce: &[u8], buf: &mut Vec<u8>, tag: &[u8]) {
    let gcm = Aes256Gcm::new(key.into());
    let _ = gcm.encrypt(nonce.into(), b"m".as_ref());
    let _ = gcm.decrypt(nonce.into(), b"c".as_ref());
    let _ = gcm.encrypt_in_place(nonce.into(), b"", buf);
    let _ = gcm.encrypt_inout_detached(nonce.into(), b"", buf.into());

    let gcm128 = aes_gcm::Aes128Gcm::new_from_slice(key).unwrap();
    let _ = gcm128.decrypt_in_place(nonce.into(), b"", buf);

    let wide = WideNonceGcm::new(key.into());
    let _ = wide.encrypt(nonce.into(), b"m".as_ref());

    let _k = Key::<Aes256Gcm>::generate();
    let _n = Nonce::from_slice(nonce);

    let siv = Aes256GcmSiv::new(key.into());
    let _ = siv.encrypt_in_place_detached(nonce.into(), b"", buf);

    let ccm = Aes256Ccm::new(key.into());
    let _ = ccm.encrypt(nonce.into(), b"m".as_ref());
    let _ = ccm.decrypt_in_place_detached(nonce.into(), b"", buf, tag.into());
    let ccm_turbofish = ccm::Ccm::<Aes128, U10, CcmNonce>::new(key.into());
    let _ = ccm_turbofish.encrypt(nonce.into(), b"m".as_ref());

    let reduced = ChaCha8Poly1305::new(key.into());
    let _ = reduced.encrypt(nonce.into(), b"m".as_ref());
    let xreduced = XChaCha12Poly1305::new(key.into());
    let _ = xreduced.decrypt(nonce.into(), b"c".as_ref());
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
		"aes_gcm.Aes256Gcm.new":                    {"factory", "aes-gcm"},
		"aes_gcm.Aes256Gcm.encrypt":                {"operation", "aes-gcm"},
		"aes_gcm.Aes256Gcm.decrypt":                {"operation", "aes-gcm"},
		"aes_gcm.Aes256Gcm.encrypt_in_place":       {"operation", "aes-gcm"},
		"aes_gcm.Aes256Gcm.encrypt_inout_detached": {"operation", "aes-gcm"},
		"aes_gcm.Aes128Gcm.new_from_slice":         {"factory", "aes-gcm"},
		"aes_gcm.Aes128Gcm.decrypt_in_place":       {"operation", "aes-gcm"},
		"aes_gcm.AesGcm.new":                       {"factory", "aes-gcm"},
		"aes_gcm.AesGcm.encrypt":                   {"operation", "aes-gcm"},
		// The documented spelling imports Key through the re-exported `aead`,
		// which is a different callee identity from the crate-root re-export.
		"aes_gcm::aead.Key.generate":                         {"factory", "aes-gcm"},
		"aes_gcm.Nonce.from_slice":                           {"factory", "aes-gcm"},
		"aes_gcm_siv.Aes256GcmSiv.new":                       {"factory", "aes-gcm-siv"},
		"aes_gcm_siv.Aes256GcmSiv.encrypt_in_place_detached": {"operation", "aes-gcm-siv"},
		"ccm.Ccm.new":                                {"factory", "ccm"},
		"ccm.Ccm.encrypt":                            {"operation", "ccm"},
		"ccm.Ccm.decrypt_in_place_detached":          {"operation", "ccm"},
		"chacha20poly1305.ChaCha8Poly1305.new":       {"factory", "chacha20poly1305"},
		"chacha20poly1305.ChaCha8Poly1305.encrypt":   {"operation", "chacha20poly1305"},
		"chacha20poly1305.XChaCha12Poly1305.new":     {"factory", "chacha20poly1305"},
		"chacha20poly1305.XChaCha12Poly1305.decrypt": {"operation", "chacha20poly1305"},
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, arity := splitMethodArity(&callee)
				expect, ok := want[method]
				if !ok {
					continue
				}
				seen[method] = true
				got := kb.ContractsFor(method, arity)
				if len(got) != 1 {
					t.Errorf("%s: ContractsFor returned %d contracts, want 1", method, len(got))
					continue
				}
				if got[0].Role != expect.role || got[0].SourceLibrary != expect.library {
					t.Errorf("%s: role=%q library=%q, want role=%q library=%q",
						method, got[0].Role, got[0].SourceLibrary, expect.role, expect.library)
				}
			}
		}
	}

	for method := range want {
		if !seen[method] {
			t.Errorf("parser produced no call with key %q", method)
		}
	}
}

// The Rust parser encodes no arity, so ContractsFor falls back to a name-only
// lookup and a loose match hides a wrong declared arity. The export path does
// not: it looks a contract up by the call site's real argument count. This
// table pins the exact-arity lookup for one method of each shape, so a
// contract authored at the wrong arity fails here instead of resolving
// everywhere except where it is used.
func TestAeadContractsResolveAtExactCallSiteArity(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	// `Generate::generate()` takes no arguments (crypto-common 0.2.0
	// src/generate.rs:43); `generate_from_rng(rng)` and
	// `KeyInit::generate_key(rng)` take one (src/generate.rs:17, src/lib.rs:200).
	cases := []struct {
		method string
		arity  int
	}{
		{"aes_gcm::Aes256Gcm.new", 1},
		{"aes_gcm::Aes256Gcm.new_from_slice", 1},
		{"aes_gcm::Aes256Gcm.generate_key", 1},
		{"aes_gcm::Aes256Gcm.encrypt", 2},
		{"aes_gcm::Aes256Gcm.encrypt_in_place", 3},
		{"aes_gcm::Aes256Gcm.encrypt_inout_detached", 3},
		{"aes_gcm::Aes256Gcm.decrypt_in_place_detached", 4},
		{"aes_gcm::Key.generate", 0},
		{"aes_gcm::Key.generate_from_rng", 1},
		{"aes_gcm::Key.from_slice", 1},
		{"aes_gcm::Nonce.generate", 0},
		{"aes_gcm::aead::Key.generate", 0},
		{"aes_gcm::aead::Nonce.generate", 0},
		{"aes_gcm_siv::Aes256GcmSiv.new", 1},
		{"aes_gcm_siv::Key.generate", 0},
		{"aes_gcm_siv::Nonce.from_slice", 1},
		{"ccm::Ccm.new", 1},
		{"ccm::Ccm.generate_key", 1},
		{"ccm::Ccm.encrypt", 2},
		{"ccm::Key.generate", 0},
		{"chacha20poly1305::ChaCha8Poly1305.new", 1},
		{"chacha20poly1305::ChaCha8Poly1305.encrypt", 2},
		{"chacha20poly1305::XChaCha12Poly1305.decrypt_inout_detached", 4},
		{"chacha20poly1305::Key.generate", 0},
		{"chacha20poly1305::XNonce.generate", 0},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s#%d", tc.method, tc.arity), func(t *testing.T) {
			if got := kb.ContractsFor(tc.method, tc.arity); len(got) != 1 {
				t.Fatalf("ContractsFor(%q, %d) = %d contracts, want 1", tc.method, tc.arity, len(got))
			}
		})
	}
}
