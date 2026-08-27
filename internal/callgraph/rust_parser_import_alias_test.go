// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// parseRustCalleeFQNs returns raw call text -> resolved callee FQN for one source.
func parseRustCalleeFQNs(t *testing.T, src string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	got := map[string]string{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			calls := analysis.Functions[i].Calls
			for j := range calls {
				callee := calls[j].Callee
				fqn, _ := splitMethodArity(&callee)
				got[calls[j].Raw] = fqn
			}
		}
	}
	return got
}

// A renaming import (`use a::b::C as D;`) previously produced an unqualified
// callee identity, because no `use_as_clause` case existed in either the
// top-level or the use-list handler. The block-mode crates force that spelling
// on real consumers: cbc, cfb-mode and ctr all export `Encryptor`/`Decryptor`,
// so a file using two of them must rename at least one. Assert the exact keys —
// a polluted identity resolves to no contract while still looking like data.
func TestRustParser_RenamingImportsResolveExactCalleeKeys(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use cbc::Encryptor as CbcEnc;
use cbc::{Decryptor as CbcDec, Encryptor};
use cfb_mode as cfb;
use ctr::Ctr128BE as AesCtr;

fn build(key: &[u8; 16], iv: &[u8; 16]) {
    let a = CbcEnc::<Aes128>::new(key.into(), iv.into());
    let b = CbcDec::<Aes128>::new(key.into(), iv.into());
    let c = cfb::Encryptor::<Aes128>::new(key.into(), iv.into());
    let d = AesCtr::<Aes128>::new(key.into(), iv.into());
    let e = Encryptor::<Aes128>::new(key.into(), iv.into());
    let f = cbc::Decryptor::<Aes128>::new(key.into(), iv.into());
}`)

	want := map[string]string{
		// Renamed type imports, at the top level and inside a use list.
		"CbcEnc::new": "cbc.Encryptor.new",
		"CbcDec::new": "cbc.Decryptor.new",
		// A renamed module: the alias is substituted, not prefixed.
		"cfb::Encryptor::new": "cfb_mode.Encryptor.new",
		// A renamed type alias from a different crate in the same family.
		"AesCtr::new": "ctr.Ctr128BE.new",
		// Unrenamed spellings must keep resolving exactly as before.
		"Encryptor::new":      "cbc.Encryptor.new",
		"cbc::Decryptor::new": "cbc.Decryptor.new",
	}
	for raw, wantFQN := range want {
		if got[raw] != wantFQN {
			t.Errorf("call %q resolved to %q, want %q", raw, got[raw], wantFQN)
		}
	}
}

// A variable initialized from a turbofish constructor recorded its type with the
// turbofish's trailing "::" still attached ("Encryptor::"), so every later
// method call on it was keyed "<crate>.(Encryptor::).method" and matched no
// contract. Pin the receiver-side keys, including the renamed-import receiver.
func TestRustParser_TurbofishReceiverTypesResolveExactCalleeKeys(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use aes::Aes128;
use cbc::Encryptor;
use cfb_mode::Decryptor as CfbDec;

fn operate(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    let enc = Encryptor::<Aes128>::new(key.into(), iv.into());
    let _ct = enc.encrypt_padded_mut(buf, 16);
    let mut stream = ctr::Ctr128BE::<Aes128>::new(key.into(), iv.into());
    stream.apply_keystream(buf);
    let annotated: cbc::Decryptor<Aes128> = cbc::Decryptor::<Aes128>::new(key.into(), iv.into());
    let _pt = annotated.decrypt_padded_mut(buf);
    let renamed = CfbDec::<Aes128>::new(key.into(), iv.into());
    renamed.decrypt(buf);
}`)

	want := map[string]string{
		"enc.encrypt_padded_mut": "cbc.Encryptor.encrypt_padded_mut",
		"stream.apply_keystream": "ctr.Ctr128BE.apply_keystream",
		"renamed.decrypt":        "cfb_mode.Decryptor.decrypt",
		// An explicit type annotation already worked; it must keep working.
		"annotated.decrypt_padded_mut": "cbc.Decryptor.decrypt_padded_mut",
	}
	for raw, wantFQN := range want {
		if got[raw] != wantFQN {
			t.Errorf("call %q resolved to %q, want %q", raw, got[raw], wantFQN)
		}
	}
}

// The pre-existing non-renaming import forms are what the other Rust KBs are
// keyed on, so pin them here too: this change must be additive.
func TestRustParser_PlainImportFormsUnchanged(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use ring::aead::UnboundKey;
use ring::digest;

fn seal(key: &[u8], data: &[u8]) {
    let imported = UnboundKey::new(&ring::aead::AES_256_GCM, key);
    let qualified = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key);
    let module_ctx = digest::Context::new(&digest::SHA256);
    let free = digest::digest(&digest::SHA256, data);
}`)

	want := map[string]string{
		"UnboundKey::new":             "ring::aead.UnboundKey.new",
		"ring::aead::UnboundKey::new": "ring::aead.UnboundKey.new",
		"digest::Context::new":        "ring::digest.Context.new",
		// A free function keeps the module as the receiver segment; the "::"
		// spelling is restored by the contract lookup, not by the parser.
		"digest::digest": "ring.digest.digest",
	}
	for raw, wantFQN := range want {
		if got[raw] != wantFQN {
			t.Errorf("call %q resolved to %q, want %q", raw, got[raw], wantFQN)
		}
	}
}

// A renamed MODULE must be substituted on the receiver path too, not only on the
// callee path. This shape resolved the constructor correctly while keying every
// later call on the receiver as `cfb.Encryptor.<method>`, leaving the alias in
// the package segment: a key that looks like data and matches nothing.
func TestRustParser_RenamedModuleReceiverResolvesRealPath(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use cfb_mode as cfb;

fn stream(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    let enc = cfb::Encryptor::<Aes128>::new(key.into(), iv.into());
    enc.encrypt(buf);
    let dec = cfb::Decryptor::<Aes128>::new(key.into(), iv.into());
    dec.decrypt(buf);
}`)

	want := map[string]string{
		"cfb::Encryptor::new": "cfb_mode.Encryptor.new",
		"enc.encrypt":         "cfb_mode.Encryptor.encrypt",
		"cfb::Decryptor::new": "cfb_mode.Decryptor.new",
		"dec.decrypt":         "cfb_mode.Decryptor.decrypt",
	}
	for raw, wantFQN := range want {
		if got[raw] != wantFQN {
			t.Errorf("call %q resolved to %q, want %q", raw, got[raw], wantFQN)
		}
	}
}

// `use cbc::{self as c};` renames the module itself. The alias clause carries a
// `self` node rather than an identifier, so the rename was dropped and the local
// name stayed in the identity.
func TestRustParser_SelfRenamingImportResolvesModulePath(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `use cbc::{self as c};

fn decrypt(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    let dec = c::Decryptor::<Aes128>::new(key.into(), iv.into());
    dec.decrypt_padded_mut(buf);
}`)

	want := map[string]string{
		"c::Decryptor::new":      "cbc.Decryptor.new",
		"dec.decrypt_padded_mut": "cbc.Decryptor.decrypt_padded_mut",
	}
	for raw, wantFQN := range want {
		if got[raw] != wantFQN {
			t.Errorf("call %q resolved to %q, want %q", raw, got[raw], wantFQN)
		}
	}
}

// Explicit type arguments in a type ANNOTATION or a PARAMETER type are truncated
// by the same helper as an initializer, which left the turbofish's trailing
// separator on the recorded type (`cbc::Encryptor::`). Both positions are pinned
// because the fix belongs to the shared truncation, not to one caller.
func TestRustParser_TurbofishInDeclaredTypesResolvesExactCalleeKeys(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `fn annotated(buf: &mut [u8]) {
    let enc: cbc::Encryptor::<Aes128> = cbc::Encryptor::new(b"k".into(), b"i".into());
    enc.encrypt_padded_mut(buf, 16);
}

fn parameterized(dec: cbc::Decryptor::<Aes128>, buf: &mut [u8]) {
    dec.decrypt_padded_mut(buf);
}`)

	want := map[string]string{
		"enc.encrypt_padded_mut": "cbc.Encryptor.encrypt_padded_mut",
		"dec.decrypt_padded_mut": "cbc.Decryptor.decrypt_padded_mut",
	}
	for raw, wantFQN := range want {
		if got[raw] != wantFQN {
			t.Errorf("call %q resolved to %q, want %q", raw, got[raw], wantFQN)
		}
	}
}

// The form every block-mode crate's own documentation teaches: a local type
// alias over the mode plus its inner cipher, then a call through that alias.
// Without alias tracking the local name was the identity, so the documented
// idiom produced a detection with no reachability behind it.
func TestRustParser_LocalTypeAliasResolvesToAliasedPath(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

fn roundtrip(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    let enc = Aes128CbcEnc::new(key.into(), iv.into());
    enc.encrypt_padded_mut(buf, 16);
    let dec = Aes128CbcDec::new(key.into(), iv.into());
    dec.decrypt_padded_mut(buf);
    let mut stream = Aes128Ctr64LE::new(key.into(), iv.into());
    stream.apply_keystream(buf);
}`)

	want := map[string]string{
		"Aes128CbcEnc::new":      "cbc.Encryptor.new",
		"enc.encrypt_padded_mut": "cbc.Encryptor.encrypt_padded_mut",
		"Aes128CbcDec::new":      "cbc.Decryptor.new",
		"dec.decrypt_padded_mut": "cbc.Decryptor.decrypt_padded_mut",
		"Aes128Ctr64LE::new":     "ctr.Ctr64LE.new",
		"stream.apply_keystream": "ctr.Ctr64LE.apply_keystream",
	}
	for raw, wantFQN := range want {
		if got[raw] != wantFQN {
			t.Errorf("call %q resolved to %q, want %q", raw, got[raw], wantFQN)
		}
	}
}

// Stripping type arguments also changes what a turbofish on the METHOD records
// as the initializer's type. None of these ever matched a contract, before or
// after, but the behavior is pinned here rather than left implicit: the earlier
// spellings were themselves non-matching paths, and a future change should have
// to state that it is altering them.
func TestRustParser_TurbofishOnMethodRecordsNoContractType(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ expr, want string }{
		{`serde_json::from_str::<Config>(s)`, "serde_json"},
		{`Foo::bar::<T>(y)`, "Foo"},
		{`generic_call::<u8>(buf)`, ""},
	} {
		if got := inferRustTypeFromExpr(tc.expr); got != tc.want {
			t.Errorf("inferRustTypeFromExpr(%q) = %q, want %q", tc.expr, got, tc.want)
		}
	}
}

// The point of resolving a local type alias is that the contracts behind it
// become reachable, so assert the contract lookup and not only the identity.
// This lives with the parser fix because it fails without it.
func TestRustParser_LocalTypeAliasReachesContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	got := parseRustCalleeFQNs(t, `type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;
type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;

fn documented_idiom(key: &[u8; 16], iv: &[u8; 16], buf: &mut [u8]) {
    let enc = Aes128CbcEnc::new(key.into(), iv.into());
    let _ = enc.encrypt_padded_b2b_mut(buf, buf);
    let dec = Aes128CfbDec::new(key.into(), iv.into());
    dec.decrypt_b2b(buf, buf);
    let mut stream = Aes128Ctr64BE::new(key.into(), iv.into());
    stream.apply_keystream(buf);
}`)

	want := map[string]string{
		"Aes128CbcEnc::new":          "cbc.Encryptor.new",
		"enc.encrypt_padded_b2b_mut": "cbc.Encryptor.encrypt_padded_b2b_mut",
		"Aes128CfbDec::new":          "cfb_mode.Decryptor.new",
		"dec.decrypt_b2b":            "cfb_mode.Decryptor.decrypt_b2b",
		"Aes128Ctr64BE::new":         "ctr.Ctr64BE.new",
		"stream.apply_keystream":     "ctr.Ctr64BE.apply_keystream",
	}
	for raw, wantFQN := range want {
		fqn := got[raw]
		if fqn != wantFQN {
			t.Errorf("call %q resolved to %q, want %q", raw, fqn, wantFQN)
			continue
		}
		if len(kb.ContractsFor(fqn, -1)) == 0 {
			t.Errorf("no contract resolved for %q reached through a local type alias", fqn)
		}
	}
}

// `extern crate openssl_sys as ffi;` is the 2015-edition rename. Only the
// `use ... as ...` spelling was resolved, so a call through the extern-crate
// alias kept the local name in the identity — `ffi.EVP_sha256` rather than
// `openssl_sys.EVP_sha256` — and matched no contract. FFI binding crates are
// where this shows, because aliasing them is the norm.
func TestRustParser_ExternCrateRenameResolvesCrateIdentity(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `extern crate openssl_sys as ffi;

unsafe fn digest(rsa: *mut ffi::RSA, e: *mut ffi::BIGNUM) {
    let _md = ffi::EVP_sha256();
    let _ = ffi::RSA_generate_key_ex(rsa, 2048, e, core::ptr::null_mut());
}`)

	want := map[string]string{
		"ffi::EVP_sha256":          "openssl_sys.EVP_sha256",
		"ffi::RSA_generate_key_ex": "openssl_sys.RSA_generate_key_ex",
	}
	for raw, wantFQN := range want {
		if got[raw] != wantFQN {
			t.Errorf("call %q resolved to %q, want %q", raw, got[raw], wantFQN)
		}
	}
}

// The two spellings that must keep behaving as they did: `use ... as ...`
// already resolved, and a plain `extern crate` without a rename has no alias to
// apply and must leave the crate path untouched.
func TestRustParser_ExternCrateWithoutRenameKeepsCratePath(t *testing.T) {
	t.Parallel()

	got := parseRustCalleeFQNs(t, `extern crate openssl_sys;
use openssl_sys as sys;

unsafe fn digest() {
    let _a = openssl_sys::EVP_sha256();
    let _b = sys::EVP_sha384();
}`)

	want := map[string]string{
		"openssl_sys::EVP_sha256": "openssl_sys.EVP_sha256",
		"sys::EVP_sha384":         "openssl_sys.EVP_sha384",
	}
	for raw, wantFQN := range want {
		if got[raw] != wantFQN {
			t.Errorf("call %q resolved to %q, want %q", raw, got[raw], wantFQN)
		}
	}
}
