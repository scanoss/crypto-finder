// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// openssl-sys exposes free functions at its crate root, so the KB is keyed on
// the dot form a single-segment crate emits. The consumer spellings that must
// all reach the same contract are the fully qualified path, the imported bare
// name, and the two renames: `use openssl_sys as ffi;` and the 2015-edition
// `extern crate openssl_sys as ffi;`. Aliasing an FFI crate is the norm rather
// than the exception -- the safe `openssl` crate renames it to `ffi` -- so a
// rename that leaves the local name in the identity produces a key that looks
// like data and matches nothing.
func TestOpenSSLSysContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	dir := t.TempDir()
	src := `extern crate openssl_sys as ffi;
use openssl_sys::{EVP_sha256, RSA_generate_key_ex};

unsafe fn digests() {
    let _a = openssl_sys::EVP_aes_256_gcm();
    let _b = EVP_sha256();
    let _c = ffi::EVP_aes_128_ctr();
}

unsafe fn keys(rsa: *mut ffi::RSA, e: *mut ffi::BIGNUM) {
    let _ = RSA_generate_key_ex(rsa, 2048, e, core::ptr::null_mut());
    let _ = ffi::EC_KEY_new_by_curve_name(415);
}

unsafe fn tls() {
    let m = ffi::TLS_client_method();
    let _ = ffi::SSL_CTX_new(m);
}`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"openssl_sys.EVP_aes_256_gcm":          "factory",
		"openssl_sys.EVP_sha256":               "factory",
		"openssl_sys.EVP_aes_128_ctr":          "factory",
		"openssl_sys.RSA_generate_key_ex":      "operation",
		"openssl_sys.EC_KEY_new_by_curve_name": "factory",
		"openssl_sys.TLS_client_method":        "factory",
		"openssl_sys.SSL_CTX_new":              "factory",
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				role, expected := want[method]
				if !expected {
					continue
				}
				got := kb.ContractsFor(method, len(call.Arguments))
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one openssl-sys contract",
						method, len(call.Arguments), len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "openssl-sys" {
					t.Fatalf("contract for %q = %#v, want openssl-sys %s", method, got[0], role)
				}
				seen[method] = true
			}
		}
	}

	for method := range want {
		if !seen[method] {
			t.Errorf("call identity %q was never produced by the parser", method)
		}
	}
}

// The modulus size is the one argument on this surface that carries a
// cryptographic property, and it is a plain integer rather than the bit length
// of a key buffer. Pin the derivation so a schema change cannot quietly turn it
// into a byte count.
func TestOpenSSLSysRSAKeygenContributesModulusSize(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}
	got := kb.ContractsFor("openssl_sys.RSA_generate_key_ex", 4)
	if len(got) != 1 {
		t.Fatalf("ContractsFor(RSA_generate_key_ex, 4) = %d, want 1", len(got))
	}
	var found bool
	for _, p := range got[0].Parameters {
		if p.Index == nil || *p.Index != 1 {
			continue
		}
		found = true
		if p.Contributes == nil {
			t.Fatalf("argument 1 contributes nothing, want keySize")
		}
		if p.Contributes.Property != "keySize" || p.Contributes.Derivation != "argument_value" {
			t.Fatalf("argument 1 contributes %+v, want keySize from argument_value", *p.Contributes)
		}
	}
	if !found {
		t.Fatalf("no contract entry for argument 1 of RSA_generate_key_ex")
	}
}
