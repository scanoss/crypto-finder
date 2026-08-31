// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// aws-lc-rs is the safe wrapper and aws-lc-sys the raw FFI beneath it. A
// contract keyed on the wrong one resolves silently and mislabels the crate
// rather than failing, so assert the exact key, arity, owning library, role and
// return type for both.
func TestLoadEmbeddedRustIncludesAwsLcContracts(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		method string
		arity  int
		lib    string
		role   string
		ret    string
	}{
		// Safe API. Free functions in a module, and methods on a type.
		{"aws_lc_rs::digest.digest", 2, "aws-lc-rs", "operation", "aws_lc_rs::digest::Digest"},
		{"aws_lc_rs::hmac.sign", 2, "aws-lc-rs", "operation", "aws_lc_rs::hmac::Tag"},
		{"aws_lc_rs::hmac.verify", 3, "aws-lc-rs", "operation", "core::result::Result"},
		{"aws_lc_rs::aead::UnboundKey.new", 2, "aws-lc-rs", "factory", "core::result::Result"},
		{"aws_lc_rs::aead::LessSafeKey.new", 1, "aws-lc-rs", "factory", "aws_lc_rs::aead::LessSafeKey"},

		// Raw FFI. Free functions at the crate root.
		{"aws_lc_sys.EVP_aead_aes_256_gcm", 0, "aws-lc-sys", "factory", "*const aws_lc_sys::EVP_AEAD"},
		{"aws_lc_sys.EVP_sha256", 0, "aws-lc-sys", "factory", "*const aws_lc_sys::EVP_MD"},
		{"aws_lc_sys.HMAC", 7, "aws-lc-sys", "operation", "*mut u8"},
		{"aws_lc_sys.ECDSA_do_sign", 3, "aws-lc-sys", "operation", "*mut aws_lc_sys::ECDSA_SIG"},
		{"aws_lc_sys.RSA_generate_key_ex", 4, "aws-lc-sys", "factory", "core::ffi::c_int"},
	}

	for _, tc := range tests {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract", tc.method, tc.arity)
			continue
		}
		c := got[0]
		if c.SourceLibrary != tc.lib {
			t.Errorf("%s: library = %q, want %q", tc.method, c.SourceLibrary, tc.lib)
		}
		if c.Role != tc.role {
			t.Errorf("%s: role = %q, want %q", tc.method, c.Role, tc.role)
		}
		if c.Return.Type != tc.ret {
			t.Errorf("%s: return = %q, want %q", tc.method, c.Return.Type, tc.ret)
		}
	}
}

// THE KEY SHAPES DIFFER BY CALLABLE KIND and both must resolve from the FQN the
// parser actually emits. A raw FFI free function at the crate root produces a
// key with ONE dot (`aws_lc_sys.EVP_sha256`), which the Rust key normalisation
// returns unchanged; a free function inside a module produces TWO
// (`aws_lc_rs.digest.digest`), which it rewrites. Authoring either in the wrong
// shape yields a contract that loads, passes a lookup on the authored spelling,
// and still exports "(?, ?)" — indistinguishable from having no contract.
// These are the keys observed in an exported call graph, verbatim.
func TestAwsLcContractsResolveFromEmittedCallSiteKeys(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	tests := []struct {
		callSiteKey string
		arity       int
		wantLib     string
	}{
		{"aws_lc_sys.EVP_aead_aes_256_gcm", 0, "aws-lc-sys"},
		{"aws_lc_sys.EVP_aead_aes_256_gcm", -1, "aws-lc-sys"},
		{"aws_lc_sys.EVP_sha256", 0, "aws-lc-sys"},
		{"aws_lc_rs.digest.digest", 2, "aws-lc-rs"},
		{"aws_lc_rs.digest.digest", -1, "aws-lc-rs"},
		{"aws_lc_rs.hmac.sign", 2, "aws-lc-rs"},
		{"aws_lc_rs::aead.UnboundKey.new", 2, "aws-lc-rs"},
		{"aws_lc_rs::aead.UnboundKey.new", -1, "aws-lc-rs"},
	}

	for _, tc := range tests {
		got := kb.ContractsFor(tc.callSiteKey, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d): no contract for an emitted call-site key", tc.callSiteKey, tc.arity)
			continue
		}
		if got[0].SourceLibrary != tc.wantLib {
			t.Errorf("%s: library = %q, want %q", tc.callSiteKey, got[0].SourceLibrary, tc.wantLib)
		}
	}
}

// The safe crate and the sys crate must stay distinct at the contract layer, so
// one consumer call is never attributable to both. The family plan asks for this
// explicitly: "prove no duplicate attribution through the sys crate".
func TestAwsLcSafeAndSysContractsDoNotCollide(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("rust")
	if err != nil {
		t.Fatalf("LoadEmbedded(rust): %v", err)
	}

	safe := kb.ContractsFor("aws_lc_rs::digest.digest", 2)
	raw := kb.ContractsFor("aws_lc_sys.EVP_sha256", 0)
	if len(safe) == 0 || len(raw) == 0 {
		t.Fatalf("expected both to resolve; safe=%d raw=%d", len(safe), len(raw))
	}
	if safe[0].SourceLibrary == raw[0].SourceLibrary {
		t.Errorf("both resolved to %q: the safe and sys crates collapsed", safe[0].SourceLibrary)
	}

	// aws-lc-sys is a BoringSSL fork sharing symbol names with boring-sys. The
	// contract keys are crate-qualified, so they cannot collide — assert it
	// rather than assume it.
	boring := kb.ContractsFor("boring_sys.EVP_sha256", 0)
	if len(boring) > 0 && boring[0].SourceLibrary == raw[0].SourceLibrary {
		t.Errorf("boring_sys.EVP_sha256 resolved to %q", boring[0].SourceLibrary)
	}
}
