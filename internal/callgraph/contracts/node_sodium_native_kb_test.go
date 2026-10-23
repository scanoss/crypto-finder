// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeSodiumNative(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	type want struct {
		method string
		arity  int
		typ    string
		role   string
	}
	for _, w := range []want{
		// Output buffers come first, so the C-style arities apply.
		{"sodium-native.crypto_secretbox_easy", 4, "void", "operation"},
		{"sodium-native.crypto_secretbox_open_easy", 4, "boolean", "operation"},
		{"sodium-native.crypto_aead_xchacha20poly1305_ietf_encrypt", 6, "number", "operation"},
		{"sodium-native.crypto_aead_xchacha20poly1305_ietf_decrypt_detached", 7, "void", "operation"},
		{"sodium-native.crypto_sign_verify_detached", 3, "boolean", "operation"},
		{"sodium-native.crypto_sign_keypair", 2, "void", "factory"},
		{"sodium-native.crypto_generichash_init", 3, "void", "config"},
		{"sodium-native.crypto_sign_ed25519_pk_to_curve25519", 2, "void", "output"},
		{"sodium-native.randombytes_random", 0, "number", "operation"},
		// Optional trailing key or callback.
		{"sodium-native.crypto_generichash", 2, "void", "operation"},
		{"sodium-native.crypto_generichash", 3, "void", "operation"},
		{"sodium-native.crypto_pwhash_str_verify_async", 2, "boolean", "operation"},
		{"sodium-native.crypto_pwhash_str_verify_async", 3, "void", "operation"},
		// 2.x streaming instances.
		{"sodium-native.crypto_hash_sha256_instance", 0, "sodium-native.CryptoHashSha256Wrap", "factory"},
		{"sodium-native.crypto_generichash_instance", 2, "sodium-native.CryptoGenericHashWrap", "factory"},
	} {
		got := kb.ContractsFor(w.method, w.arity)
		if len(got) == 0 {
			t.Errorf("%s#%d resolved nothing", w.method, w.arity)
			continue
		}
		if got[0].Return.Type != w.typ || got[0].Role != w.role {
			t.Errorf("%s#%d = (%q, %q), want (%q, %q)", w.method, w.arity, got[0].Return.Type, got[0].Role, w.typ, w.role)
		}
	}

	// The libsodium-wrappers arity drops the output buffer; it must not resolve here.
	if got := kb.ContractsFor("sodium-native.crypto_secretbox_easy", 3); len(got) != 0 {
		t.Error("crypto_secretbox_easy#3 resolved; sodium-native takes the output buffer first")
	}

	assertLibraryOwnsItsKeys(t, kb, "sodium-native", "sodium-native.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "sodium-native.") {
			n++
		}
	}
	if n != 121 {
		t.Errorf("sodium-native contributes %d keys, want 121", n)
	}
}
