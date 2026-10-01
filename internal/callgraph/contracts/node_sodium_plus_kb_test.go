// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeSodiumPlus(t *testing.T) {
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
		{"sodium-plus.SodiumPlus.auto", 0, "sodium-plus.SodiumPlus", "factory"},
		{"sodium-plus.SodiumPlus.<init>", 1, "sodium-plus.SodiumPlus", "factory"},
		{"sodium-plus.SodiumPlus.crypto_secretbox", 3, "Buffer", "operation"},
		{"sodium-plus.SodiumPlus.crypto_secretbox_keygen", 0, "sodium-plus.CryptographyKey", "operation"},
		{"sodium-plus.SodiumPlus.crypto_box_seal_open", 3, "Buffer", "operation"},
		{"sodium-plus.SodiumPlus.crypto_sign_verify_detached", 3, "boolean", "operation"},
		{"sodium-plus.SodiumPlus.crypto_sign_ed25519_pk_to_curve25519", 1, "sodium-plus.X25519PublicKey", "operation"},
		{"sodium-plus.SodiumPlus.crypto_kx_client_session_keys", 3, "Array", "operation"},
		{"sodium-plus.SodiumPlus.randombytes_buf", 1, "Buffer", "operation"},
		// A keypair is split into its halves.
		{"sodium-plus.SodiumPlus.crypto_box_secretkey", 1, "sodium-plus.X25519SecretKey", "output"},
		{"sodium-plus.SodiumPlus.crypto_sign_publickey", 1, "sodium-plus.Ed25519PublicKey", "output"},
		// Stream states are built, then fed.
		{"sodium-plus.SodiumPlus.crypto_generichash_init", 0, "sodium-plus.GenericHashState", "factory"},
		{"sodium-plus.SodiumPlus.crypto_generichash_init", 2, "sodium-plus.GenericHashState", "factory"},
		{"sodium-plus.SodiumPlus.crypto_secretstream_xchacha20poly1305_init_push", 1, "sodium-plus.SecretStreamState", "factory"},
		// Optional trailing parameters: every accepted arity resolves.
		{"sodium-plus.SodiumPlus.crypto_aead_xchacha20poly1305_ietf_encrypt", 3, "Buffer", "operation"},
		{"sodium-plus.SodiumPlus.crypto_aead_xchacha20poly1305_ietf_encrypt", 4, "Buffer", "operation"},
		{"sodium-plus.SodiumPlus.crypto_pwhash", 5, "sodium-plus.CryptographyKey", "operation"},
		{"sodium-plus.SodiumPlus.crypto_pwhash", 6, "sodium-plus.CryptographyKey", "operation"},
		// Both spellings the 0.x line published.
		{"sodium-plus.SodiumPlus.crypto_box_keypair_from_secretkey_and_publickey", 2, "sodium-plus.CryptographyKey", "operation"},
		{"sodium-plus.SodiumPlus.crypto_box_keypair_from_secretkey_and_secretkey", 2, "sodium-plus.CryptographyKey", "operation"},
		{"sodium-plus.X25519SecretKey.<init>", 1, "sodium-plus.X25519SecretKey", "factory"},
		{"sodium-plus.CryptographyKey.from", 2, "sodium-plus.CryptographyKey", "factory"},
		{"sodium-plus.CryptographyKey.getBuffer", 0, "Buffer", "output"},
		{"sodium-plus.CryptographyKey.slice", 2, "Buffer", "output"},
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

	// Byte helpers and state inspection move or compare data without a key.
	for _, unwanted := range []string{
		"sodium-plus.SodiumPlus.sodium_memcmp#2",
		"sodium-plus.SodiumPlus.sodium_pad#2",
		"sodium-plus.SodiumPlus.sodium_bin2hex#1",
		"sodium-plus.SodiumPlus.crypto_pwhash_str_needs_rehash#3",
		"sodium-plus.SodiumPlus.crypto_secretstream_xchacha20poly1305_rekey#1",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "sodium-plus", "sodium-plus.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "sodium-plus.") {
			n++
		}
	}
	if n != 95 {
		t.Errorf("sodium-plus contributes %d keys, want 95", n)
	}
}
