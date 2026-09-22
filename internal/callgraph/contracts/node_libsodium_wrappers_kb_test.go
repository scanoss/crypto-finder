// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Every entry is a free function on the module namespace. libsodium exposes no
// classes and no chains, so this KB is flat -- there are no constructor entries
// making anything reachable, unlike every other Node KB in this campaign.
func TestLoadEmbeddedNodeLibsodiumWrappers(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	// The functions consumers actually call, counted across a 16-consumer draw:
	// secretbox 22 call sites, the xchacha AEAD pair 19, secretstream 16, the
	// Ed25519-to-Curve25519 conversions 13, scalarmult 6.
	for _, want := range []string{
		"libsodium-wrappers.crypto_secretbox_easy#3",
		"libsodium-wrappers.crypto_secretbox_open_easy#3",
		"libsodium-wrappers.crypto_aead_xchacha20poly1305_ietf_encrypt#2",
		"libsodium-wrappers.crypto_sign_detached#2",
		"libsodium-wrappers.crypto_sign_verify_detached#3",
		"libsodium-wrappers.crypto_scalarmult#2",
		"libsodium-wrappers.crypto_pwhash#6",
		"libsodium-wrappers.crypto_generichash#2",
		"libsodium-wrappers.crypto_sign_ed25519_pk_to_curve25519#1",
	} {
		if _, ok := kb.Contracts[want]; !ok {
			t.Errorf("contract %q missing from the embedded Node KB", want)
		}
	}

	// ARITIES COME FROM THE WRAPPER, NOT FROM THE C API. The JavaScript wrapper
	// drops the output-buffer and length arguments the C functions take, so
	// crypto_secretbox_easy is three arguments here against five in C.
	// Declaring the C arities would type calls no consumer can write.
	if got := kb.ContractsFor("libsodium-wrappers.crypto_secretbox_easy", 5); len(got) != 0 {
		t.Error("crypto_secretbox_easy#5 resolved; that is the C arity, not the wrapper's")
	}
	if got := kb.ContractsFor("libsodium-wrappers.crypto_secretbox_easy", 3); len(got) == 0 {
		t.Error("crypto_secretbox_easy#3 resolved nothing; that is the wrapper's arity")
	}

	// NO ENTRY NAMES AN ALGORITHM and none needs to: the algorithm is in the
	// function name and no parameter can change it. If a key ever carries one,
	// this KB has started duplicating what the rules read.
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "libsodium-wrappers.") &&
			(strings.Contains(k, "XSalsa") || strings.Contains(k, "Ed25519.") || strings.Contains(k, "BLAKE")) {
			t.Errorf("key %q names an algorithm; libsodium carries it in the function name", k)
		}
	}

	// verify returns a boolean and is an operation; the Ed25519-to-Curve25519
	// conversions hand back key material and are output.
	if got := kb.ContractsFor("libsodium-wrappers.crypto_sign_verify_detached", 3); len(got) == 0 || got[0].Role != "operation" {
		t.Error("crypto_sign_verify_detached must be an operation")
	}
	for _, m := range []string{
		"libsodium-wrappers.crypto_sign_ed25519_pk_to_curve25519",
		"libsodium-wrappers.crypto_sign_ed25519_sk_to_curve25519",
	} {
		got := kb.ContractsFor(m, 1)
		if len(got) == 0 {
			t.Errorf("%s resolved nothing", m)
			continue
		}
		if got[0].Role != "output" {
			t.Errorf("%s role = %q, want \"output\": it converts a key that already exists", m, got[0].Role)
		}
	}

	// Size constants and encoding helpers report and convert; they compute
	// nothing and must not be declared.
	for _, unwanted := range []string{
		"libsodium-wrappers.crypto_secretbox_keybytes#0",
		"libsodium-wrappers.from_base64#1",
		"libsodium-wrappers.to_hex#1",
		"libsodium-wrappers.ready#0",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q reports or converts and must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "libsodium-wrappers", "libsodium-wrappers.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "libsodium-wrappers.") {
			n++
		}
	}
	if n != 76 {
		t.Errorf("libsodium-wrappers contributes %d keys, want 76", n)
	}
}
