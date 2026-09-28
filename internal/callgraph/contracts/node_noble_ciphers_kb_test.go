// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeNobleCiphers(t *testing.T) {
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
		// The parser keys by the import specifier, so the 2.x `.js` subpath and
		// the bare subpath are both constructors of the same cipher object.
		{"@noble/ciphers/aes.gcm", 2, "@noble/ciphers.Cipher", "factory"},
		{"@noble/ciphers/aes.js.gcm", 2, "@noble/ciphers.Cipher", "factory"},
		{"@noble/ciphers/aes.cbc", 3, "@noble/ciphers.Cipher", "factory"},
		{"@noble/ciphers/chacha.js.xchacha20poly1305", 2, "@noble/ciphers.Cipher", "factory"},
		{"@noble/ciphers/chacha.chacha20_poly1305", 2, "@noble/ciphers.Cipher", "factory"},
		{"@noble/ciphers/salsa.secretbox", 2, "@noble/ciphers.Cipher", "factory"},
		{"@noble/ciphers/aes.aeskw", 1, "@noble/ciphers.Cipher", "factory"},
		{"@noble/ciphers/webcrypto/aes.aes_256_gcm", 2, "@noble/ciphers.Cipher", "factory"},
		{"@noble/ciphers/ff1.FF1", 2, "@noble/ciphers.Cipher", "factory"},
		// The object does the work.
		{"@noble/ciphers.Cipher.encrypt", 1, "Uint8Array", "operation"},
		{"@noble/ciphers.Cipher.decrypt", 2, "Uint8Array", "operation"},
		// Stream ciphers and one-shot CMAC compute in the call itself.
		{"@noble/ciphers/chacha.chacha20", 3, "Uint8Array", "operation"},
		{"@noble/ciphers/aes.js.cmac", 2, "Uint8Array", "operation"},
		{"@noble/ciphers/aes.cmac.create", 1, "@noble/ciphers.Mac", "factory"},
		{"@noble/ciphers.Mac.digest", 0, "Uint8Array", "output"},
		{"@noble/ciphers/aes.rngAesCtrDrbg256", 1, "@noble/ciphers.PRG", "factory"},
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

	// The internal modules and the explicitly unsafe export stay undeclared.
	for key := range kb.Contracts {
		if strings.HasPrefix(key, "@noble/ciphers/_") || strings.Contains(key, ".unsafe.") ||
			strings.Contains(key, ".hchacha#") || strings.Contains(key, ".hsalsa#") {
			t.Errorf("contract %q names an internal or unsafe export", key)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "noble-ciphers", "@noble/ciphers")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "@noble/ciphers") {
			n++
		}
	}
	if n != 178 {
		t.Errorf("noble-ciphers contributes %d keys, want 178", n)
	}
}
