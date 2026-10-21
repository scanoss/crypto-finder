// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeNobleHashes(t *testing.T) {
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
		// The hash digests in one call and builds the incremental hasher, under
		// the 0.4 `lib/`, the 1.x bare and the 2.x `.js` specifiers.
		{"@noble/hashes/sha2.js.sha256", 1, "Uint8Array", "operation"},
		{"@noble/hashes/sha2.js.sha256.create", 0, "@noble/hashes.Hash", "factory"},
		{"@noble/hashes/sha256.sha256.create", 0, "@noble/hashes.Hash", "factory"},
		{"@noble/hashes/lib/sha3.keccak_256", 1, "Uint8Array", "operation"},
		{"@noble/hashes/blake2b.blake2b", 2, "Uint8Array", "operation"},
		{"@noble/hashes/legacy.js.md5.create", 0, "@noble/hashes.Hash", "factory"},
		{"@noble/hashes/hmac.hmac", 3, "Uint8Array", "operation"},
		{"@noble/hashes/hmac.js.hmac.create", 2, "@noble/hashes.Hash", "factory"},
		{"@noble/hashes/sha3-addons.kmac256.create", 1, "@noble/hashes.Hash", "factory"},
		{"@noble/hashes/hkdf.js.expand", 4, "Uint8Array", "operation"},
		{"@noble/hashes/lib/hkdf.hkdf_extract", 3, "Uint8Array", "operation"},
		{"@noble/hashes/pbkdf2.js.pbkdf2Async", 4, "Uint8Array", "operation"},
		{"@noble/hashes/argon2.js.argon2id", 3, "Uint8Array", "operation"},
		{"@noble/hashes/eskdf.js.eskdf", 2, "@noble/hashes.ESKDF", "factory"},
		{"@noble/hashes/webcrypto.js.pbkdf2", 4, "Uint8Array", "operation"},
		// The object does the incremental work.
		{"@noble/hashes.Hash.update", 1, "@noble/hashes.Hash", "operation"},
		{"@noble/hashes.Hash.digest", 0, "Uint8Array", "output"},
		{"@noble/hashes.Hash.xof", 1, "Uint8Array", "output"},
		{"@noble/hashes.ESKDF.deriveChildKey", 2, "Uint8Array", "operation"},
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

	// Internals and the byte helpers stay undeclared.
	for key := range kb.Contracts {
		if strings.HasPrefix(key, "@noble/hashes/_") || strings.HasPrefix(key, "@noble/hashes/utils") {
			t.Errorf("contract %q names an internal or helper export", key)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "noble-hashes", "@noble/hashes")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "@noble/hashes") {
			n++
		}
	}
	if n != 376 {
		t.Errorf("noble-hashes contributes %d keys, want 376", n)
	}
}
