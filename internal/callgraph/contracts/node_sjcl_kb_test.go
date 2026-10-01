// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeSJCL(t *testing.T) {
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
		{"sjcl.cipher.aes.<init>", 1, "sjcl.cipher.aes", "factory"},
		{"sjcl.cipher.aes.encrypt", 1, "Array", "operation"},
		{"sjcl.cipher.aes.decrypt", 1, "Array", "operation"},
		{"sjcl.hash.sha256.<init>", 0, "sjcl.hash.sha256", "factory"},
		{"sjcl.hash.sha256.<init>", 1, "sjcl.hash.sha256", "factory"},
		{"sjcl.hash.sha256.update", 1, "sjcl.hash.sha256", "operation"},
		{"sjcl.hash.sha256.finalize", 0, "Array", "operation"},
		{"sjcl.hash.sha256.hash", 1, "Array", "operation"},
		{"sjcl.misc.hmac.<init>", 1, "sjcl.misc.hmac", "factory"},
		{"sjcl.misc.hmac.<init>", 2, "sjcl.misc.hmac", "factory"},
		{"sjcl.misc.hmac.mac", 1, "Array", "operation"},
		{"sjcl.misc.hmac.update", 1, "void", "operation"},
		{"sjcl.misc.hmac.digest", 0, "Array", "operation"},
		// count, length and the prf are optional.
		{"sjcl.misc.pbkdf2", 2, "Array", "operation"},
		{"sjcl.misc.pbkdf2", 5, "Array", "operation"},
		{"sjcl.misc.cachedPbkdf2", 1, "sjcl.CachedKey", "operation"},
		// adata and the tag length are optional on every mode.
		{"sjcl.mode.ccm.encrypt", 3, "Array", "operation"},
		{"sjcl.mode.ccm.decrypt", 5, "Array", "operation"},
		{"sjcl.mode.gcm.encrypt", 5, "Array", "operation"},
		{"sjcl.mode.ocb2.encrypt", 6, "Array", "operation"},
		{"sjcl.encrypt", 2, "string", "operation"},
		{"sjcl.encrypt", 4, "string", "operation"},
		{"sjcl.decrypt", 3, "string", "operation"},
		{"sjcl.random.randomWords", 1, "Array", "operation"},
		{"sjcl.random.randomWords", 2, "Array", "operation"},
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

	// Modules the npm build leaves out, and helpers that produce no key material.
	for _, unwanted := range []string{
		"sjcl.hash.sha512.hash#1",
		"sjcl.hash.sha1.hash#1",
		"sjcl.mode.cbc.encrypt#4",
		"sjcl.misc.hkdf#4",
		"sjcl.misc.scrypt#6",
		"sjcl.ecc.ecdsa.generateKeys#0",
		"sjcl.codec.hex.fromBits#1",
		"sjcl.random.addEntropy#3",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "sjcl", "sjcl.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "sjcl.") {
			n++
		}
	}
	if n != 50 {
		t.Errorf("sjcl contributes %d keys, want 50", n)
	}
}
