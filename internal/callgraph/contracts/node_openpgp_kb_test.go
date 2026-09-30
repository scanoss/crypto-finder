// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeOpenPGP(t *testing.T) {
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
		{"openpgp.encrypt", 1, "string", "operation"},
		{"openpgp.decrypt", 1, "openpgp.DecryptResult", "operation"},
		{"openpgp.verify", 1, "openpgp.VerifyResult", "operation"},
		{"openpgp.generateKey", 1, "openpgp.GeneratedKeys", "operation"},
		{"openpgp.decryptKey", 1, "openpgp.PrivateKey", "operation"},
		{"openpgp/lightweight.sign", 1, "string", "operation"},
		// Parsing decodes and verifies nothing: a factory, never an operation.
		{"openpgp.readKey", 1, "openpgp.Key", "factory"},
		{"openpgp.readMessage", 1, "openpgp.Message", "factory"},
		{"openpgp.readSignature", 1, "openpgp.Signature", "factory"},
		{"openpgp/lightweight.createMessage", 1, "openpgp.Message", "factory"},
		// Key accessors, on both key types the functions return.
		{"openpgp.Key.getFingerprint", 0, "string", "output"},
		{"openpgp.PrivateKey.getFingerprint", 0, "string", "output"},
		{"openpgp.PrivateKey.getExpirationTime", 2, "Date", "output"},
		{"openpgp.PrivateKey.isDecrypted", 0, "boolean", "output"},
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

	// No parser may be declared an operation: that would report a verification
	// where the library performs none.
	for key, cs := range kb.Contracts {
		if (strings.Contains(key, ".read") || strings.Contains(key, ".create")) && strings.HasPrefix(key, "openpgp") {
			for _, c := range cs {
				if c.Role == "operation" {
					t.Errorf("%s is a parser and must not be an operation", key)
				}
			}
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "openpgp", "openpgp")
}
