// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeWebCrypto(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	type want struct {
		method   string
		arity    int
		typ      string
		role     string
		property string
	}
	for _, w := range []want{
		{"SubtleCrypto.digest", 2, "ArrayBuffer", "operation", "algorithm"},
		{"SubtleCrypto.encrypt", 3, "ArrayBuffer", "operation", "plaintext"},
		{"SubtleCrypto.decrypt", 3, "ArrayBuffer", "operation", "ciphertext"},
		{"SubtleCrypto.sign", 3, "ArrayBuffer", "operation", "keyMaterial"},
		{"SubtleCrypto.verify", 4, "boolean", "operation", "signature"},
		{"SubtleCrypto.generateKey", 3, "CryptoKey", "factory", "algorithm"},
		{"SubtleCrypto.importKey", 5, "CryptoKey", "factory", "algorithm"},
		{"SubtleCrypto.exportKey", 2, "ArrayBuffer", "output", "keyMaterial"},
		{"SubtleCrypto.deriveKey", 5, "CryptoKey", "factory", "keyType"},
		{"SubtleCrypto.deriveBits", 3, "ArrayBuffer", "operation", "outputLength"},
		{"SubtleCrypto.deriveBits", 2, "ArrayBuffer", "operation", "algorithm"},
		{"SubtleCrypto.wrapKey", 4, "ArrayBuffer", "output", "algorithm"},
		{"SubtleCrypto.unwrapKey", 7, "CryptoKey", "factory", "keyType"},
		{"Crypto.getRandomValues", 1, "ArrayBufferView", "operation", "output"},
	} {
		got := kb.ContractsFor(w.method, w.arity)
		if len(got) != 1 || got[0].SourceLibrary != "webcrypto" {
			t.Errorf("%s#%d = %#v, want one webcrypto contract", w.method, w.arity, got)
			continue
		}
		if got[0].Return.Type != w.typ || got[0].Role != w.role {
			t.Errorf("%s#%d = (%q, %q), want (%q, %q)", w.method, w.arity, got[0].Return.Type, got[0].Role, w.typ, w.role)
		}
		found := false
		for _, p := range got[0].Parameters {
			if p.Contributes != nil && p.Contributes.Property == w.property {
				found = true
			}
		}
		if !found {
			t.Errorf("%s#%d parameters = %#v, want a contribution for %q", w.method, w.arity, got[0].Parameters, w.property)
		}
	}

	// Every webcrypto key names one of the two WebIDL interfaces, so the
	// parser's spelling-independent callee lands on it.
	n := 0
	for key, list := range kb.Contracts {
		for _, c := range list {
			if c.SourceLibrary != "webcrypto" {
				continue
			}
			n++
			if !strings.HasPrefix(key, "SubtleCrypto.") && !strings.HasPrefix(key, "Crypto.") {
				t.Errorf("webcrypto contract %q is keyed off its interface", key)
			}
		}
	}
	if n != 14 {
		t.Errorf("webcrypto contracts = %d, want 14", n)
	}

	if got := kb.ContractsFor("Crypto.randomUUID", 0); len(got) != 0 {
		t.Errorf("Crypto.randomUUID = %#v, want none: no algorithm is selected", got)
	}
}
