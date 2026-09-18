// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Two entries. The module export is the function, and what separates the two
// declarations is whether an options object is present -- `{ private: true }`
// is what turns a public-key conversion into a private key being serialized.
func TestLoadEmbeddedNodeJwkToPem(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	// BOTH ARITIES ARE REAL AND BOTH ARE OUTPUT. This library computes no
	// cryptography: it re-encodes a key that already exists. Declaring either
	// as an operation would record a cryptographic operation for a format
	// conversion.
	for _, arity := range []int{1, 2} {
		got := kb.ContractsFor("jwk-to-pem", arity)
		if len(got) == 0 {
			t.Errorf("jwk-to-pem#%d resolved nothing", arity)
			continue
		}
		if got[0].Role != "output" {
			t.Errorf("jwk-to-pem#%d role = %q, want \"output\": it converts a format, it computes nothing", arity, got[0].Role)
		}
		if got[0].Return.Type != "jwk-to-pem.PEM" {
			t.Errorf("jwk-to-pem#%d returns %q, want jwk-to-pem.PEM", arity, got[0].Return.Type)
		}
	}

	// ONE PEM TYPE, NOT ONE PER CURVE. kty and crv live inside a JWK fetched at
	// runtime -- every measured call site passes a variable -- so a per-curve
	// type would be inventing what it cannot see.
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "jwk-to-pem.") && (strings.Contains(k, "P-256") || strings.Contains(k, "RSA")) {
			t.Errorf("key %q names an algorithm; jwk-to-pem cannot see one at the call site", k)
		}
	}

	if got := kb.ContractsFor("jwk-to-pem", 3); len(got) != 0 {
		t.Error("jwk-to-pem#3 resolved; the function takes a JWK and an optional options object")
	}

	n := 0
	for k := range kb.Contracts {
		if k == "jwk-to-pem#1" || k == "jwk-to-pem#2" || strings.HasPrefix(k, "jwk-to-pem.") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("jwk-to-pem contributes %d keys, want 2", n)
	}
}
