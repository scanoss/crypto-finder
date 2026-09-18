// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// THE FACTORIES RETURN FUNCTIONS, and that is the whole shape of this library:
//
//	const sign  = createSigner({ key, algorithm: 'RS256' });
//	const token = sign(payload);
//
// `createSigner` does not sign -- it returns the function that will. Typing that
// return is what connects the algorithm chosen at configuration time to the call
// that actually produces a token, which in real code is somewhere else entirely.
func TestLoadEmbeddedNodeFastJwt(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	for _, tc := range []struct {
		method string
		arity  int
		want   string
	}{
		{"fast-jwt.createSigner", 1, "fast-jwt.Signer"},
		{"fast-jwt.createVerifier", 1, "fast-jwt.Verifier"},
		{"fast-jwt.createDecoder", 1, "fast-jwt.Decoder"},

		// Both factories are callable with no options at all.
		{"fast-jwt.createSigner", 0, "fast-jwt.Signer"},
		{"fast-jwt.createVerifier", 0, "fast-jwt.Verifier"},

		// The returned functions.
		{"fast-jwt.Signer", 1, "string"},
		{"fast-jwt.Verifier", 1, "object"},
		{"fast-jwt.Decoder", 1, "object"},
	} {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d) resolved nothing", tc.method, tc.arity)
			continue
		}
		if got[0].Return.Type != tc.want {
			t.Errorf("ContractsFor(%q, %d) returns %q, want %q", tc.method, tc.arity, got[0].Return.Type, tc.want)
		}
	}

	// A DECODER PERFORMS NO CRYPTOGRAPHY. It splits the token and base64-decodes
	// the claims WITHOUT checking the signature, so it is declared `output` and
	// never `operation`: an inventory must not read a decode as a verification,
	// and that difference is the entire security boundary of a JWT.
	dec := kb.ContractsFor("fast-jwt.Decoder", 1)
	if len(dec) == 0 {
		t.Fatal("the decoder is missing")
	}
	if got := dec[0].Role; got != "output" {
		t.Errorf("decoder role = %q, want output: decoding is not verification", got)
	}
	ver := kb.ContractsFor("fast-jwt.Verifier", 1)
	if len(ver) == 0 {
		t.Fatal("the verifier is missing")
	}
	if got := ver[0].Role; got != "operation" {
		t.Errorf("verifier role = %q, want operation", got)
	}

	// The crowded JWT ecosystem: jsonwebtoken and jose sign the same JWA
	// algorithms with the same identifiers at their own coordinates. What has to
	// hold is that each keeps to its own, not that the others are absent, since
	// LoadEmbedded merges every library in the ecosystem.
	assertLibraryOwnsPrefix(t, kb, "fast-jwt", "fast-jwt.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "fast-jwt.") {
			n++
		}
	}
	if n != 9 {
		t.Errorf("fast-jwt contributes %d keys, want 9", n)
	}
}
