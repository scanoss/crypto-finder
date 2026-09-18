// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// jose is a builder library, and this KB exists to keep a chain resolvable to
// the end. Nothing is signed in one call:
//
//	await new SignJWT(payload).setProtectedHeader({alg: "ES256"}).sign(key)
//
// Every setter returns `this`, and only the LAST call performs cryptography. If
// a setter loses its return type, `.sign()` resolves against nothing and the one
// call that matters goes unattributed -- a failure that raises no error, just a
// quieter report. That is what most of this test asserts.
func TestLoadEmbeddedNodeJose(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	// The eight builders and the three most used free functions in the draw.
	for _, want := range []string{
		"jose.SignJWT.<init>#1", "jose.SignJWT.setProtectedHeader#1", "jose.SignJWT.sign#1",
		"jose.EncryptJWT.<init>#1", "jose.EncryptJWT.setProtectedHeader#1", "jose.EncryptJWT.encrypt#1",
		"jose.CompactSign.<init>#1", "jose.CompactSign.sign#1",
		"jose.FlattenedSign.setProtectedHeader#1", "jose.GeneralSign.addSignature#1",
		"jose.CompactEncrypt.encrypt#1", "jose.FlattenedEncrypt.setProtectedHeader#1",
		"jose.GeneralEncrypt.addRecipient#1",
		"jose.jwtVerify#2", "jose.compactDecrypt#2", "jose.createRemoteJWKSet#1",
		"jose.importPKCS8#2", "jose.generateKeyPair#1",
	} {
		if _, ok := kb.Contracts[want]; !ok {
			t.Errorf("contract %q missing from the embedded Node KB", want)
		}
	}

	// THE LINK THAT CARRIES THE CHAIN. Every setter on every builder must return
	// the builder, at both arities, or the terminal sign/encrypt is orphaned.
	for _, tc := range []struct{ cls, setter string }{
		{"SignJWT", "setProtectedHeader"},
		{"SignJWT", "setExpirationTime"},
		{"SignJWT", "setIssuedAt"},
		{"SignJWT", "setAudience"},
		{"EncryptJWT", "setProtectedHeader"},
		{"EncryptJWT", "setKeyManagementParameters"},
		{"CompactSign", "setProtectedHeader"},
		{"FlattenedSign", "setUnprotectedHeader"},
		{"CompactEncrypt", "setInitializationVector"},
		{"FlattenedEncrypt", "setAdditionalAuthenticatedData"},
		{"GeneralEncrypt", "setSharedUnprotectedHeader"},
		{"UnsecuredJWT", "setExpirationTime"},
	} {
		for _, arity := range []int{1, 2} {
			key := "jose." + tc.cls + "." + tc.setter
			got := kb.ContractsFor(key, arity)
			if len(got) == 0 {
				t.Errorf("%s#%d resolved nothing", key, arity)
				continue
			}
			if got[0].Return.Type != "jose."+tc.cls {
				t.Errorf("%s#%d returns %q, want the builder type %q", key, arity, got[0].Return.Type, "jose."+tc.cls)
			}
		}
	}

	// UnsecuredJWT PERFORMS NO CRYPTOGRAPHY AND IS AN OPERATION ANYWAY. It mints
	// a token with alg none -- no signature, so anyone can forge one. An
	// inventory that quietly dropped it because "nothing was computed" would
	// omit the single most alarming thing this library can do.
	enc := kb.ContractsFor("jose.UnsecuredJWT.encode", 0)
	if len(enc) == 0 {
		t.Fatal("UnsecuredJWT.encode resolved nothing")
	}
	if enc[0].Role != "operation" {
		t.Errorf("UnsecuredJWT.encode role = %q, want \"operation\": an unsigned token is the finding", enc[0].Role)
	}

	// DECODING IS NOT VERIFYING. These read the claims and the header without
	// checking any signature, so they are output. Typing one as an operation
	// would record a verification at a line where none happened.
	for _, m := range []string{"jose.decodeJwt", "jose.decodeProtectedHeader", "jose.UnsecuredJWT.decode"} {
		arity := 1
		got := kb.ContractsFor(m, arity)
		if len(got) == 0 {
			t.Errorf("%s#%d resolved nothing", m, arity)
			continue
		}
		if got[0].Role != "output" {
			t.Errorf("%s role = %q, want \"output\": it decodes without verifying", m, got[0].Role)
		}
	}

	// The real verifications are operations, and they take the optional options
	// argument, so both arities are real.
	for _, m := range []string{"jose.jwtVerify", "jose.compactVerify", "jose.jwtDecrypt", "jose.compactDecrypt"} {
		for _, arity := range []int{2, 3} {
			got := kb.ContractsFor(m, arity)
			if len(got) == 0 {
				t.Errorf("%s#%d resolved nothing", m, arity)
				continue
			}
			if got[0].Role != "operation" {
				t.Errorf("%s#%d role = %q, want \"operation\"", m, arity, got[0].Role)
			}
		}
	}

	// Configuration and error reporting are deliberately uncontracted: they
	// compute nothing and a contract on one would report an asset for a setting.
	for _, unwanted := range []string{
		"jose.customFetch#1", "jose.jwksCache#1",
		"jose.JWSSignatureVerificationFailed.<init>#1",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q computes nothing and must not be declared", unwanted)
		}
	}

	if got := kb.ContractsFor("jose.jwtVerify", 9); len(got) != 0 {
		t.Errorf("ContractsFor(jwtVerify, 9) resolved %d contracts; that arity does not exist", len(got))
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "jose.") {
			n++
		}
	}
	if n != 173 {
		t.Errorf("jose contributes %d keys, want 173", n)
	}
}
