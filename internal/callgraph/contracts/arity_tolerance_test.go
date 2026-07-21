// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

// Package contracts_test covers ecosystem-aware contract lookup fallbacks.
//
// Python lookup is arity-tolerant; C lookup falls back to a bare global symbol.
// Exact matches win, and other ecosystems keep exact method+arity semantics.
// See engram decision #1706 for rationale.
package contracts_test

import (
	"testing"
)

const pythonAESYAML = `
schema_version: "2"
ecosystem: python
library:
  name: pycryptodome-arity-test
contracts:
  - method: Crypto.Cipher.AES.new
    arity: 2
    return:
      type: Crypto.Cipher.AES.AES
      confidence: high
hierarchy:
  Crypto.Cipher.AES.AES:
    - builtins.object
`

const javaYAML = `
schema_version: "2"
ecosystem: java
library:
  name: jdk-arity-test
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy:
  javax.crypto.SecretKey:
    - java.lang.Object
`

const cYAML = `
schema_version: "2"
ecosystem: c
library:
  name: openssl-symbol-lookup-test
contracts:
  - method: EVP_CIPHER_CTX_new
    arity: 0
    return:
      type: EVP_CIPHER_CTX*
      confidence: high
  - method: app.EVP_CIPHER_CTX_new
    arity: 0
    return:
      type: APP_CIPHER_CTX*
      confidence: high
`

func TestContractsForTolerant_CGlobalSymbolIgnoresProjectPackage(t *testing.T) {
	t.Parallel()

	kb := mustLoad(t, cYAML)
	for _, method := range []string{"example/crypto.EVP_CIPHER_CTX_new", "other.EVP_CIPHER_CTX_new"} {
		if got := kb.ContractsForTolerant(method, 0); len(got) != 1 || got[0].Method != "EVP_CIPHER_CTX_new" {
			t.Fatalf("ContractsForTolerant(%q, 0) = %#v, want bare C symbol contract", method, got)
		}
	}
	if got := kb.ContractsForTolerant("app.EVP_CIPHER_CTX_new", 0); len(got) != 1 || got[0].Return.Type != "APP_CIPHER_CTX*" {
		t.Fatalf("exact C contract = %#v, want APP_CIPHER_CTX*", got)
	}
}

// TestContractsForTolerant_Python_ArityMismatchFallsBack asserts that a Python
// KB lookup for arity=3 matches an arity=2 KB entry when no exact match exists.
// This is the core arity-tolerance requirement (decision #1706).
func TestContractsForTolerant_Python_ArityMismatchFallsBack(t *testing.T) {
	t.Parallel()

	kb := mustLoad(t, pythonAESYAML)

	// No exact match for AES.new#3 exists in the KB.
	exact := kb.ContractsFor("Crypto.Cipher.AES.new", 3)
	if len(exact) != 0 {
		t.Fatalf("precondition: expected no exact match for arity 3, got %d", len(exact))
	}

	// Tolerant lookup must find the arity-2 entry.
	got := kb.ContractsForTolerant("Crypto.Cipher.AES.new", 3)
	if len(got) == 0 {
		t.Fatal("ContractsForTolerant: expected arity-2 fallback for Python arity-3 call, got 0 results")
	}
	if got[0].Return.Type != "Crypto.Cipher.AES.AES" {
		t.Errorf("ContractsForTolerant: return type = %q, want %q", got[0].Return.Type, "Crypto.Cipher.AES.AES")
	}
}

// TestContractsForTolerant_Python_ExactArityPreferred asserts that when both an
// exact-arity match and a different-arity entry exist, the exact match is returned.
func TestContractsForTolerant_Python_ExactArityPreferred(t *testing.T) {
	t.Parallel()

	const yaml = `
schema_version: "2"
ecosystem: python
library:
  name: pyca-arity-pref
contracts:
  - method: cryptography.fernet.Fernet.encrypt
    arity: 1
    return:
      type: builtins.bytes
      confidence: high
  - method: cryptography.fernet.Fernet.encrypt_at_time
    arity: 2
    return:
      type: builtins.bytes
      confidence: high
hierarchy:
  builtins.bytes:
    - builtins.object
`
	kb := mustLoad(t, yaml)

	// Exact match exists for arity=1.
	got := kb.ContractsForTolerant("cryptography.fernet.Fernet.encrypt", 1)
	if len(got) == 0 {
		t.Fatal("ContractsForTolerant: expected exact match for arity 1, got 0 results")
	}
	if got[0].Arity != 1 {
		t.Errorf("ContractsForTolerant: returned arity %d, want 1", got[0].Arity)
	}
}

// TestContractsForTolerant_Python_ExactPreferredOverAnyArityFallback asserts that
// when both an exact-arity contract AND a different-arity contract exist for the
// same method, the exact-arity contract is returned (not the fallback).
func TestContractsForTolerant_Python_ExactPreferredOverAnyArityFallback(t *testing.T) {
	t.Parallel()

	const yaml = `
schema_version: "2"
ecosystem: python
library:
  name: pyca-both-arities
contracts:
  - method: cryptography.fernet.Fernet.encrypt
    arity: 1
    return:
      type: builtins.bytes
      confidence: high
  - method: cryptography.fernet.Fernet.encrypt
    arity: 3
    return:
      type: builtins.bytes
      confidence: high
hierarchy:
  builtins.bytes:
    - builtins.object
`
	kb := mustLoad(t, yaml)

	// Lookup for arity=1 must return the arity-1 contract, not the arity-3 one.
	got := kb.ContractsForTolerant("cryptography.fernet.Fernet.encrypt", 1)
	if len(got) == 0 {
		t.Fatal("ContractsForTolerant: expected result for arity=1, got 0")
	}
	if got[0].Arity != 1 {
		t.Errorf("ContractsForTolerant: prefer exact arity: got arity=%d, want 1", got[0].Arity)
	}

	// Lookup for arity=2 (no exact) must fall back — with two candidates (arity 1 and 3),
	// tiebreak is lowest arity (deterministic).
	fallback := kb.ContractsForTolerant("cryptography.fernet.Fernet.encrypt", 2)
	if len(fallback) == 0 {
		t.Fatal("ContractsForTolerant: expected fallback for arity=2, got 0")
	}
	// Tiebreak: lowest arity first — arity=1 must be the chosen candidate.
	if fallback[0].Arity != 1 {
		t.Errorf("ContractsForTolerant: tiebreak (lowest-arity): got arity=%d, want 1", fallback[0].Arity)
	}
}

// TestContractsForTolerant_Java_ArityMismatchDoesNotMatch asserts that Java
// exact-arity behavior is preserved: a Java KB must NOT fall back on arity mismatch.
func TestContractsForTolerant_Java_ArityMismatchDoesNotMatch(t *testing.T) {
	t.Parallel()

	kb := mustLoad(t, javaYAML)

	// Ask for arity=1 but KB only has arity=0. Java must NOT match.
	got := kb.ContractsForTolerant("javax.crypto.KeyGenerator.generateKey", 1)
	if len(got) != 0 {
		t.Fatalf("ContractsForTolerant on Java KB: arity mismatch must NOT match; got %d results", len(got))
	}
}

// TestContractsForTolerant_Python_NameOnlyFallbackReturnsCorrectMetadata asserts
// that the fallback contract carries the correct return type and arity metadata.
func TestContractsForTolerant_Python_NameOnlyFallbackReturnsCorrectMetadata(t *testing.T) {
	t.Parallel()

	kb := mustLoad(t, pythonAESYAML)

	// Call with arity=5 (far from KB arity=2).
	got := kb.ContractsForTolerant("Crypto.Cipher.AES.new", 5)
	if len(got) == 0 {
		t.Fatal("ContractsForTolerant: expected fallback contract, got none")
	}
	c := got[0]
	if c.Method != "Crypto.Cipher.AES.new" {
		t.Errorf("fallback contract method = %q, want %q", c.Method, "Crypto.Cipher.AES.new")
	}
	if c.Return.Type != "Crypto.Cipher.AES.AES" {
		t.Errorf("fallback contract return type = %q, want %q", c.Return.Type, "Crypto.Cipher.AES.AES")
	}
	if c.Return.Confidence != "high" {
		t.Errorf("fallback contract confidence = %q, want %q", c.Return.Confidence, "high")
	}
}
