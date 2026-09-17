// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The one thing this KB exists to record is that Keccak and SHA-3 are not the
// same algorithm. They share a permutation and differ in one padding byte, so
// Keccak-256 and SHA3-256 produce different digests for the same input. A single
// shared Hasher type would have been shorter and would have let an incremental
// chain that began at keccak256 be read as a SHA3-256 three calls later.
func TestLoadEmbeddedNodeJsSha3(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	for _, want := range []string{
		"js-sha3.sha3_256#1", "js-sha3.sha3_512#1",
		"js-sha3.keccak256#1", "js-sha3.keccak_256#1",
		"js-sha3.shake128#2", "js-sha3.cshake128#4",
		"js-sha3.kmac128#3", "js-sha3.kmac_256#3",
		"js-sha3.Keccak256.update#1", "js-sha3.Sha3_256.update#1",
	} {
		if _, ok := kb.Contracts[want]; !ok {
			t.Errorf("contract %q missing from the embedded Node KB", want)
		}
	}

	// KECCAK AND SHA-3 ARE DIFFERENT TYPES. If this ever collapses, an inventory
	// stops being able to tell a reader migrating off Keccak whether they are done.
	for _, tc := range []struct{ factory, want string }{
		{"js-sha3.sha3_224.create", "js-sha3.Sha3_224"},
		{"js-sha3.sha3_256.create", "js-sha3.Sha3_256"},
		{"js-sha3.sha3_512.create", "js-sha3.Sha3_512"},
		{"js-sha3.keccak_256.create", "js-sha3.Keccak256"},
		{"js-sha3.keccak_512.create", "js-sha3.Keccak512"},
	} {
		got := kb.ContractsFor(tc.factory, 0)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, 0) resolved nothing", tc.factory)
			continue
		}
		if got[0].Return.Type != tc.want {
			t.Errorf("%s returns %q, want %q", tc.factory, got[0].Return.Type, tc.want)
		}
	}
	if kb.ContractsFor("js-sha3.sha3_256.create", 0)[0].Return.Type ==
		kb.ContractsFor("js-sha3.keccak_256.create", 0)[0].Return.Type {
		t.Error("SHA3-256 and Keccak-256 resolve to the same type; they are different algorithms")
	}

	// BOTH EXPORT SPELLINGS ARE ONE ALGORITHM. keccak256 and keccak_256 must
	// reach the same type, or the same code would inventory as two things.
	if a, b := kb.ContractsFor("js-sha3.keccak256.create", 0), kb.ContractsFor("js-sha3.keccak_256.create", 0); len(a) == 0 || len(b) == 0 {
		t.Error("one of the two keccak256 spellings resolved nothing")
	} else if a[0].Return.Type != b[0].Return.Type {
		t.Errorf("keccak256 gives %q and keccak_256 gives %q; they are the same algorithm", a[0].Return.Type, b[0].Return.Type)
	}

	// The XOFs take the output length as an argument, so their arities differ
	// from every fixed-size digest above. That difference is the point: a chain
	// that started at a SHAKE must not read as a fixed digest.
	if got := kb.ContractsFor("js-sha3.shake128", 1); len(got) != 0 {
		t.Error("shake128 at arity 1 resolved; the output length is not optional")
	}
	if got := kb.ContractsFor("js-sha3.shake128", 2); len(got) == 0 {
		t.Error("shake128(message, bits) resolved nothing")
	}

	// KMAC is the one keyed construction and is typed apart from every digest.
	k := kb.ContractsFor("js-sha3.kmac128.create", 2)
	if len(k) == 0 {
		t.Fatal("kmac128.create resolved nothing")
	}
	if k[0].Return.Type != "js-sha3.Kmac128" {
		t.Errorf("kmac128.create returns %q, want js-sha3.Kmac128", k[0].Return.Type)
	}

	if _, ok := kb.Contracts["js-sha3.Sha3_256.toString#0"]; ok {
		t.Error("toString is an alias of hex and must not be declared")
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "js-sha3.") {
			n++
		}
	}
	if n != 174 {
		t.Errorf("js-sha3 contributes %d keys, want 174", n)
	}
}
