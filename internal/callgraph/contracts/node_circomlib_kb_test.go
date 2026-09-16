// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// circomlib joins completely: every entry is a module-level function reached
// through the index re-export, so a consumer's `circomlib.poseidon([a,b])`
// emits `circomlib.poseidon` -- measured, all three probe symbols resolve to
// the coordinate. Same shape as blakejs, and unlike the client-instance
// families whose KBs cannot join today.
//
// THE VERSION RANGE IS BOUNDED AT 2.0.0 ON PURPOSE. circomlib 0.x ships this
// JavaScript API; 2.x ships only .circom templates and the JavaScript moved to
// the separate `circomlibjs` package -- a different coordinate. Declaring these
// methods unbounded would claim 2.x consumers for an API their installed
// version does not have.
func TestLoadEmbeddedNodeCircomlib(t *testing.T) {
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
		// The three measured to join.
		{"circomlib.poseidon", 1, "bigint"},
		{"circomlib.eddsa.prv2pub", 1, "object"},
		{"circomlib.eddsa.signPoseidon", 2, "object"},

		// FOUR SIGNING VARIANTS, ONE PER HASH. The hash is what the verifier
		// circuit must reproduce, so a consumer switching variants changes what
		// its circuit computes -- they are not interchangeable.
		{"circomlib.eddsa.sign", 2, "object"},
		{"circomlib.eddsa.signMiMC", 2, "object"},
		{"circomlib.eddsa.signMiMCSponge", 2, "object"},
		{"circomlib.eddsa.verifyPoseidon", 3, "boolean"},

		// The ZK-native hashes, each under its own module namespace. A free
		// receiver here would report three different algorithms under one name.
		{"circomlib.mimc7.hash", 2, "bigint"},
		{"circomlib.mimcsponge.multiHash", 2, "bigint"},
		{"circomlib.pedersenHash.hash", 1, "Uint8Array"},

		// BabyJubjub arithmetic.
		{"circomlib.babyJub.mulPointEscalar", 2, "object"},
		{"circomlib.babyJub.addPoint", 2, "object"},
		{"circomlib.babyJub.inCurve", 1, "boolean"},
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

	for _, bogus := range []struct {
		method string
		arity  int
	}{
		{"circomlib.poseidon", 3},
		{"circomlib.eddsa.prv2pub", 2},
		{"circomlib.babyJub.addPoint", 1},
	} {
		if got := kb.ContractsFor(bogus.method, bogus.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) resolved %d contracts; that arity does not exist", bogus.method, bogus.arity, len(got))
		}
	}

	// `circomlibjs` is where this API lives from 2.0.0 on, at its own
	// coordinate. It must never be keyed under this one.
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "circomlibjs.") {
			t.Errorf("key %q belongs to the circomlibjs package, not to circomlib", k)
		}
	}

	// The Sparse Merkle Tree is deliberately absent: its node hashing is
	// delegated to Poseidon or MiMC, which are contracted at their own call
	// sites, and typing the tree would double-count one operation.
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "circomlib.smt") || strings.HasPrefix(k, "circomlib.SMT") {
			t.Errorf("key %q types the SMT, which would double-count its delegated hash", k)
		}
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "circomlib.") {
			n++
		}
	}
	if n != 24 {
		t.Errorf("circomlib contributes %d keys, want 24", n)
	}
}
