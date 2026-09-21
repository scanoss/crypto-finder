// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// THIS IS THE FIRST NODE FAMILY WHOSE KB HAS REAL WORK TO DO, and the first
// where the join is measurably PARTIAL. Measured on a consumer exercising every
// shape, with this KB present:
//
//	bitcoin.crypto.hash160(x)      ->  bitcoinjs-lib.crypto.hash160     JOIN
//	bitcoin.crypto.taggedHash(..)  ->  bitcoinjs-lib.crypto.taggedHash  JOIN
//	bitcoin.initEccLib(ecc)        ->  bitcoinjs-lib.initEccLib         JOIN
//	bitcoin.toXOnly(pub)           ->  bitcoinjs-lib.toXOnly            JOIN
//	bitcoin.ECPair.fromWIF(wif)    ->  bitcoinjs-lib.ECPair.fromWIF     JOIN
//	psbt.signInput(0, keyPair)     ->  <consumer module>.signInput      no
//	tx.hashForWitnessV1(..)        ->  <consumer module>.hashForWitnessV1  no
//
// Five of seven. Everything reached through the imported binding resolves to
// the coordinate; everything called on an INSTANCE does not, because a
// contract's return type is not propagated to a variable receiver. The Psbt and
// Transaction entries below are correct and inert: the day receiver typing
// lands they join with no further work, and until then they are what keeps
// `12-api-contract-join.sh` from reporting every rule's api as unjoinable.
func TestLoadEmbeddedNodeBitcoinjsLib(t *testing.T) {
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
		// The five that join today.
		{"bitcoinjs-lib.crypto.hash160", 1, "Uint8Array"},
		{"bitcoinjs-lib.crypto.hash256", 1, "Uint8Array"},
		{"bitcoinjs-lib.crypto.taggedHash", 2, "Uint8Array"},
		{"bitcoinjs-lib.initEccLib", 1, "void"},
		{"bitcoinjs-lib.toXOnly", 1, "Uint8Array"},
		{"bitcoinjs-lib.ECPair.fromWIF", 2, "bitcoinjs-lib.ECPair"},

		// THE CHAINABLE METHODS RETURN `this`, read off the .d.ts. Typing the
		// constructor and the builders is what would keep a whole build-sign-
		// finalize-extract sequence attributable rather than only its first call.
		{"bitcoinjs-lib.Psbt.<init>", 1, "bitcoinjs-lib.Psbt"},
		{"bitcoinjs-lib.Psbt.fromHex", 1, "bitcoinjs-lib.Psbt"},
		{"bitcoinjs-lib.Psbt.signInput", 2, "bitcoinjs-lib.Psbt"},
		{"bitcoinjs-lib.Psbt.signTaprootInput", 2, "bitcoinjs-lib.Psbt"},
		{"bitcoinjs-lib.Psbt.finalizeAllInputs", 0, "bitcoinjs-lib.Psbt"},

		// THE ASYNC TWINS RETURN Promise<void>, NOT the Psbt: `await
		// psbt.signInputAsync(0, k)` cannot be chained, and declaring it as a
		// Psbt would type a variable as something the runtime never produces.
		{"bitcoinjs-lib.Psbt.signInputAsync", 2, "void"},

		// extractTransaction is the exit from the Psbt type and what makes the
		// sighash methods reachable at all.
		{"bitcoinjs-lib.Psbt.extractTransaction", 0, "bitcoinjs-lib.Transaction"},
		{"bitcoinjs-lib.Transaction.hashForWitnessV0", 4, "Uint8Array"},
		{"bitcoinjs-lib.Transaction.hashForWitnessV1", 4, "Uint8Array"},
		{"bitcoinjs-lib.Psbt.validateSignaturesOfInput", 2, "boolean"},
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

	// Arities the library does not accept must resolve to nothing.
	for _, bogus := range []struct {
		method string
		arity  int
	}{
		{"bitcoinjs-lib.Psbt.signInput", 0},
		{"bitcoinjs-lib.crypto.hash160", 2},
		{"bitcoinjs-lib.Transaction.hashForSignature", 1},
		{"bitcoinjs-lib.initEccLib", 0},
	} {
		if got := kb.ContractsFor(bogus.method, bogus.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) resolved %d contracts; that arity does not exist", bogus.method, bogus.arity, len(got))
		}
	}

	// ECPair MOVED OUT in 6.0.0 and is the separate `ecpair` package now -- a
	// different coordinate. It is declared here because the deployed corpus
	// still pins 5.x, where it genuinely lived; it must never appear under the
	// standalone package's name.
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "ecpair.") {
			t.Errorf("key %q belongs to the standalone `ecpair` package, which is not this family", k)
		}
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "bitcoinjs-lib.") {
			n++
		}
	}
	if n != 51 {
		t.Errorf("bitcoinjs-lib contributes %d keys, want 51", n)
	}
}
