// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// blakejs joins COMPLETELY, unlike bitcoinjs-lib (5 of 7) and
// @azure/keyvault-keys (0 of n): every export is a module-level function, so a
// consumer's `blake.blake2bInit(32)` emits `blakejs.blake2bInit` -- measured,
// all three streaming symbols resolve to the coordinate.
//
// What the KB adds beyond the api join is the STREAMING CONTEXT. Init returns a
// Blake2bCTX that Update and Final consume, and typing it is what ties three
// statements to one digest rather than three unrelated calls. That is the shape
// consumers actually write: 24 streaming call sites against 6 one-shot across a
// 15-consumer draw.
func TestLoadEmbeddedNodeBlakejs(t *testing.T) {
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
		// The streaming chain, which is the point of this KB.
		{"blakejs.blake2bInit", 1, "blakejs.Blake2bCTX"},
		{"blakejs.blake2bUpdate", 2, "void"},
		{"blakejs.blake2bFinal", 1, "Uint8Array"},

		// THE TWO CONTEXTS ARE DISTINCT TYPES. A Blake2sCTX is not a
		// Blake2bCTX: passing one to the other's Update is a bug the library
		// does not catch, and a KB that merged them would type it as correct.
		{"blakejs.blake2sInit", 1, "blakejs.Blake2sCTX"},
		{"blakejs.blake2sFinal", 1, "Uint8Array"},

		// One-shot and hex forms, at all three arities: (input, key?, outlen?).
		{"blakejs.blake2b", 1, "Uint8Array"},
		{"blakejs.blake2b", 3, "Uint8Array"},
		{"blakejs.blake2bHex", 3, "string"},
		{"blakejs.blake2s", 3, "Uint8Array"},
		{"blakejs.blake2sHex", 1, "string"},
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

	// blake2bInit's outlen is OPTIONAL and blake2sInit's is NOT -- read off
	// index.d.ts, and the reason the two differ at arity 0.
	if got := kb.ContractsFor("blakejs.blake2bInit", 0); len(got) == 0 {
		t.Error("blake2bInit() with no argument is valid and must resolve")
	}
	if got := kb.ContractsFor("blakejs.blake2sInit", 0); len(got) != 0 {
		t.Error("blake2sInit() requires an outlen; arity 0 must resolve to nothing")
	}

	for _, bogus := range []struct {
		method string
		arity  int
	}{
		{"blakejs.blake2b", 4},
		{"blakejs.blake2bFinal", 2},
		{"blakejs.blake2bUpdate", 1},
	} {
		if got := kb.ContractsFor(bogus.method, bogus.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) resolved %d contracts; that arity does not exist", bogus.method, bogus.arity, len(got))
		}
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "blakejs.") {
			n++
		}
	}
	if n != 21 {
		t.Errorf("blakejs contributes %d keys, want 21", n)
	}
}
