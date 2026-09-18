// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// jws is a thin layer over jwa, and this KB types the three free functions and
// the two streaming constructors. The interesting part is which of them is not
// a cryptographic operation.
func TestLoadEmbeddedNodeJws(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	for _, want := range []string{
		"jws.sign#1", "jws.verify#2", "jws.verify#3",
		"jws.decode#1", "jws.decode#2",
		"jws.createSign#1", "jws.createVerify#1",
	} {
		if _, ok := kb.Contracts[want]; !ok {
			t.Errorf("contract %q missing from the embedded Node KB", want)
		}
	}

	// DECODE IS NOT VERIFY, and here it is not a marginal call: across sixteen
	// published consumers, sign has 8 call sites, verify 7 and decode 7. It
	// splits the token and base64-decodes it, checking no signature.
	for _, arity := range []int{1, 2} {
		got := kb.ContractsFor("jws.decode", arity)
		if len(got) == 0 {
			t.Errorf("jws.decode#%d resolved nothing", arity)
			continue
		}
		if got[0].Role != "output" {
			t.Errorf("jws.decode#%d role = %q, want \"output\": it decodes without verifying", arity, got[0].Role)
		}
	}

	for _, m := range []string{"jws.sign", "jws.verify"} {
		arity := 1
		if m == "jws.verify" {
			arity = 3
		}
		got := kb.ContractsFor(m, arity)
		if len(got) == 0 {
			t.Errorf("%s#%d resolved nothing", m, arity)
			continue
		}
		if got[0].Role != "operation" {
			t.Errorf("%s role = %q, want \"operation\"", m, got[0].Role)
		}
	}

	// BOTH VERIFY ARITIES ARE REAL. The algorithm is the second argument, and
	// jws forces the caller to pass it so the token's own header cannot choose.
	// Keeping the arities apart is what lets the rules read that literal.
	if got := kb.ContractsFor("jws.verify", 2); len(got) == 0 {
		t.Error("jws.verify#2 resolved nothing")
	}
	if got := kb.ContractsFor("jws.verify", 9); len(got) != 0 {
		t.Error("jws.verify#9 resolved; that arity does not exist")
	}

	// isValid TESTS A STRING SHAPE, not a signature: three base64 segments
	// separated by dots. A contract on it would add an asset for a regular
	// expression.
	for _, unwanted := range []string{"jws.isValid#1", "jws.ALGORITHMS#0"} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q performs no cryptography and must not be declared", unwanted)
		}
	}

	// Ask whether jws claims a coordinate that is not its own, rather than
	// scanning the merged KB for a adjacent package's prefix -- the shared helper exists
	// because that scan passes only while the adjacent package has no KB yet.
	assertLibraryOwnsItsKeys(t, kb, "jws", "jws.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "jws.") {
			n++
		}
	}
	if n != 7 {
		t.Errorf("jws contributes %d keys, want 7", n)
	}
}
