// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Seven free functions on a frozen export object. The handshake state is a plain
// object the caller threads through writeMessage and readMessage, so this KB is
// flat and initialize is a factory for that state rather than a constructor.
func TestLoadEmbeddedNodeNoiseProtocol(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	for _, want := range []string{
		"noise-protocol.initialize#3", "noise-protocol.initialize#6",
		"noise-protocol.writeMessage#3", "noise-protocol.readMessage#3",
		"noise-protocol.keygen#0", "noise-protocol.seedKeygen#1",
	} {
		if _, ok := kb.Contracts[want]; !ok {
			t.Errorf("contract %q missing from the embedded Node KB", want)
		}
	}

	// THE ARITIES OF initialize ARE THE POINT. It takes three to six arguments
	// depending on which static and remote keys the pattern needs -- NN takes
	// three, KK takes six -- and the rules read the pattern from the first one.
	// Keeping the arities apart is what lets them.
	for _, arity := range []int{3, 4, 5, 6} {
		got := kb.ContractsFor("noise-protocol.initialize", arity)
		if len(got) == 0 {
			t.Errorf("initialize#%d resolved nothing", arity)
			continue
		}
		if got[0].Return.Type != "noise-protocol.HandshakeState" {
			t.Errorf("initialize#%d returns %q, want the handshake state", arity, got[0].Return.Type)
		}
	}
	if got := kb.ContractsFor("noise-protocol.initialize", 2); len(got) != 0 {
		t.Error("initialize#2 resolved; the pattern, role and prologue are all required")
	}

	// THE CIPHER SUITE IS NOT IN ANY ARGUMENT, so it is not in this KB. The
	// package implements X25519-ChaChaPoly-BLAKE2b and nothing else, with no
	// negotiation; the rules publish it unconditionally and a key naming it here
	// would be duplicating what they already know.
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "noise-protocol.") &&
			(strings.Contains(k, "25519") || strings.Contains(k, "ChaCha") || strings.Contains(k, "BLAKE")) {
			t.Errorf("key %q names the cipher suite; this package has only one and the rules carry it", k)
		}
	}

	// keygen AND seedKeygen ARE SEPARATE ENTRIES and must stay separate:
	// seedKeygen derives the key deterministically, so it is only as secret as
	// its seed. One coordinate for both would file a reproducible key beside a
	// random one.
	for _, m := range []string{"noise-protocol.keygen", "noise-protocol.seedKeygen"} {
		arity := 0
		if strings.HasSuffix(m, "seedKeygen") {
			arity = 1
		}
		got := kb.ContractsFor(m, arity)
		if len(got) == 0 {
			t.Errorf("%s#%d resolved nothing", m, arity)
			continue
		}
		if got[0].Return.Type != "noise-protocol.KeyPair" {
			t.Errorf("%s returns %q, want noise-protocol.KeyPair", m, got[0].Return.Type)
		}
	}

	// destroy zeroes a buffer; SKLEN and PKLEN are integers.
	for _, unwanted := range []string{
		"noise-protocol.destroy#1", "noise-protocol.SKLEN#0", "noise-protocol.PKLEN#0",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q computes nothing and must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "noise-protocol", "noise-protocol.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "noise-protocol.") {
			n++
		}
	}
	if n != 10 {
		t.Errorf("noise-protocol contributes %d keys, want 10", n)
	}
}
