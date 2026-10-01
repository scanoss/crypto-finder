// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeNobleEd25519(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	type want struct {
		method string
		arity  int
		typ    string
		role   string
	}
	for _, w := range []want{
		// The three calling conventions are three exports, and all resolve.
		{"@noble/ed25519.sign", 2, "Uint8Array", "operation"},
		{"@noble/ed25519.signAsync", 2, "Uint8Array", "operation"},
		{"@noble/ed25519.sync.sign", 2, "Uint8Array", "operation"},
		{"@noble/ed25519.verify", 3, "boolean", "operation"},
		{"@noble/ed25519.verify", 4, "boolean", "operation"},
		{"@noble/ed25519.sync.verify", 3, "boolean", "operation"},
		{"@noble/ed25519.getPublicKey", 1, "Uint8Array", "operation"},
		{"@noble/ed25519.utils.randomPrivateKey", 0, "Uint8Array", "operation"},
		{"@noble/ed25519.utils.randomSecretKey", 1, "Uint8Array", "operation"},
		{"@noble/ed25519.keygen", 0, "@noble/ed25519.KeyPair", "operation"},
		{"@noble/ed25519.getSharedSecret", 2, "Uint8Array", "operation"},
		{"@noble/ed25519.curve25519.scalarMultBase", 1, "Uint8Array", "operation"},
		{"@noble/ed25519.hash", 1, "Uint8Array", "operation"},
		{"@noble/ed25519.Point.fromHex", 1, "@noble/ed25519.Point", "factory"},
	} {
		got := kb.ContractsFor(w.method, w.arity)
		if len(got) == 0 {
			t.Errorf("%s#%d resolved nothing", w.method, w.arity)
			continue
		}
		if got[0].Return.Type != w.typ || got[0].Role != w.role {
			t.Errorf("%s#%d = (%q, %q), want (%q, %q)", w.method, w.arity, got[0].Return.Type, got[0].Role, w.typ, w.role)
		}
	}

	// 1.x sync.verify takes no options object.
	if got := kb.ContractsFor("@noble/ed25519.sync.verify", 4); len(got) != 0 {
		t.Error("sync.verify#4 resolved; the 1.x sync object's verify takes three arguments")
	}

	// The hash hooks configure and the byte helpers convert; neither computes.
	for _, unwanted := range []string{
		"@noble/ed25519.etc.sha512Sync#1",
		"@noble/ed25519.utils.sha512Sync#1",
		"@noble/ed25519.etc.concatBytes#2",
		"@noble/ed25519.utils.bytesToHex#1",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q computes nothing and must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "noble-ed25519", "@noble/ed25519.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "@noble/ed25519.") {
			n++
		}
	}
	if n != 26 {
		t.Errorf("noble-ed25519 contributes %d keys, want 26", n)
	}
}
