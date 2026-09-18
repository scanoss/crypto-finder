// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// kbpgp is callback-style, so nothing chains: every entry takes an options
// object and a Node callback, and the value a consumer works with arrives as a
// callback argument rather than as a return. The return types here describe what
// the callback receives.
func TestLoadEmbeddedNodeKbpgp(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	for _, want := range []string{
		"kbpgp.box#2", "kbpgp.unbox#2",
		"kbpgp.KeyManager.generate#2", "kbpgp.KeyManager.generate_primary#2",
		"kbpgp.KeyManager.import_public#2", "kbpgp.KeyManager.import_from_armored_pgp#2",
		"kbpgp.KeyManager.import_from_p3skb#2",
		"kbpgp.keyring.KeyRing.<init>#0",
	} {
		if _, ok := kb.Contracts[want]; !ok {
			t.Errorf("contract %q missing from the embedded Node KB", want)
		}
	}

	// BOX AND UNBOX ARE NOT NARROWED TO ENCRYPT OR SIGN. Each does several
	// things depending on options the KB cannot see, and in the draw those
	// options are always an object built elsewhere. Declaring box as "encrypt"
	// would lose the signing half of every call that supplies sign_with.
	for _, m := range []string{"kbpgp.box", "kbpgp.unbox"} {
		got := kb.ContractsFor(m, 2)
		if len(got) == 0 {
			t.Errorf("%s#2 resolved nothing", m)
			continue
		}
		if got[0].Role != "operation" {
			t.Errorf("%s role = %q, want \"operation\"", m, got[0].Role)
		}
	}

	// THE KEY MANAGERS ARE FACTORIES AND THEY ARE MOST OF WHAT CONSUMERS TOUCH:
	// across sixteen consumers, import_from_armored_pgp has 14 call sites,
	// KeyRing 11, import_public 7 and generate 8 -- more than box and unbox
	// together. Each must return a KeyManager or nothing downstream resolves.
	for _, m := range []string{
		"kbpgp.KeyManager.generate", "kbpgp.KeyManager.import_public",
		"kbpgp.KeyManager.import_from_armored_pgp", "kbpgp.KeyManager.import_from_p3skb",
	} {
		got := kb.ContractsFor(m, 2)
		if len(got) == 0 {
			t.Errorf("%s#2 resolved nothing", m)
			continue
		}
		if got[0].Return.Type != "kbpgp.KeyManager" {
			t.Errorf("%s returns %q, want kbpgp.KeyManager", m, got[0].Return.Type)
		}
		if got[0].Role != "factory" {
			t.Errorf("%s role = %q, want \"factory\"", m, got[0].Role)
		}
	}

	// IMPORTING A PUBLIC KEY AND IMPORTING AN ARMORED BLOCK ARE DIFFERENT FACTS.
	// The first brings in a verification key; the second can carry secret key
	// material depending on the block. Both must stay declared so the rules can
	// report them apart.
	if _, ok := kb.Contracts["kbpgp.KeyManager.import_public#2"]; !ok {
		t.Error("import_public must stay distinguishable from import_from_armored_pgp")
	}

	// Exporting key material is output, not an operation.
	for _, m := range []string{"kbpgp.KeyManager.export_pgp_private", "kbpgp.KeyManager.export_pgp_public"} {
		got := kb.ContractsFor(m, 2)
		if len(got) == 0 {
			t.Errorf("%s#2 resolved nothing", m)
			continue
		}
		if got[0].Role != "output" {
			t.Errorf("%s role = %q, want \"output\": it serializes a key that already exists", m, got[0].Role)
		}
	}

	// Encoding and enumeration are deliberately uncontracted.
	for _, unwanted := range []string{
		"kbpgp.armor.encode#2", "kbpgp.armor.decode#1", "kbpgp.bn.BigInteger.<init>#1",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q encodes or enumerates and must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "kbpgp", "kbpgp.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "kbpgp.") {
			n++
		}
	}
	if n != 12 {
		t.Errorf("kbpgp contributes %d keys, want 12", n)
	}
}
