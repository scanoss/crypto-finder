// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Two classes, and the mechanism is the constructor's first argument. This KB is
// two factories plus the methods they make reachable.
func TestLoadEmbeddedNodeLiboqsNode(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	for _, want := range []string{
		"liboqs-node.KeyEncapsulation.<init>#1", "liboqs-node.KeyEncapsulation.<init>#2",
		"liboqs-node.KeyEncapsulation.encapsulateSecret#1",
		"liboqs-node.KeyEncapsulation.decapsulateSecret#1",
		"liboqs-node.Signature.<init>#1", "liboqs-node.Signature.<init>#2",
		"liboqs-node.Signature.sign#1", "liboqs-node.Signature.verify#3",
	} {
		if _, ok := kb.Contracts[want]; !ok {
			t.Errorf("contract %q missing from the embedded Node KB", want)
		}
	}

	// ONE TYPE PER CLASS, NOT ONE PER MECHANISM. The mechanism arrives as a
	// string, so a per-mechanism type could not resolve `new Signature(alg)`
	// with a variable. Reading the literal is the rules' job -- the same shape
	// as the jwa and keccak KBs.
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "liboqs-node.") &&
			(strings.Contains(k, "Kyber") || strings.Contains(k, "Dilithium") || strings.Contains(k, "SIKE")) {
			t.Errorf("key %q types a specific mechanism; liboqs-node carries it in an argument", k)
		}
	}

	// THE SECOND CONSTRUCTOR ARGUMENT IS A SECRET KEY, which is why both
	// arities exist: arity 1 generates a fresh key pair, arity 2 RESUMES FROM
	// EXISTING PRIVATE KEY MATERIAL. If the arities ever collapse, an inventory
	// loses the difference between minting a key and loading one.
	for _, cls := range []string{"KeyEncapsulation", "Signature"} {
		for _, arity := range []int{1, 2} {
			got := kb.ContractsFor("liboqs-node."+cls+".<init>", arity)
			if len(got) == 0 {
				t.Errorf("%s.<init>#%d resolved nothing", cls, arity)
				continue
			}
			if got[0].Return.Type != "liboqs-node."+cls {
				t.Errorf("%s.<init>#%d returns %q, want liboqs-node.%s", cls, arity, got[0].Return.Type, cls)
			}
		}
	}

	// verify TAKES MESSAGE, SIGNATURE AND PUBLIC KEY. There is no two-argument
	// form, and declaring one would type a call that cannot run.
	if got := kb.ContractsFor("liboqs-node.Signature.verify", 2); len(got) != 0 {
		t.Error("verify#2 resolved; liboqs verification takes message, signature and public key")
	}

	// exportSecretKey hands out material that already exists -- and for these
	// schemes that material is large, Classic-McEliece private keys running to
	// hundreds of kilobytes.
	for _, cls := range []string{"KeyEncapsulation", "Signature"} {
		got := kb.ContractsFor("liboqs-node."+cls+".exportSecretKey", 0)
		if len(got) == 0 {
			t.Errorf("%s.exportSecretKey resolved nothing", cls)
			continue
		}
		if got[0].Role != "output" {
			t.Errorf("%s.exportSecretKey role = %q, want \"output\"", cls, got[0].Role)
		}
	}

	// Enumeration helpers report which mechanisms the build supports and
	// perform no cryptography.
	for _, unwanted := range []string{
		"liboqs-node.KEMs.getEnabledAlgorithms#0", "liboqs-node.Sigs.isAlgorithmEnabled#1",
		"liboqs-node.KeyEncapsulation.getDetails#0",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q enumerates support and must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "liboqs-node", "liboqs-node.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "liboqs-node.") {
			n++
		}
	}
	if n != 12 {
		t.Errorf("liboqs-node contributes %d keys, want 12", n)
	}
}
