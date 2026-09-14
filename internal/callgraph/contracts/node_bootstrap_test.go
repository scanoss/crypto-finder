// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The Node KB used to hold one placeholder file with `contracts: []`, kept only
// because go:embed needs a YAML match, and this test asserted the placeholder was
// what loaded. node-forge is the first real Node library KB, so the placeholder
// is gone and the assertion is now the opposite one: the embedded KB must carry
// real contracts.
func TestLoadEmbeddedNode(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}
	if kb.Ecosystem != "node" {
		t.Fatalf("ecosystem = %q, want node", kb.Ecosystem)
	}
	if len(kb.Contracts) == 0 {
		t.Fatal("the embedded Node KB carries no contracts")
	}

	// An entry point keyed as the graph emits it, and a method keyed on the type
	// that entry point returns. The pair is what makes the second half of a
	// fluent call sequence resolvable at all.
	for _, want := range []string{
		"forge.pki.certificateFromPem#1",
		"node-forge.Certificate.setSubject#1",
	} {
		if _, ok := kb.Contracts[want]; !ok {
			t.Errorf("contract %q missing from the embedded Node KB", want)
		}
	}
}
