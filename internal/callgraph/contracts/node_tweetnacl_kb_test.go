// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Nested function properties are keys of their own: box.open.after is not box.open.
func TestLoadEmbeddedNodeTweetnacl(t *testing.T) {
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
		{"tweetnacl.box", 4, "builtins.bytes", "operation"},
		{"tweetnacl.box.open.after", 3, "builtins.bytes", "operation"},
		{"tweetnacl.box.keyPair", 0, "tweetnacl.BoxKeyPair", "factory"},
		{"tweetnacl.sign.detached.verify", 3, "boolean", "operation"},
		{"tweetnacl.sign.keyPair.fromSeed", 1, "tweetnacl.SignKeyPair", "factory"},
		{"tweetnacl.scalarMult.base", 1, "builtins.bytes", "operation"},
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

	for _, unwanted := range []string{
		"tweetnacl.box#2",
		"tweetnacl.secretbox#4",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "tweetnacl", "tweetnacl.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "tweetnacl.") {
			n++
		}
	}
	if n != 20 {
		t.Errorf("tweetnacl contributes %d keys, want 20", n)
	}
}
