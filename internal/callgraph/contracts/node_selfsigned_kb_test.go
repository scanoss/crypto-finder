// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeSelfsigned(t *testing.T) {
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
		// Both arguments are optional.
		{"selfsigned.generate", 0, "selfsigned.Pems", "operation"},
		{"selfsigned.generate", 1, "selfsigned.Pems", "operation"},
		{"selfsigned.generate", 2, "selfsigned.Pems", "operation"},
		// The 1.x to 4.x callback form binds no result.
		{"selfsigned.generate", 3, "void", "operation"},
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

	assertLibraryOwnsItsKeys(t, kb, "selfsigned", "selfsigned.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "selfsigned.") {
			n++
		}
	}
	if n != 4 {
		t.Errorf("selfsigned contributes %d keys, want 4", n)
	}
}
