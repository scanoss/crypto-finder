// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// scrypt takes an optional progress callback; syncScrypt does not.
func TestLoadEmbeddedNodeScryptJs(t *testing.T) {
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
		{"scrypt-js.scrypt", 6, "builtins.bytes", "operation"},
		{"scrypt-js.scrypt", 7, "builtins.bytes", "operation"},
		{"scrypt-js.syncScrypt", 6, "builtins.bytes", "operation"},
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
		"scrypt-js.syncScrypt#7",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "scrypt-js", "scrypt-js.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "scrypt-js.") {
			n++
		}
	}
	if n != 3 {
		t.Errorf("scrypt-js contributes %d keys, want 3", n)
	}
}
