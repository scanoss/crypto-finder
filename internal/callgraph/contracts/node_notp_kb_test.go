// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The trailing options object is optional.
func TestLoadEmbeddedNodeNotp(t *testing.T) {
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
		{"notp.totp.gen", 1, "builtins.string", "operation"},
		{"notp.hotp.gen", 2, "builtins.string", "operation"},
		{"notp.totp.verify", 2, "notp.Delta", "operation"},
		{"notp.hotp.verify", 3, "notp.Delta", "operation"},
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
		"notp.totp.verify#1",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "notp", "notp.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "notp.") {
			n++
		}
	}
	if n != 8 {
		t.Errorf("notp contributes %d keys, want 8", n)
	}
}
