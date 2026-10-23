// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Callback-style functions return nothing and accept every leading-optional arity.
func TestLoadEmbeddedNodePem(t *testing.T) {
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
		{"pem.createPrivateKey", 1, "void", "operation"},
		{"pem.createPrivateKey", 3, "void", "operation"},
		{"pem.createEcparam", 4, "void", "operation"},
		{"pem.createCertificate", 2, "void", "operation"},
		{"pem.createPkcs12", 5, "void", "output"},
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
		"pem.createCertificate#3",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "pem", "pem.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "pem.") {
			n++
		}
	}
	if n != 19 {
		t.Errorf("pem contributes %d keys, want 19", n)
	}
}
