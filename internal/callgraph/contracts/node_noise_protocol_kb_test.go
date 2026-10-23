// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Key pairs are factories; writeMessage is the handshake step.
func TestLoadEmbeddedNodeNoiseProtocol(t *testing.T) {
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
		{"noise-protocol.keygen", 0, "noise-protocol.KeyPair", "factory"},
		{"noise-protocol.seedKeygen", 1, "noise-protocol.KeyPair", "factory"},
		{"noise-protocol.writeMessage", 3, "noise-protocol.CipherStates", "operation"},
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
		"noise-protocol.readMessage#3",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "noise-protocol", "noise-protocol.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "noise-protocol.") {
			n++
		}
	}
	if n != 4 {
		t.Errorf("noise-protocol contributes %d keys, want 4", n)
	}
}
