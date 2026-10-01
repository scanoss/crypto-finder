// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeWeb3(t *testing.T) {
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
		// The provider and, in 1.x, the net are optional.
		{"web3.Web3.<init>", 0, "web3.Web3", "factory"},
		{"web3.Web3.<init>", 1, "web3.Web3", "factory"},
		{"web3.Web3.<init>", 2, "web3.Web3", "factory"},
		{"web3.utils.keccak256", 1, "string", "operation"},
		{"web3.utils.sha3", 1, "string", "operation"},
		{"web3.utils.sha3Raw", 1, "string", "operation"},
		// Variadic: declared for 1 to 6 values.
		{"web3.utils.soliditySha3", 1, "string", "operation"},
		{"web3.utils.soliditySha3", 6, "string", "operation"},
		{"web3.utils.soliditySha3Raw", 3, "string", "operation"},
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

	// The accounts surface hangs off a nested object the parser does not type,
	// and the RPC signing calls ask the connected node to sign.
	for _, unwanted := range []string{
		"web3.eth.accounts.sign#2",
		"web3.eth.accounts.create#0",
		"web3.eth.accounts.privateKeyToAccount#1",
		"web3.eth.sign#2",
		"web3.eth.personal.sign#3",
		"web3.eth.signTransaction#1",
		"web3.utils.soliditySha3#7",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "web3", "web3.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "web3.") {
			n++
		}
	}
	if n != 18 {
		t.Errorf("web3 contributes %d keys, want 18", n)
	}
}
