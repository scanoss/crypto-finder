// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeSSH(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}
	for _, w := range []struct {
		method string
		arity  int
		role   string
	}{
		{"node-ssh.NodeSSH.<init>", 0, "factory"},
		{"node-ssh.node_ssh.<init>", 0, "factory"},
		{"node-ssh.NodeSSH.connect", 1, "operation"},
	} {
		got := kb.ContractsFor(w.method, w.arity)
		if len(got) == 0 {
			t.Errorf("%s#%d resolved nothing", w.method, w.arity)
			continue
		}
		if got[0].Return.Type != "node-ssh.NodeSSH" || got[0].Role != w.role {
			t.Errorf("%s#%d = (%q, %q), want (node-ssh.NodeSSH, %q)", w.method, w.arity, got[0].Return.Type, got[0].Role, w.role)
		}
	}

	// Transfers over the connection carry no cryptographic step.
	for _, unwanted := range []string{"node-ssh.NodeSSH.execCommand#1", "node-ssh.NodeSSH.putFile#2", "node-ssh.NodeSSH.dispose#0"} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "node-ssh", "node-ssh.")
}
