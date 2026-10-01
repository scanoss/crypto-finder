// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeSSH2(t *testing.T) {
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
		{"ssh2.Client.<init>", 0, "ssh2.Client", "factory"},
		{"ssh2.Client.connect", 1, "ssh2.Client", "operation"},
		{"ssh2.Server.<init>", 1, "ssh2.Server", "factory"},
		{"ssh2.Server.<init>", 2, "ssh2.Server", "factory"},
		{"ssh2.utils.generateKeyPairSync", 1, "ssh2.GeneratedKeyPair", "operation"},
		{"ssh2.utils.generateKeyPairSync", 2, "ssh2.GeneratedKeyPair", "operation"},
		{"ssh2.utils.generateKeyPair", 3, "void", "operation"},
		{"ssh2.utils.parseKey", 1, "ssh2.ParsedKey", "factory"},
		{"ssh2.utils.parseKey", 2, "ssh2.ParsedKey", "factory"},
		// The hash algorithm is an optional trailing argument.
		{"ssh2.ParsedKey.sign", 1, "Buffer", "operation"},
		{"ssh2.ParsedKey.sign", 2, "Buffer", "operation"},
		{"ssh2.ParsedKey.verify", 2, "boolean", "operation"},
		{"ssh2.ParsedKey.verify", 3, "boolean", "operation"},
		{"ssh2.ParsedKey.getPublicSSH", 0, "string", "output"},
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

	// Channels, sessions and agents run inside an established connection and
	// compute nothing of their own.
	for _, unwanted := range []string{
		"ssh2.Client.exec#2",
		"ssh2.Client.shell#2",
		"ssh2.Client.sftp#1",
		"ssh2.Client.forwardOut#5",
		"ssh2.Server.listen#2",
		"ssh2.ParsedKey.isPrivateKey#0",
		"ssh2.ParsedKey.equals#1",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "ssh2", "ssh2.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "ssh2.") {
			n++
		}
	}
	if n != 18 {
		t.Errorf("ssh2 contributes %d keys, want 18", n)
	}
}
