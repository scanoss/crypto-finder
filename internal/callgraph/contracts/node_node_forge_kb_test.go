// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeForgeKeysMatchTheParser(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	type want struct {
		method string
		arity  int
		role   string
	}
	for _, w := range []want{
		{"node-forge.pki.createCertificate", 0, "factory"},
		{"node-forge.md.sha256.create", 0, "factory"},
		{"node-forge.pki.createCaStore", 0, "factory"},
		{"node-forge.CaStore.addCertificate", 1, "config"},
		{"node-forge.CertificationRequest.setSubject", 1, "config"},
		{"node-forge.CertificationRequest.setAttributes", 1, "config"},
		{"node-forge.CertificationRequest.sign", 2, "operation"},
		{"node-forge.CertificationRequest.verify", 0, "operation"},
		{"node-forge.Certificate.verify", 1, "operation"},
		{"node-forge.MessageDigest.update", 2, "operation"},
	} {
		got := kb.ContractsFor(w.method, w.arity)
		if len(got) == 0 {
			t.Errorf("%s#%d resolved nothing", w.method, w.arity)
			continue
		}
		if got[0].Role != w.role {
			t.Errorf("%s#%d role = %q, want %q", w.method, w.arity, got[0].Role, w.role)
		}
	}

	// The parser keys `forge.pki.createCertificate()` by the module the local
	// name was imported from, so every key must start with the package name. A
	// key on the consumer's local name (`forge.`) never matches a call.
	assertLibraryOwnsItsKeys(t, kb, "node-forge", "node-forge.")
}
