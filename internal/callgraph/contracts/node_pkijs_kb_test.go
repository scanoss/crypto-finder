// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// pkijs signs and verifies through methods on its ASN.1 objects, so each class
// needs a constructor that types the receiver and the method the rules name.
func TestLoadEmbeddedNodePkijs(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	for _, w := range []struct {
		method string
		arity  int
		typ    string
		role   string
	}{
		{"pkijs.Certificate.<init>", 0, "pkijs.Certificate", "factory"},
		{"pkijs.Certificate.sign", 2, "void", "operation"},
		{"pkijs.Certificate.verify", 1, "boolean", "operation"},
		{"pkijs.CertificateChainValidationEngine.verify", 0, "pkijs.CertificateChainValidationEngineVerifyResult", "operation"},
		{"pkijs.CertificationRequest.verify", 0, "boolean", "operation"},
		{"pkijs.EnvelopedData.decrypt", 2, "builtins.bytes", "operation"},
		{"pkijs.SignedData.sign", 5, "void", "operation"},
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

	// sign needs a private key; there is no zero-argument form in any release.
	if got := kb.ContractsFor("pkijs.Certificate.sign", 0); len(got) != 0 {
		t.Errorf("ContractsFor(Certificate.sign, 0) resolved %d contracts; that arity does not exist", len(got))
	}

	assertLibraryOwnsItsKeys(t, kb, "pkijs", "pkijs.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "pkijs.") {
			n++
		}
	}
	if n != 43 {
		t.Errorf("pkijs contributes %d keys, want 43", n)
	}
}
