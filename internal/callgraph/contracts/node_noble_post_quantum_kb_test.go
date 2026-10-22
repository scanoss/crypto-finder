// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeNoblePostQuantum(t *testing.T) {
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
		{"@noble/post-quantum/ml-kem.ml_kem768.keygen", 0, "@noble/post-quantum.KeyPair", "operation"},
		{"@noble/post-quantum/ml-kem.js.ml_kem1024.encapsulate", 1, "@noble/post-quantum.Encapsulation", "operation"},
		{"@noble/post-quantum/ml-kem.js.ml_kem512.decapsulate", 2, "Uint8Array", "operation"},
		{"@noble/post-quantum/hybrid.js.ml_kem768_x25519.encapsulate", 1, "@noble/post-quantum.Encapsulation", "operation"},
		{"@noble/post-quantum/hybrid.js.QSF_ml_kem1024_p384.keygen", 1, "@noble/post-quantum.KeyPair", "operation"},
		// 0.1-0.4 sign takes up to four arguments, 0.5+ up to three.
		{"@noble/post-quantum/ml-dsa.ml_dsa65.sign", 4, "Uint8Array", "operation"},
		{"@noble/post-quantum/ml-dsa.js.ml_dsa87.verify", 3, "boolean", "operation"},
		{"@noble/post-quantum/slh-dsa.js.slh_dsa_shake_256s.sign", 2, "Uint8Array", "operation"},
		{"@noble/post-quantum/falcon.js.falcon512.attached.seal", 2, "Uint8Array", "operation"},
		{"@noble/post-quantum/falcon.js.falcon1024padded.verify", 4, "boolean", "operation"},
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

	// hybrid and falcon only ever shipped `.js` subpaths.
	for key := range kb.Contracts {
		if strings.HasPrefix(key, "@noble/post-quantum/hybrid.") && !strings.HasPrefix(key, "@noble/post-quantum/hybrid.js.") ||
			strings.HasPrefix(key, "@noble/post-quantum/falcon.") && !strings.HasPrefix(key, "@noble/post-quantum/falcon.js.") ||
			strings.HasPrefix(key, "@noble/post-quantum/utils") {
			t.Errorf("contract %q names a helper or a spelling the package never shipped", key)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "noble-post-quantum", "@noble/post-quantum")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "@noble/post-quantum") {
			n++
		}
	}
	if n != 314 {
		t.Errorf("noble-post-quantum contributes %d keys, want 314", n)
	}
}
