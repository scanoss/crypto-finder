// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

func TestLoadEmbeddedNodeSeal(t *testing.T) {
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
		// The factory resolves the runtime under every published build.
		{"node-seal.SEAL", 0, "node-seal.Seal", "factory"},
		{"node-seal/throws.SEAL", 0, "node-seal.Seal", "factory"},
		{"node-seal/allows_wasm_node_umd.js.SEAL", 0, "node-seal.Seal", "factory"},
		{"node-seal/throws_wasm_cf_worker_es.SEAL", 1, "node-seal.Seal", "factory"},
		{"node-seal.Seal.KeyGenerator", 1, "node-seal.KeyGenerator", "factory"},
		{"node-seal.Seal.Encryptor", 2, "node-seal.Encryptor", "factory"},
		{"node-seal.Seal.Decryptor", 2, "node-seal.Decryptor", "factory"},
		{"node-seal.EncryptionParameters.setPolyModulusDegree", 1, "void", "config"},
		// The secret key already exists in the generator; the others are made.
		{"node-seal.KeyGenerator.secretKey", 0, "node-seal.SecretKey", "output"},
		{"node-seal.KeyGenerator.createPublicKey", 0, "node-seal.PublicKey", "operation"},
		{"node-seal.KeyGenerator.createGaloisKeys", 1, "node-seal.GaloisKeys", "operation"},
		{"node-seal.Encryptor.encrypt", 1, "node-seal.CipherText", "operation"},
		{"node-seal.Encryptor.encryptSymmetric", 2, "node-seal.CipherText", "operation"},
		{"node-seal.Decryptor.decrypt", 2, "node-seal.PlainText", "operation"},
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

	// Encoders and homomorphic arithmetic carry no key-bearing step.
	for _, unwanted := range []string{
		"node-seal.Seal.BatchEncoder#1",
		"node-seal.Seal.Evaluator#1",
		"node-seal.Evaluator.add#3",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "node-seal", "node-seal")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "node-seal") {
			n++
		}
	}
	if n != 147 {
		t.Errorf("node-seal contributes %d keys, want 147", n)
	}
}
