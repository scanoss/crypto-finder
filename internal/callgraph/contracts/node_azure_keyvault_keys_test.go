// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// This KB does not JOIN yet: the JavaScript parser emits `<module>.sign` for
// `cryptographyClient.sign(..)` rather than the library coordinate, because what
// normalises a call site to a coordinate is namespace-import resolution and a
// contract's return type is not propagated to a variable receiver. Measured with
// a positive control -- a node-forge consumer on the same binary emits
// `node-forge.pki.certificateFromPem`.
//
// That is exactly why this test exists. "The KB is not in the binary" and "the
// KB is in the binary and the parser does not produce its keys" are two
// different defects that look identical from a scan result: no finding carries
// the coordinate either way. This pins the first half, so the day receiver
// typing lands, a regression here is legible as what it is.
func TestLoadEmbeddedNodeAzureKeyvaultKeys(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	// The constructors are the load-bearing entries: without a typed receiver
	// every method entry below is unreachable. Both the two- and three-argument
	// spellings are real -- the pipeline options argument is optional.
	for _, want := range []string{
		"@azure/keyvault-keys.CryptographyClient.<init>#2",
		"@azure/keyvault-keys.CryptographyClient.<init>#3",
		"@azure/keyvault-keys.KeyClient.<init>#2",
		"@azure/keyvault-keys.KeyClient.<init>#3",
		// getCryptographyClient performs no cryptography and is contracted
		// because it RETURNS a client: it is the third way to obtain one.
		"@azure/keyvault-keys.KeyClient.getCryptographyClient#1",
		// encrypt/decrypt take a parameters object OR the algorithm
		// positionally; both overloads are declared in the package's own .d.ts.
		"@azure/keyvault-keys.CryptographyClient.encrypt#1",
		"@azure/keyvault-keys.CryptographyClient.encrypt#2",
		// sign/verify/wrapKey/unwrapKey take the algorithm positionally only.
		//
		// These six arities are not a reading of the documentation: they are
		// every shape REAL published consumers write, counted across the 31
		// call sites this family's rules match in a 15-consumer draw --
		// unwrapKey(2) x10, wrapKey(2) x10, sign(2) x5, verify(3) x4,
		// encrypt(2) x1, decrypt(2) x1. Every one has an entry here, so the
		// day the parser resolves a variable receiver this KB joins real code
		// rather than a fixture.
		"@azure/keyvault-keys.CryptographyClient.sign#2",
		"@azure/keyvault-keys.CryptographyClient.verify#3",
		"@azure/keyvault-keys.CryptographyClient.wrapKey#2",
		"@azure/keyvault-keys.CryptographyClient.unwrapKey#2",
		"@azure/keyvault-keys.CryptographyClient.decrypt#2",
		"@azure/keyvault-keys.KeyClient.createKey#2",
		"@azure/keyvault-keys.KeyClient.importKey#2",
		"@azure/keyvault-keys.KeyClient.getRandomBytes#1",
	} {
		if _, ok := kb.Contracts[want]; !ok {
			t.Errorf("contract %q missing from the embedded Node KB", want)
		}
	}

	// A constructor must carry a return type, or it types nothing and the
	// method entries are dead weight.
	ctors, ok := kb.Contracts["@azure/keyvault-keys.CryptographyClient.<init>#2"]
	if !ok || len(ctors) == 0 {
		t.Fatal("the CryptographyClient constructor is missing")
	}
	if ctors[0].Return.Type != "@azure/keyvault-keys.CryptographyClient" {
		t.Errorf("constructor return = %+v, want the CryptographyClient type", ctors[0].Return)
	}

	// Vault administration is deliberately uncontracted: listing, deleting,
	// recovering, backing up and rotating keys perform no cryptography. A
	// contract on one of these would report an asset for an audit operation.
	for _, unwanted := range []string{
		"@azure/keyvault-keys.KeyClient.listPropertiesOfKeys#0",
		"@azure/keyvault-keys.KeyClient.beginDeleteKey#1",
		"@azure/keyvault-keys.KeyClient.backupKey#1",
		"@azure/keyvault-keys.KeyClient.updateKeyRotationPolicy#2",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q is vault administration and must not be declared", unwanted)
		}
	}

	// THE RESOLUTION LAYER, not the map. Everything above reads kb.Contracts
	// directly, which proves the file parsed and nothing more. ContractsFor is
	// what the callgraph actually calls, so this is the last thing about this
	// KB that can be checked without a mining stage: given the key the graph
	// would emit for each real consumer shape, does the KB answer, and does it
	// answer with the right type?
	//
	// The keys below are the six shapes counted in published consumers. The
	// graph does not emit them for this library today -- every crypto call is
	// on an instance, and a receiver's type is not resolved from a contract
	// return -- so this asserts the half that is ours: when the key arrives,
	// the answer is here.
	for _, tc := range []struct {
		method string
		arity  int
		want   string
	}{
		{"@azure/keyvault-keys.CryptographyClient.sign", 2, "@azure/keyvault-keys.SignResult"},
		{"@azure/keyvault-keys.CryptographyClient.verify", 3, "@azure/keyvault-keys.VerifyResult"},
		{"@azure/keyvault-keys.CryptographyClient.wrapKey", 2, "@azure/keyvault-keys.WrapResult"},
		{"@azure/keyvault-keys.CryptographyClient.unwrapKey", 2, "@azure/keyvault-keys.UnwrapResult"},
		{"@azure/keyvault-keys.CryptographyClient.encrypt", 2, "@azure/keyvault-keys.EncryptResult"},
		{"@azure/keyvault-keys.CryptographyClient.decrypt", 2, "@azure/keyvault-keys.DecryptResult"},
		// The constructor is the entry that makes the six above reachable at
		// all: it is what types the receiver.
		{"@azure/keyvault-keys.CryptographyClient.<init>", 2, "@azure/keyvault-keys.CryptographyClient"},
		// And the third way to obtain a client, from a KeyClient.
		{"@azure/keyvault-keys.KeyClient.getCryptographyClient", 1, "@azure/keyvault-keys.CryptographyClient"},
	} {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, %d) resolved nothing", tc.method, tc.arity)
			continue
		}
		if got[0].Return.Type != tc.want {
			t.Errorf("ContractsFor(%q, %d) returns %q, want %q", tc.method, tc.arity, got[0].Return.Type, tc.want)
		}
	}

	// An arity the library does not accept must resolve to nothing, or the KB
	// would type a call that cannot compile.
	if got := kb.ContractsFor("@azure/keyvault-keys.CryptographyClient.sign", 9); len(got) != 0 {
		t.Errorf("ContractsFor(sign, 9) resolved %d contracts; that arity does not exist", len(got))
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "@azure/keyvault-keys.") {
			n++
		}
	}
	if n != 39 {
		t.Errorf("@azure/keyvault-keys contributes %d keys, want 39", n)
	}
}
