// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// This KB does not JOIN yet, and the reason is structural rather than specific
// to this library: the JavaScript parser emits `<module>.asymmetricSign` for
// `this.client.asymmetricSign(..)`, because what normalises a call site to a
// coordinate is namespace-import resolution, and a contract's return type is
// not propagated to a variable receiver. Measured with a positive control on
// the same binary -- a node-forge consumer emits `node-forge.pki.certificateFromPem`.
//
// Which is exactly why this test exists. "The KB is not in the binary" and "the
// KB is in the binary and the parser does not produce its keys" are two
// different defects that look identical in a scan result: no finding carries the
// coordinate either way. This pins the first half, so the day receiver typing
// lands, a regression here is legible as what it is.
func TestLoadEmbeddedNodeGoogleCloudKMS(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	// The constructor entries are load-bearing: without a typed receiver every
	// method entry below is unreachable. `new KeyManagementServiceClient()` with
	// no argument is the spelling published consumers actually write -- it is
	// what kms-decrypt and pd.gcp do -- so arity 0 is not a completeness
	// flourish, it is the common case.
	for _, want := range []string{
		"@google-cloud/kms.KeyManagementServiceClient.<init>#0",
		"@google-cloud/kms.KeyManagementServiceClient.<init>#1",
		"@google-cloud/kms.KeyManagementServiceClient.<init>#2",
		// Every gapic method is (request), (request, options|callback) or
		// (request, options, callback). All three arities exist for each.
		"@google-cloud/kms.KeyManagementServiceClient.encrypt#1",
		"@google-cloud/kms.KeyManagementServiceClient.encrypt#2",
		"@google-cloud/kms.KeyManagementServiceClient.encrypt#3",
		"@google-cloud/kms.KeyManagementServiceClient.decrypt#1",
		"@google-cloud/kms.KeyManagementServiceClient.rawEncrypt#1",
		"@google-cloud/kms.KeyManagementServiceClient.rawDecrypt#1",
		"@google-cloud/kms.KeyManagementServiceClient.asymmetricSign#1",
		"@google-cloud/kms.KeyManagementServiceClient.asymmetricDecrypt#1",
		"@google-cloud/kms.KeyManagementServiceClient.macSign#1",
		"@google-cloud/kms.KeyManagementServiceClient.macVerify#1",
		"@google-cloud/kms.KeyManagementServiceClient.generateRandomBytes#1",
		"@google-cloud/kms.KeyManagementServiceClient.getPublicKey#1",
		"@google-cloud/kms.KeyManagementServiceClient.createCryptoKey#1",
		"@google-cloud/kms.KeyManagementServiceClient.createImportJob#1",
		"@google-cloud/kms.KeyManagementServiceClient.importCryptoKeyVersion#1",
	} {
		if _, ok := kb.Contracts[want]; !ok {
			t.Errorf("contract %q missing from the embedded Node KB", want)
		}
	}

	// A constructor must carry a return type, or it types nothing and every
	// method entry above is dead weight.
	ctors, ok := kb.Contracts["@google-cloud/kms.KeyManagementServiceClient.<init>#0"]
	if !ok || len(ctors) == 0 {
		t.Fatal("the KeyManagementServiceClient constructor is missing")
	}
	if ctors[0].Return.Type != "@google-cloud/kms.KeyManagementServiceClient" {
		t.Errorf("constructor return = %+v, want the KeyManagementServiceClient type", ctors[0].Return)
	}

	// THE ONE DISTINCTION IN THIS KB THAT IS NOT MECHANICAL. getPublicKey
	// returns the PEM of a key's public half and verifies NOTHING; consumers
	// fetch it to derive an address. Declared `output` and not `operation`,
	// because typing it as an operation would put a verification in the
	// inventory at a line where none happened -- the same boundary that keeps
	// fast-jwt's createDecoder out of the verify bucket. If this assertion ever
	// fails, the inventory has started claiming a cryptographic operation for a
	// read.
	pub := kb.ContractsFor("@google-cloud/kms.KeyManagementServiceClient.getPublicKey", 1)
	if len(pub) == 0 {
		t.Fatal("getPublicKey resolved nothing")
	}
	if got := pub[0].Role; got != "output" {
		t.Errorf("getPublicKey role = %q, want \"output\": it returns key material and performs no verification", got)
	}

	// The cryptographic calls are operations, and macVerify is one of them: the
	// MAC purpose admits HMAC only, so the same key that checks the tag can
	// also produce it.
	for _, m := range []string{"asymmetricSign", "macSign", "macVerify", "encrypt", "decrypt"} {
		got := kb.ContractsFor("@google-cloud/kms.KeyManagementServiceClient."+m, 1)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%s, 1) resolved nothing", m)
			continue
		}
		if got[0].Role != "operation" {
			t.Errorf("%s role = %q, want \"operation\"", m, got[0].Role)
		}
	}

	// Service administration is deliberately uncontracted: listing keys,
	// destroying and restoring versions, and IAM policy calls perform no
	// cryptography. A contract on one of these would report an asset for an
	// audit operation.
	for _, unwanted := range []string{
		"@google-cloud/kms.KeyManagementServiceClient.listCryptoKeys#1",
		"@google-cloud/kms.KeyManagementServiceClient.destroyCryptoKeyVersion#1",
		"@google-cloud/kms.KeyManagementServiceClient.updateCryptoKeyPrimaryVersion#1",
		"@google-cloud/kms.KeyManagementServiceClient.getIamPolicy#1",
		// Path helpers build a resource string and touch no key material.
		"@google-cloud/kms.KeyManagementServiceClient.cryptoKeyPath#4",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q is service administration and must not be declared", unwanted)
		}
	}

	// An arity the library does not accept must resolve to nothing, or the KB
	// would type a call that cannot compile.
	if got := kb.ContractsFor("@google-cloud/kms.KeyManagementServiceClient.asymmetricSign", 9); len(got) != 0 {
		t.Errorf("ContractsFor(asymmetricSign, 9) resolved %d contracts; that arity does not exist", len(got))
	}

	// Ask whether this library claims a coordinate that is not its own, rather
	// than scanning the merged KB for the @google-cloud prefix: that scan passes
	// only while no sibling Google Cloud package has a KB, and adding one is the
	// ordinary way this catalog grows.
	assertLibraryOwnsItsKeys(t, kb, "@google-cloud/kms", "@google-cloud/kms.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "@google-cloud/kms.") {
			n++
		}
	}
	if n != 42 {
		t.Errorf("@google-cloud/kms contributes %d keys, want 42", n)
	}
}
