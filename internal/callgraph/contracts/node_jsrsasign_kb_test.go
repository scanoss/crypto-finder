// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// jsrsasign exposes its whole surface through three global-looking namespaces --
// KJUR, KEYUTIL and X509 -- rather than through exported functions, so every key
// here is a namespace path.
//
// THE SCOPE OF THIS KB IS MEASURED, NOT ENUMERATED. The library ships hundreds of
// classes (CMS, CAdES, TSP, OCSP, the whole of ASN.1) and contracting all of them
// would be typing no consumer exercises. What is declared is what the consumer
// files that actually import jsrsasign call, counted across a 16-consumer draw.
func TestLoadEmbeddedNodeJsrsasign(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	for _, want := range []string{
		"jsrsasign.KJUR.crypto.Signature.<init>#1",
		"jsrsasign.KJUR.crypto.Signature.sign#0",
		"jsrsasign.KJUR.crypto.Signature.verify#1",
		"jsrsasign.KJUR.crypto.MessageDigest.<init>#1",
		"jsrsasign.KJUR.crypto.Util.hashHex#2",
		"jsrsasign.KJUR.crypto.Cipher.encrypt#3",
		"jsrsasign.KJUR.jws.JWS.sign#4",
		// The four most-called entries in the draw.
		"jsrsasign.KEYUTIL.getKey#1",
		"jsrsasign.KEYUTIL.getPEM#1",
		"jsrsasign.KEYUTIL.getJWK#1",
		"jsrsasign.KEYUTIL.generateKeypair#2",
		"jsrsasign.X509.<init>#0",
		"jsrsasign.X509.getPublicKeyFromCertPEM#1",
	} {
		if _, ok := kb.Contracts[want]; !ok {
			t.Errorf("contract %q missing from the embedded Node KB", want)
		}
	}

	// THE CONSTRUCTORS ARE LOAD-BEARING. Both Signature and MessageDigest are
	// driven through methods on the instance, so without a return type here
	// every one of those method entries is unreachable.
	for _, tc := range []struct{ ctor, want string }{
		{"jsrsasign.KJUR.crypto.Signature.<init>", "jsrsasign.KJUR.crypto.Signature"},
		{"jsrsasign.KJUR.crypto.MessageDigest.<init>", "jsrsasign.KJUR.crypto.MessageDigest"},
		{"jsrsasign.X509.<init>", "jsrsasign.X509"},
	} {
		got := kb.ContractsFor(tc.ctor, 0)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, 0) resolved nothing", tc.ctor)
			continue
		}
		if got[0].Return.Type != tc.want {
			t.Errorf("%s returns %q, want %q", tc.ctor, got[0].Return.Type, tc.want)
		}
	}

	// updateString carries the chain so the terminal sign() has a receiver.
	for _, m := range []string{
		"jsrsasign.KJUR.crypto.Signature.updateString",
		"jsrsasign.KJUR.crypto.MessageDigest.updateString",
	} {
		got := kb.ContractsFor(m, 1)
		if len(got) == 0 {
			t.Errorf("%s resolved nothing", m)
			continue
		}
		if !strings.HasPrefix(got[0].Return.Type, "jsrsasign.KJUR.crypto.") {
			t.Errorf("%s returns %q, want the same crypto object", m, got[0].Return.Type)
		}
	}

	// KEY PARSING IS A FACTORY AND KEY RE-ENCODING IS OUTPUT. getKey produces a
	// key object the caller then uses; getPEM and getJWK produce text. The
	// distinction is what lets an inventory say where key material CROSSES A
	// BOUNDARY rather than merely where it is read.
	if got := kb.ContractsFor("jsrsasign.KEYUTIL.getKey", 1); len(got) == 0 || got[0].Role != "factory" {
		t.Error("KEYUTIL.getKey must be a factory returning a key object")
	}
	for _, m := range []string{"jsrsasign.KEYUTIL.getPEM", "jsrsasign.KEYUTIL.getJWK"} {
		got := kb.ContractsFor(m, 1)
		if len(got) == 0 {
			t.Errorf("%s resolved nothing", m)
			continue
		}
		if got[0].Role != "output" {
			t.Errorf("%s role = %q, want \"output\": it re-encodes a key that already exists", m, got[0].Role)
		}
	}

	// READING A CERTIFICATE IS NOT VERIFYING IT. readCertPEM decodes structure
	// and checks nothing; verifySignature is the verification. If these ever
	// collapse, an inventory starts reporting a signature check at a line that
	// only parsed bytes.
	if got := kb.ContractsFor("jsrsasign.X509.getPublicKeyFromCertPEM", 1); len(got) == 0 || got[0].Role != "output" {
		t.Error("getPublicKeyFromCertPEM must be output: it extracts a key, it verifies nothing")
	}
	if got := kb.ContractsFor("jsrsasign.X509.verifySignature", 1); len(got) == 0 || got[0].Role != "operation" {
		t.Error("verifySignature must be an operation")
	}

	// ENCODING HELPERS ARE DELIBERATELY ABSENT. hextob64 is the second
	// most-called jsrsasign function in the draw and computes no cryptography,
	// which is exactly why its absence is asserted: call frequency is not
	// cryptographic relevance.
	for _, unwanted := range []string{
		"jsrsasign.hextob64#1", "jsrsasign.b64tohex#1", "jsrsasign.pemtohex#1",
		"jsrsasign.ASN1HEX.getVbyList#4",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q converts encodings and must not be declared", unwanted)
		}
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "jsrsasign.") {
			n++
		}
	}
	if n != 54 {
		t.Errorf("jsrsasign contributes %d keys, want 54", n)
	}
}
