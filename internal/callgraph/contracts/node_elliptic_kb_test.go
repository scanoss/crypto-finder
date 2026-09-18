// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// elliptic is the case where a KB has the most to do: the curve is named once,
// at construction, and every operation afterwards is a method on an object two
// steps removed from it --
//
//	const ec     = new EC('secp256k1');   // the curve
//	const key    = ec.genKeyPair();       // a KeyPair, from the context
//	const sig    = key.sign(msgHash);     // an operation, on the KeyPair
//	const shared = key.derive(peerPoint); // ECDH, on the same KeyPair
//
// Typing `ec` and then `key` is what ties that signature back to secp256k1.
func TestLoadEmbeddedNodeElliptic(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	for _, tc := range []struct {
		method string
		arity  int
		want   string
	}{
		// BOTH CASINGS: the package exports `ec` and `eddsa` in lower case and
		// consumers overwhelmingly alias them to `EC` and `EdDSA`. The rules
		// carrying only the export spelling missed every aliased call site --
		// caught by the fixture, and it moved real-consumer recall from 80 to 85.
		{"elliptic.ec.<init>", 1, "elliptic.ec"},
		{"elliptic.EC.<init>", 1, "elliptic.ec"},
		{"elliptic.eddsa.<init>", 1, "elliptic.eddsa"},
		{"elliptic.EdDSA.<init>", 1, "elliptic.eddsa"},

		// TWO TYPES, NOT ONE: the context produces KeyPairs and the operations
		// live on the KeyPair. Merging them would let `ec.sign(..)` resolve,
		// which the library does not offer.
		{"elliptic.ec.genKeyPair", 0, "elliptic.KeyPair"},
		{"elliptic.ec.keyFromPrivate", 2, "elliptic.KeyPair"},
		{"elliptic.eddsa.keyFromSecret", 1, "elliptic.KeyPair"},

		{"elliptic.KeyPair.sign", 1, "elliptic.Signature"},
		{"elliptic.KeyPair.verify", 2, "boolean"},

		// derive() is ECDH and returns a BN, not a key object.
		{"elliptic.KeyPair.derive", 1, "BN"},

		// getPublic() returns a Point; getPublic('hex') returns a string. The
		// encoding argument changes the type, which is why both arities are
		// declared with different returns.
		{"elliptic.KeyPair.getPublic", 0, "elliptic.Point"},
		{"elliptic.KeyPair.getPublic", 1, "string"},

		{"elliptic.ec.recoverPubKey", 3, "elliptic.Point"},
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

	// The operations are NOT on the context. Asserting the absence keeps a
	// later edit from quietly merging the two types.
	for _, notOnContext := range []string{"elliptic.ec.sign", "elliptic.ec.verify", "elliptic.ec.derive"} {
		for arity := 0; arity <= 3; arity++ {
			if got := kb.ContractsFor(notOnContext, arity); len(got) != 0 {
				t.Errorf("%q resolved at arity %d; that method is on the KeyPair, not the curve context", notOnContext, arity)
			}
		}
	}

	// Separate coordinates implementing the same curves keep to their own keys.
	assertLibraryOwnsPrefix(t, kb, "elliptic", "elliptic.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "elliptic.") {
			n++
		}
	}
	if n != 24 {
		t.Errorf("elliptic contributes %d keys, want 24", n)
	}
}
