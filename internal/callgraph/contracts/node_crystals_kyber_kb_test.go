// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The first post-quantum Node family in this campaign: ML-KEM (FIPS 203,
// formerly CRYSTALS-Kyber), whose operations are encapsulate and decapsulate
// rather than encrypt or sign.
//
// THE CONSTRUCTORS CARRY THE SECURITY LEVEL and the operations do not. A
// consumer writes `const kem = new MlKem768()` once and then calls
// `kem.encap(pk)` with no level in sight, so typing the constructor is the only
// way a reader can tell which ML-KEM a given encap belongs to. The rules make
// the same split, and an earlier version that did not reported ML-KEM-512, 768
// and 1024 for one call.
func TestLoadEmbeddedNodeCrystalsKyber(t *testing.T) {
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
		// All three parameter sets, under both class names.
		{"crystals-kyber-js.MlKem512.<init>", 0, "crystals-kyber-js.MlKemBase"},
		{"crystals-kyber-js.MlKem768.<init>", 0, "crystals-kyber-js.MlKemBase"},
		{"crystals-kyber-js.MlKem1024.<init>", 0, "crystals-kyber-js.MlKemBase"},

		// BOTH NAMES ARE LIVE: NIST standardized Kyber as ML-KEM in FIPS 203,
		// and the old names are still the majority in the deployed corpus --
		// measured, Kyber1024 appears more often than MlKem1024 in the draw.
		{"crystals-kyber-js.Kyber768.<init>", 0, "crystals-kyber-js.MlKemBase"},
		{"crystals-kyber-js.Kyber1024.<init>", 0, "crystals-kyber-js.MlKemBase"},
		{"crystals-kyber-js.createMlKem768", 0, "crystals-kyber-js.MlKemBase"},

		// THE TUPLE RETURNS ARE REAL: generateKeyPair and deriveKeyPair return
		// [publicKey, secretKey] and encap returns [ciphertext, sharedSecret].
		// Declaring those as a single Uint8Array would type a variable as half
		// of what the runtime produces. decap returns the shared secret alone.
		{"crystals-kyber-js.MlKemBase.generateKeyPair", 0, "Uint8Array[]"},
		{"crystals-kyber-js.MlKemBase.deriveKeyPair", 1, "Uint8Array[]"},
		{"crystals-kyber-js.MlKemBase.encap", 1, "Uint8Array[]"},
		{"crystals-kyber-js.MlKemBase.decap", 2, "Uint8Array"},

		// The re-exported SHA-3 primitives consumers use for domain separation.
		{"crystals-kyber-js.sha3_256", 1, "Uint8Array"},
		{"crystals-kyber-js.shake256", 1, "Uint8Array"},
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

	for _, bogus := range []struct {
		method string
		arity  int
	}{
		{"crystals-kyber-js.MlKemBase.decap", 1},
		{"crystals-kyber-js.MlKemBase.generateKeyPair", 1},
		{"crystals-kyber-js.MlKem768.<init>", 1},
	} {
		if got := kb.ContractsFor(bogus.method, bogus.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) resolved %d contracts; that arity does not exist", bogus.method, bogus.arity, len(got))
		}
	}

	// The other ML-KEM implementations are separate coordinates and must never
	// be keyed here: `mlkem`, `@noble/post-quantum` and `liboqs-node` share
	// every operation name with this package.
	for _, foreign := range []string{"mlkem.", "@noble/post-quantum.", "liboqs-node."} {
		for k := range kb.Contracts {
			if strings.HasPrefix(k, foreign) {
				t.Errorf("key %q belongs to %s, a different ML-KEM package", k, foreign)
			}
		}
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "crystals-kyber-js.") {
			n++
		}
	}
	if n != 18 {
		t.Errorf("crystals-kyber-js contributes %d keys, want 18", n)
	}
}
