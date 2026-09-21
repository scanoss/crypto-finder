// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// crypto-js is reached through the namespace, so its keys are the ones the
// parser emits -- measured, `CryptoJS.AES.encrypt(..)` resolves to
// `crypto-js.AES.encrypt` and `CryptoJS.HmacSHA256(..)` to
// `crypto-js.HmacSHA256`.
//
// The one shape that does NOT resolve is the chained `.toString(enc)` on a
// digest's return value, which stays on the consumer's module: a contract's
// return type is not propagated to a receiver, the same limit measured across
// every Node family. The WordArray entries below are correct and inert until
// that lands -- and this library is where it would pay most, because
// `CryptoJS.SHA256(m).toString(CryptoJS.enc.Hex)` is how essentially every
// consumer writes a digest.
func TestLoadEmbeddedNodeCryptoJs(t *testing.T) {
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
		// The two measured to join.
		{"crypto-js.AES.encrypt", 2, "crypto-js.CipherParams"},
		{"crypto-js.HmacSHA256", 2, "crypto-js.WordArray"},

		// THE HASHES RETURN A WordArray, NOT A STRING. That is the single most
		// useful thing this KB types: the digest call is almost always followed
		// by `.toString(enc)` on its result.
		{"crypto-js.SHA256", 1, "crypto-js.WordArray"},
		{"crypto-js.MD5", 1, "crypto-js.WordArray"},
		{"crypto-js.SHA1", 1, "crypto-js.WordArray"},
		{"crypto-js.RIPEMD160", 1, "crypto-js.WordArray"},

		// encrypt returns CipherParams and decrypt returns a WordArray -- which
		// is why `AES.encrypt(..).toString()` works and why the result can be
		// handed straight back to decrypt.
		{"crypto-js.AES.decrypt", 2, "crypto-js.WordArray"},
		{"crypto-js.TripleDES.encrypt", 2, "crypto-js.CipherParams"},
		{"crypto-js.RC4.encrypt", 2, "crypto-js.CipherParams"},
		{"crypto-js.Blowfish.decrypt", 3, "crypto-js.WordArray"},

		{"crypto-js.PBKDF2", 3, "crypto-js.WordArray"},
		{"crypto-js.EvpKDF", 2, "crypto-js.WordArray"},

		// The exit points that close the chain.
		{"crypto-js.WordArray.toString", 1, "string"},
		{"crypto-js.CipherParams.toString", 0, "string"},
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
		{"crypto-js.SHA256", 3},
		{"crypto-js.AES.encrypt", 1},
		{"crypto-js.HmacSHA256", 1},
	} {
		if got := kb.ContractsFor(bogus.method, bogus.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) resolved %d contracts; that arity does not exist", bogus.method, bogus.arity, len(got))
		}
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "crypto-js.") {
			n++
		}
	}
	if n != 64 {
		t.Errorf("crypto-js contributes %d keys, want 64", n)
	}
}
