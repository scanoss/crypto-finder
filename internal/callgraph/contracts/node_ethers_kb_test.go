// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// THE HASHES RETURN HEX STRINGS, NOT BYTES, and that is the one thing worth
// typing here: `keccak256(data)` produces a `0x`-prefixed string that consumers
// slice, compare and concatenate, so the return type is what keeps a
// `.slice(0, 10)` attached to the digest that produced it.
//
// `randomBytes` is the exception and returns a Uint8Array -- declaring it as a
// string alongside its neighbors would be the easy mistake.
func TestLoadEmbeddedNodeEthers(t *testing.T) {
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
		{"ethers.keccak256", 1, "string"},
		{"ethers.sha256", 1, "string"},
		{"ethers.sha512", 1, "string"},
		{"ethers.ripemd160", 1, "string"},
		{"ethers.computeHmac", 3, "string"},
		{"ethers.pbkdf2", 5, "string"},
		{"ethers.scrypt", 6, "string"},

		// The exception.
		{"ethers.randomBytes", 1, "Uint8Array"},

		{"ethers.SigningKey.<init>", 1, "ethers.SigningKey"},
		{"ethers.SigningKey.sign", 1, "ethers.Signature"},
		{"ethers.recoverAddress", 2, "string"},

		// createRandom and fromPhrase both return an HDNodeWallet: same TYPE,
		// different provenance. The rules separate them on materialSource; the
		// KB types both so a later `wallet.signMessage(..)` resolves either way.
		{"ethers.Wallet.createRandom", 0, "ethers.HDNodeWallet"},
		{"ethers.Wallet.fromPhrase", 1, "ethers.HDNodeWallet"},
		{"ethers.Wallet.signMessage", 1, "string"},
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
		{"ethers.keccak256", 2},
		{"ethers.pbkdf2", 2},
		{"ethers.SigningKey.sign", 0},
	} {
		if got := kb.ContractsFor(bogus.method, bogus.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) resolved %d contracts; that arity does not exist", bogus.method, bogus.arity, len(got))
		}
	}

	// The crowded Ethereum ecosystem: web3, @ethereumjs/util and viem expose the
	// same primitives under the same names at their own coordinates.
	// @ethereumjs/util is itself a merged family in this same Node KB, so its
	// keys are EXPECTED here -- the property worth asserting is per-coordinate,
	// not KB-wide. (The first version of this loop forbade every
	// "@ethereumjs/util." key and turned red on that family's own entries; the
	// identical mistake was made and fixed once before, on npm:bcrypt.)
	//
	// What must never happen is one of those packages' distinctive exports
	// appearing under THIS coordinate.
	for _, notOurs := range []string{"ethers.toChecksumAddress", "ethers.privateToAddress", "ethers.ecsign"} {
		for arity := 0; arity <= 4; arity++ {
			if got := kb.ContractsFor(notOurs, arity); len(got) != 0 {
				t.Errorf("%q resolved at arity %d; that export belongs to another Ethereum package", notOurs, arity)
			}
		}
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "ethers.") {
			n++
		}
	}
	if n != 27 {
		t.Errorf("ethers contributes %d keys, want 27", n)
	}
}
