// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The module export is the function and the algorithm is its first argument, so
// this KB is one factory plus the chain it opens.
func TestLoadEmbeddedNodeKeccak(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	// THE EXPORT ITSELF IS CALLABLE, at one or two arguments. Without its return
	// type the chain below is unreachable.
	for _, arity := range []int{1, 2} {
		got := kb.ContractsFor("keccak", arity)
		if len(got) == 0 {
			t.Errorf("keccak#%d resolved nothing; the module export is the function", arity)
			continue
		}
		if got[0].Return.Type != "keccak.Hash" {
			t.Errorf("keccak#%d returns %q, want keccak.Hash", arity, got[0].Return.Type)
		}
		if got[0].Role != "factory" {
			t.Errorf("keccak#%d role = %q, want \"factory\": it selects an algorithm, it computes nothing", arity, got[0].Role)
		}
	}

	// ONE Hash TYPE, NOT TEN. The algorithm arrives as a string argument, so a
	// per-algorithm type could not resolve createKeccakHash(alg) with a
	// variable. This is the jwa shape, and the opposite of js-sha3 where a
	// distinct export per algorithm makes a distinct type right.
	//
	// It follows that the KB cannot distinguish keccak256 from sha3-256 -- the
	// package's own switch separates them by a padding byte, and that lives
	// entirely in the argument string. The rules carry it.
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "keccak.") && (strings.Contains(k, "256") || strings.Contains(k, "Sha3") || strings.Contains(k, "Shake")) {
			t.Errorf("key %q types a specific algorithm; keccak carries it in an argument", k)
		}
	}

	// update carries the chain so digest has a receiver; both arities are real.
	for _, arity := range []int{1, 2} {
		got := kb.ContractsFor("keccak.Hash.update", arity)
		if len(got) == 0 {
			t.Errorf("update#%d resolved nothing", arity)
			continue
		}
		if got[0].Return.Type != "keccak.Hash" {
			t.Errorf("update#%d returns %q, want the same hasher", arity, got[0].Return.Type)
		}
	}

	// digest ends the chain and produces the value. The draw contains both
	// digest('hex') and digest().
	for _, arity := range []int{0, 1} {
		got := kb.ContractsFor("keccak.Hash.digest", arity)
		if len(got) == 0 {
			t.Errorf("digest#%d resolved nothing", arity)
			continue
		}
		if got[0].Role != "output" {
			t.Errorf("digest#%d role = %q, want \"output\"", arity, got[0].Role)
		}
	}

	// Sponge-state management computes no digest of its own.
	for _, unwanted := range []string{"keccak.Hash._resetState#0", "keccak.Hash._clone#0"} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q manages state and must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "keccak", "keccak")

	n := 0
	for k := range kb.Contracts {
		if k == "keccak#1" || k == "keccak#2" || strings.HasPrefix(k, "keccak.") {
			n++
		}
	}
	if n != 6 {
		t.Errorf("keccak contributes %d keys, want 6", n)
	}
}
