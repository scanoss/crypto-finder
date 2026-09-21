// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// jwa is the smallest shape a crypto library can have: the module export is the
// function, and the object it returns has exactly two methods. Three entries,
// and each is load-bearing.
func TestLoadEmbeddedNodeJwa(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	// THE EXPORT ITSELF IS CALLABLE. `jwa#1` is not a method on a namespace --
	// it is the module. If this key ever loses its return type the two methods
	// below become unreachable and the family resolves nothing.
	f := kb.ContractsFor("jwa", 1)
	if len(f) == 0 {
		t.Fatal("the jwa factory resolved nothing; the module export is the function")
	}
	if f[0].Return.Type != "jwa.Algorithm" {
		t.Errorf("jwa(alg) returns %q, want jwa.Algorithm", f[0].Return.Type)
	}
	if f[0].Role != "factory" {
		t.Errorf("jwa(alg) role = %q, want \"factory\": it selects an algorithm, it computes nothing", f[0].Role)
	}

	// ONE Algorithm TYPE, NOT THIRTEEN, and that is forced by the shape rather
	// than chosen for brevity: `jwa(alg)` with a variable is a real call two
	// drawn consumers write, and a per-algorithm type could not resolve it.
	// Reading the literal is the rules' job. This is the opposite of the
	// js-sha3 KB, where the algorithm IS the type.
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "jwa.") && strings.Contains(k, "HS256") {
			t.Errorf("key %q types a specific algorithm; jwa carries it in an argument, not a type", k)
		}
	}

	for _, tc := range []struct {
		method string
		arity  int
	}{
		{"jwa.Algorithm.sign", 2},
		{"jwa.Algorithm.verify", 3},
	} {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) == 0 {
			t.Errorf("%s#%d resolved nothing", tc.method, tc.arity)
			continue
		}
		if got[0].Role != "operation" {
			t.Errorf("%s role = %q, want \"operation\"", tc.method, got[0].Role)
		}
	}

	// verify takes (input, signature, key): three arguments, not two. An arity
	// the library does not accept must resolve to nothing.
	if got := kb.ContractsFor("jwa.Algorithm.verify", 2); len(got) != 0 {
		t.Error("verify#2 resolved; jwa.verify takes input, signature and key")
	}

	n := 0
	for k := range kb.Contracts {
		if k == "jwa#1" || strings.HasPrefix(k, "jwa.") {
			n++
		}
	}
	if n != 3 {
		t.Errorf("jwa contributes %d keys, want 3", n)
	}
}
