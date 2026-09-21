// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// bcrypt is the case @azure/keyvault-keys is not: its whole surface is seven
// MODULE-LEVEL functions, so a consumer writes `bcrypt.hash(pw, 10)` and the
// parser emits `bcrypt.hash` -- the library coordinate, measured, which is
// exactly the key declared below. The azure KB could not join because its API
// is reached through a client instance whose type is never resolved.
//
// What a local scan still cannot show for THIS library is a difference in the
// export with and without the KB, and that is a property of bcrypt rather than
// a defect: every function returns a string, a boolean or a number, so there is
// no chained receiver for a return type to resolve. Measured -- the two exports
// are byte-identical but for their timestamp. The KB is what makes each rule's
// `api` joinable (gate 12) and what the mining path synthesizes entry points
// from.
func TestLoadEmbeddedNodeBcrypt(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	// Arity is part of the key, and the arities come from the library's own
	// bcrypt.js: each async function takes an optional Node-style callback and
	// returns a promise without it, so it carries one more arity than its sync
	// twin.
	for _, tc := range []struct {
		method string
		arity  int
		want   string
	}{
		// The three shapes the parser was measured to emit for real consumer code.
		{"bcrypt.hash", 2, "string"},
		{"bcrypt.compare", 2, "boolean"},
		{"bcrypt.genSalt", 1, "string"},
		// Callback spellings of the same three.
		{"bcrypt.hash", 3, "string"},
		{"bcrypt.compare", 3, "boolean"},
		{"bcrypt.genSalt", 2, "string"},
		// The sync twins are separate exports, not aliases: a KB that declared
		// only the async form would leave hashSync uncataloged.
		{"bcrypt.hashSync", 2, "string"},
		{"bcrypt.compareSync", 2, "boolean"},
		{"bcrypt.genSaltSync", 1, "string"},
		// genSaltSync() with no argument is valid and defaults to 10 rounds.
		{"bcrypt.genSaltSync", 0, "string"},
		{"bcrypt.getRounds", 1, "number"},
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
	// types a call that cannot run. hash() has no one-argument form: the
	// password alone is not enough, a salt or a cost is required.
	for _, bogus := range []struct {
		method string
		arity  int
	}{
		{"bcrypt.hash", 1},
		{"bcrypt.hash", 9},
		{"bcrypt.compareSync", 3},
		{"bcrypt.getRounds", 2},
	} {
		if got := kb.ContractsFor(bogus.method, bogus.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) resolved %d contracts; that arity does not exist", bogus.method, bogus.arity, len(got))
		}
	}

	// bcryptjs is a DIFFERENT package and its own Tier 0 family, and it ships
	// in this same Node KB. Its keys are expected here; what must never happen
	// is one of its exports appearing under THIS coordinate, which would
	// attribute one package's cryptography to the other invisibly.
	//
	// The first version of this assertion forbade every "bcryptjs." key in the
	// whole KB, which was true only while that family did not exist and turned
	// red the moment it landed. The property worth pinning is per-coordinate,
	// not KB-wide.
	for _, jsOnly := range []string{"getSalt", "setRandomFallback", "truncates"} {
		for k := range kb.Contracts {
			if strings.HasPrefix(k, "bcrypt."+jsOnly) {
				t.Errorf("key %q is a bcryptjs-only export declared under the native bcrypt coordinate", k)
			}
		}
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "bcrypt.") {
			n++
		}
	}
	if n != 14 {
		t.Errorf("bcrypt contributes %d keys, want 14", n)
	}
}
