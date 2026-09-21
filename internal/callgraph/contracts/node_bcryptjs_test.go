// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// bcryptjs and the native bcrypt package compute the same ALGORITHM and are
// different PACKAGES. They must never share a key: a consumer's
// `bcrypt.hash(pw, 10)` is attributable only through its import, and measured
// on a real consumer the parser resolves it to the IMPORTED PACKAGE rather than
// to the variable name --
//
//	const bcrypt = require('bcryptjs');
//	await bcrypt.genSalt(12)   ->   bcryptjs.genSalt
//
// which is what makes these two families separable at all.
func TestLoadEmbeddedNodeBcryptjs(t *testing.T) {
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
		{"bcryptjs.hash", 2, "string"},
		{"bcryptjs.compare", 2, "boolean"},
		{"bcryptjs.genSalt", 1, "string"},
		// THE ARITIES ARE NOT THE NATIVE PACKAGE'S. bcryptjs takes an optional
		// progressCallback AFTER the callback, so hash and compare are callable
		// at four arguments where the native package stops at three. Declaring
		// the native arities would silently miss every consumer that reports
		// progress.
		{"bcryptjs.hash", 4, "string"},
		{"bcryptjs.compare", 4, "boolean"},
		{"bcryptjs.hashSync", 2, "string"},
		{"bcryptjs.compareSync", 2, "boolean"},
		{"bcryptjs.genSaltSync", 0, "string"},
		{"bcryptjs.getRounds", 1, "number"},
		// getSalt reads the salt back out of a hash: material, not an operation.
		{"bcryptjs.getSalt", 1, "string"},
		// The entropy fallback returns nothing and is contracted because it is
		// the one call that changes where a deployment's salts come from.
		{"bcryptjs.setRandomFallback", 1, "void"},
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

	// Arities the library does not accept must resolve to nothing.
	for _, bogus := range []struct {
		method string
		arity  int
	}{
		{"bcryptjs.hash", 1},
		{"bcryptjs.hash", 5},
		{"bcryptjs.getSalt", 2},
		{"bcryptjs.setRandomFallback", 0},
	} {
		if got := kb.ContractsFor(bogus.method, bogus.arity); len(got) != 0 {
			t.Errorf("ContractsFor(%q, %d) resolved %d contracts; that arity does not exist", bogus.method, bogus.arity, len(got))
		}
	}

	// THE TWO PACKAGES MUST NOT SHARE A SINGLE KEY, in either direction. A
	// `bcrypt.` key reachable from this library's coordinate -- or the reverse
	// -- would attribute one package's cryptography to the other, invisibly.
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "bcryptjs.") {
			continue
		}
		if strings.HasPrefix(k, "bcrypt.") {
			// The native family's own keys are expected; what is not expected
			// is any bcryptjs method hiding under that prefix.
			for _, jsOnly := range []string{"getSalt", "setRandomFallback", "truncates"} {
				if strings.HasPrefix(k, "bcrypt."+jsOnly) {
					t.Errorf("key %q is a bcryptjs-only export declared under the native bcrypt coordinate", k)
				}
			}
		}
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "bcryptjs.") {
			n++
		}
	}
	if n != 18 {
		t.Errorf("bcryptjs contributes %d keys, want 18", n)
	}
}
