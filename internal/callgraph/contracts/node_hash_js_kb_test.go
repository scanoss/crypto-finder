// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// hash.js is the first Node family in this campaign whose KB is mostly about a
// CHAIN rather than a call. `hash.sha256().update(msg).digest("hex")` is three
// calls and only the first names the algorithm, so what this test pins is that
// the middle link carries the type forward. If `update` ever loses its return
// type the chain breaks at the second call and `digest` resolves against
// nothing -- a failure that produces no error anywhere, just a quieter report.
func TestLoadEmbeddedNodeHashJS(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	// The six factories are what name the algorithm. Everything else in this
	// KB is reachable only through them.
	for _, want := range []string{
		"hash.js.sha1#0", "hash.js.sha224#0", "hash.js.sha256#0",
		"hash.js.sha384#0", "hash.js.sha512#0", "hash.js.ripemd160#0",
		// update takes (msg) or (msg, enc); digest takes () or (enc). Both
		// spellings of each are in the drawn consumers.
		"hash.js.SHA256.update#1", "hash.js.SHA256.update#2",
		"hash.js.SHA256.digest#0", "hash.js.SHA256.digest#1",
		"hash.js.hmac#2", "hash.js.hmac#3",
		"hash.js.Hmac.update#1", "hash.js.Hmac.digest#1",
	} {
		if _, ok := kb.Contracts[want]; !ok {
			t.Errorf("contract %q missing from the embedded Node KB", want)
		}
	}

	// THE ALGORITHM IS IN THE TYPE, and each of the six is distinct. A single
	// shared Hasher type would have been shorter and would have erased the one
	// thing worth knowing -- a chain that starts at sha512 must not be
	// readable as a SHA-256.
	for _, tc := range []struct{ factory, want string }{
		{"hash.js.sha1", "hash.js.SHA1"},
		{"hash.js.sha224", "hash.js.SHA224"},
		{"hash.js.sha256", "hash.js.SHA256"},
		{"hash.js.sha384", "hash.js.SHA384"},
		{"hash.js.sha512", "hash.js.SHA512"},
		{"hash.js.ripemd160", "hash.js.RIPEMD160"},
	} {
		got := kb.ContractsFor(tc.factory, 0)
		if len(got) == 0 {
			t.Errorf("ContractsFor(%q, 0) resolved nothing", tc.factory)
			continue
		}
		if got[0].Return.Type != tc.want {
			t.Errorf("%s returns %q, want %q", tc.factory, got[0].Return.Type, tc.want)
		}
	}

	// THE LINK THAT CARRIES THE CHAIN. update must return the SAME type it was
	// called on, at both arities, or `digest` at the end of the chain has no
	// receiver to resolve against.
	for _, typ := range []string{"SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "RIPEMD160", "Hmac"} {
		for _, arity := range []int{1, 2} {
			got := kb.ContractsFor("hash.js."+typ+".update", arity)
			if len(got) == 0 {
				t.Errorf("%s.update#%d resolved nothing", typ, arity)
				continue
			}
			if got[0].Return.Type != "hash.js."+typ {
				t.Errorf("%s.update#%d returns %q, want the same hasher type", typ, arity, got[0].Return.Type)
			}
		}
	}

	// digest ENDS the chain and is declared output: it produces the value, and
	// nothing further resolves from it.
	d := kb.ContractsFor("hash.js.SHA512.digest", 1)
	if len(d) == 0 {
		t.Fatal("SHA512.digest#1 resolved nothing")
	}
	if d[0].Role != "output" {
		t.Errorf("digest role = %q, want \"output\"", d[0].Role)
	}

	// Byte shuffling is deliberately uncontracted: the utils module converts
	// hex and endianness and computes nothing.
	for _, unwanted := range []string{
		"hash.js.utils.toHex#1", "hash.js.utils.toArray#2", "hash.js.utils.split32#2",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q is byte conversion and must not be declared", unwanted)
		}
	}

	if got := kb.ContractsFor("hash.js.sha256", 7); len(got) != 0 {
		t.Errorf("ContractsFor(sha256, 7) resolved %d contracts; that arity does not exist", len(got))
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "hash.js.") {
			n++
		}
	}
	if n != 36 {
		t.Errorf("hash.js contributes %d keys, want 36", n)
	}
}
