// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// js-sha256 exports something that is a function AND an object, and this KB has
// to type both faces. `sha256(msg)` is one shot; `sha256.create().update(m).hex()`
// is a chain. The one-shot needs no chain and the incremental form needs all of
// it, so both are declared.
func TestLoadEmbeddedNodeJsSha256(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	for _, want := range []string{
		"js-sha256.sha256#1", "js-sha256.sha224#1",
		"js-sha256.sha256.hex#1", "js-sha256.sha256.digest#1",
		"js-sha256.sha256.create#0", "js-sha256.sha224.create#0",
		"js-sha256.sha256.hmac#2", "js-sha256.sha224.hmac#2",
		"js-sha256.sha256.hmac.create#1",
		"js-sha256.Sha256.update#1", "js-sha256.HmacSha256.update#1",
	} {
		if _, ok := kb.Contracts[want]; !ok {
			t.Errorf("contract %q missing from the embedded Node KB", want)
		}
	}

	// THE ALGORITHM IS IN THE TYPE, and the two are distinct on purpose: an
	// incremental chain that began at sha224 must not be readable as a SHA-256
	// three calls later.
	for _, tc := range []struct{ factory, want string }{
		{"js-sha256.sha256.create", "js-sha256.Sha256"},
		{"js-sha256.sha224.create", "js-sha256.Sha224"},
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

	// update carries the chain: it must return the same hasher it was called on,
	// or the output method at the end resolves against nothing.
	for _, typ := range []string{"Sha256", "Sha224", "HmacSha256", "HmacSha224"} {
		got := kb.ContractsFor("js-sha256."+typ+".update", 1)
		if len(got) == 0 {
			t.Errorf("%s.update resolved nothing", typ)
			continue
		}
		if got[0].Return.Type != "js-sha256."+typ {
			t.Errorf("%s.update returns %q, want the same hasher type", typ, got[0].Return.Type)
		}
	}

	// HMAC IS A SEPARATE TYPE AND NOT A DIGEST. The same key produces and checks
	// the tag, so a chain that started at hmac must stay distinguishable from one
	// that started at the plain digest all the way to its output.
	h := kb.ContractsFor("js-sha256.sha256.hmac.create", 1)
	if len(h) == 0 {
		t.Fatal("sha256.hmac.create resolved nothing")
	}
	if h[0].Return.Type != "js-sha256.HmacSha256" {
		t.Errorf("hmac.create returns %q, want js-sha256.HmacSha256", h[0].Return.Type)
	}

	// The output methods end the chain and produce the value.
	d := kb.ContractsFor("js-sha256.Sha256.hex", 0)
	if len(d) == 0 {
		t.Fatal("Sha256.hex resolved nothing")
	}
	if d[0].Role != "output" {
		t.Errorf("Sha256.hex role = %q, want \"output\"", d[0].Role)
	}

	// toString is an alias of hex and adds no call shape a consumer writes
	// deliberately, so it is not declared.
	if _, ok := kb.Contracts["js-sha256.Sha256.toString#0"]; ok {
		t.Error("toString is an alias of hex and must not be declared")
	}

	if got := kb.ContractsFor("js-sha256.sha256", 7); len(got) != 0 {
		t.Errorf("ContractsFor(sha256, 7) resolved %d contracts; that arity does not exist", len(got))
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "js-sha256.") {
			n++
		}
	}
	if n != 46 {
		t.Errorf("js-sha256 contributes %d keys, want 46", n)
	}
}
