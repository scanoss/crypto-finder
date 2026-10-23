// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Each OTP function takes a single options object.
func TestLoadEmbeddedNodeSpeakeasy(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	type want struct {
		method string
		arity  int
		typ    string
		role   string
	}
	for _, w := range []want{
		{"speakeasy.totp", 1, "builtins.string", "operation"},
		{"speakeasy.hotp.verifyDelta", 1, "speakeasy.Delta", "operation"},
		{"speakeasy.digest", 1, "builtins.bytes", "operation"},
		{"speakeasy.generateSecret", 0, "speakeasy.GeneratedSecret", "operation"},
		{"speakeasy.generate_key_ascii", 2, "builtins.string", "operation"},
	} {
		got := kb.ContractsFor(w.method, w.arity)
		if len(got) == 0 {
			t.Errorf("%s#%d resolved nothing", w.method, w.arity)
			continue
		}
		if got[0].Return.Type != w.typ || got[0].Role != w.role {
			t.Errorf("%s#%d = (%q, %q), want (%q, %q)", w.method, w.arity, got[0].Return.Type, got[0].Role, w.typ, w.role)
		}
	}

	for _, unwanted := range []string{
		"speakeasy.totp#2",
		"speakeasy.otpauthURL#1",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q must not be declared", unwanted)
		}
	}

	assertLibraryOwnsItsKeys(t, kb, "speakeasy", "speakeasy.")

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "speakeasy.") {
			n++
		}
	}
	if n != 17 {
		t.Errorf("speakeasy contributes %d keys, want 17", n)
	}
}
