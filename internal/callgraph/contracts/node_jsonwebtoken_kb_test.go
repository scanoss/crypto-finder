// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// Three functions, and the whole value of this KB is that one of them is not
// what its name suggests.
func TestLoadEmbeddedNodeJsonWebToken(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("node")
	if err != nil {
		t.Fatalf("LoadEmbedded(node): %v", err)
	}

	for _, want := range []string{
		"jsonwebtoken.sign#2", "jsonwebtoken.sign#3", "jsonwebtoken.sign#4",
		"jsonwebtoken.verify#2", "jsonwebtoken.verify#3", "jsonwebtoken.verify#4",
		"jsonwebtoken.decode#1", "jsonwebtoken.decode#2",
	} {
		if _, ok := kb.Contracts[want]; !ok {
			t.Errorf("contract %q missing from the embedded Node KB", want)
		}
	}

	// DECODE IS NOT VERIFY, and in a 16-consumer draw it is the MOST COMMON
	// jsonwebtoken call. It base64-decodes the claims and checks no signature.
	// If this assertion ever fails, the finder has started recording the most
	// frequent call in this ecosystem as a security control.
	for _, arity := range []int{1, 2} {
		got := kb.ContractsFor("jsonwebtoken.decode", arity)
		if len(got) == 0 {
			t.Errorf("decode#%d resolved nothing", arity)
			continue
		}
		if got[0].Role != "output" {
			t.Errorf("decode#%d role = %q, want \"output\": it decodes without verifying", arity, got[0].Role)
		}
	}

	// sign and verify are the operations.
	for _, m := range []string{"jsonwebtoken.sign", "jsonwebtoken.verify"} {
		for _, arity := range []int{2, 3} {
			got := kb.ContractsFor(m, arity)
			if len(got) == 0 {
				t.Errorf("%s#%d resolved nothing", m, arity)
				continue
			}
			if got[0].Role != "operation" {
				t.Errorf("%s#%d role = %q, want \"operation\"", m, arity, got[0].Role)
			}
		}
	}

	// ARITY 2 IS DECLARED SEPARATELY AND ON PURPOSE. sign.js line 98 reads
	// `alg: options.algorithm || 'HS256'`, so a two-argument sign is an
	// HMAC-SHA-256 with a shared secret. The rules read that; the KB has to
	// keep the arity distinguishable for them to.
	if got := kb.ContractsFor("jsonwebtoken.sign", 2); len(got) == 0 {
		t.Error("sign#2 resolved nothing; the no-options form is the HS256 default case")
	}
	if got := kb.ContractsFor("jsonwebtoken.sign", 1); len(got) != 0 {
		t.Error("sign#1 resolved; jsonwebtoken requires at least a payload and a key")
	}

	// The crowded JWT ecosystem: jose and fast-jwt sign the same JWA identifiers
	// at their own coordinates. What must never happen is jsonwebtoken's own
	// surface being authored under one of theirs.
	for _, foreign := range []string{"jose.", "fast-jwt."} {
		for _, own := range []string{"sign", "verify", "decode"} {
			for arity := 0; arity <= 4; arity++ {
				if got := kb.ContractsFor(foreign+own, arity); len(got) != 0 {
					t.Errorf("jsonwebtoken's %s is declared under %s, a different package", own, foreign)
				}
			}
		}
	}

	// Error classes report failures and compute nothing.
	for _, unwanted := range []string{
		"jsonwebtoken.JsonWebTokenError.<init>#1",
		"jsonwebtoken.TokenExpiredError.<init>#2",
	} {
		if _, ok := kb.Contracts[unwanted]; ok {
			t.Errorf("contract %q computes nothing and must not be declared", unwanted)
		}
	}

	n := 0
	for k := range kb.Contracts {
		if strings.HasPrefix(k, "jsonwebtoken.") {
			n++
		}
	}
	if n != 8 {
		t.Errorf("jsonwebtoken contributes %d keys, want 8", n)
	}
}
