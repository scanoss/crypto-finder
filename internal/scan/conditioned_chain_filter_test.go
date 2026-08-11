// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/pkg/paramcondition"
)

// chainWith builds a two-node chain whose terminal node carries the given crypto
// call. A nil cryptoCall models a terminal whose crypto call did not resolve.
func chainWith(cryptoCall *callGraphCalledFunction) []callGraphChainNode {
	return []callGraphChainNode{
		{FunctionKey: "com.example.(Caller).entry#1"},
		{FunctionKey: "com.example.(Lib).terminal#1", CryptoCall: cryptoCall},
	}
}

// resolvedCall builds a terminal crypto call whose argument 0 carries value.
// An empty value models an argument the analysis could not resolve (a field, a
// config lookup, a runtime value).
func resolvedCall(value string) *callGraphCalledFunction {
	return &callGraphCalledFunction{
		FunctionName: "javax.net.ssl.SSLContext.getInstance",
		Parameters:   []callGraphParameter{{ParameterIndex: 0, ResolvedValue: value}},
	}
}

func mustCondition(t *testing.T, raw string) paramcondition.Condition {
	t.Helper()
	c, err := paramcondition.Parse(raw)
	if err != nil {
		t.Fatalf("paramcondition.Parse(%q): %v", raw, err)
	}
	return c
}

// TestFilterConditionedCallChains_UndecidableNeverZeroesReachability pins the
// reachability invariant: when NO chain can answer the predicate, the finding
// keeps its chains rather than losing all its evidence.
func TestFilterConditionedCallChains_UndecidableNeverZeroesReachability(t *testing.T) {
	conditions := []paramcondition.Condition{mustCondition(t, "param[0]==TLSv1.3")}

	tests := []struct {
		name     string
		chain    []callGraphChainNode
		wantKept bool
	}{
		{
			name:     "terminal crypto call unresolved",
			chain:    chainWith(nil),
			wantKept: true,
		},
		{
			name:     "argument value unresolved (field / config lookup)",
			chain:    chainWith(resolvedCall("")),
			wantKept: true,
		},
		{
			name: "selector binds to no parameter",
			chain: chainWith(&callGraphCalledFunction{
				FunctionName: "javax.net.ssl.SSLContext.getInstance",
			}),
			wantKept: true,
		},
		{
			name:     "decidable and matching",
			chain:    chainWith(resolvedCall("TLSv1.3")),
			wantKept: true,
		},
		{
			name:     "decidable and not matching",
			chain:    chainWith(resolvedCall("SSLv3")),
			wantKept: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterConditionedCallChains([][]callGraphChainNode{tt.chain}, conditions)
			if kept := len(got) == 1; kept != tt.wantKept {
				t.Fatalf("chain kept = %v, want %v (chains=%d)", kept, tt.wantKept, len(got))
			}
		})
	}
}

// TestFilterConditionedCallChains_DecidableEvidenceFiltersStrictly pins the other
// half: once ANY chain can answer the predicate, undecidable and non-matching
// chains are dropped. This is what keeps per-call-site selector materialization
// from attributing the 128-bit variant to the 256-bit caller path.
func TestFilterConditionedCallChains_DecidableEvidenceFiltersStrictly(t *testing.T) {
	conditions := []paramcondition.Condition{mustCondition(t, "param[0]==128")}

	chains := [][]callGraphChainNode{
		chainWith(resolvedCall("128")), // applicable caller path
		chainWith(resolvedCall("256")), // different call site, must not be attributed
		chainWith(resolvedCall("")),    // undecidable, outweighed by real evidence
		chainWith(nil),                 // no crypto call, likewise outweighed
	}

	got := filterConditionedCallChains(chains, conditions)
	if len(got) != 1 {
		t.Fatalf("chains kept = %d, want 1 (only the param[0]==128 path)", len(got))
	}
	if v := got[0][len(got[0])-1].CryptoCall.Parameters[0].ResolvedValue; v != "128" {
		t.Fatalf("kept chain resolved value = %q, want \"128\"", v)
	}
}

// TestFilterConditionedCallChains_OneRefutedConditionBeatsUnknownSiblings pins
// the three-valued verdict across MULTIPLE conditions: a single condition that
// resolved and failed refutes the whole predicate, however many sibling
// conditions stayed unknown. Treating that chain as merely "undecidable" would
// let a call site the analysis positively knows does not match get attributed to
// this asset whenever no other chain happens to be decidable.
func TestFilterConditionedCallChains_OneRefutedConditionBeatsUnknownSiblings(t *testing.T) {
	conditions := []paramcondition.Condition{
		mustCondition(t, "param[0]==AES/GCM/NoPadding"),
		mustCondition(t, "param[1]==256"),
	}

	// arg 0 resolved and contradicts the predicate; arg 1 came from a config
	// value that did not resolve. This is the finding's only chain.
	chain := chainWith(&callGraphCalledFunction{
		FunctionName: "javax.crypto.Cipher.getInstance",
		Parameters: []callGraphParameter{
			{ParameterIndex: 0, ResolvedValue: "DES/ECB/PKCS5Padding"},
			{ParameterIndex: 1, ResolvedValue: ""},
		},
	})

	got := filterConditionedCallChains([][]callGraphChainNode{chain}, conditions)
	if len(got) != 0 {
		t.Fatalf("chains kept = %d, want 0 — a resolved, contradicting argument refutes the predicate", len(got))
	}
}

// TestFilterConditionedCallChains_NoConditionsIsIdentity guards the degenerate
// input: with nothing to evaluate the filter must not touch the chains.
func TestFilterConditionedCallChains_NoConditionsIsIdentity(t *testing.T) {
	chains := [][]callGraphChainNode{chainWith(nil), chainWith(resolvedCall("TLSv1.3"))}
	got := filterConditionedCallChains(chains, nil)
	if len(got) != len(chains) {
		t.Fatalf("chains kept = %d, want %d", len(got), len(chains))
	}
}

// TestFilterConditionedCallChains_EmptyChainAlwaysDropped keeps the degenerate
// case explicit: a zero-node chain carries no terminal and is never emitted.
func TestFilterConditionedCallChains_EmptyChainAlwaysDropped(t *testing.T) {
	conditions := []paramcondition.Condition{mustCondition(t, "param[0]==TLSv1.3")}
	got := filterConditionedCallChains([][]callGraphChainNode{{}}, conditions)
	if len(got) != 0 {
		t.Fatalf("empty chain kept: got %d chains, want 0", len(got))
	}
}
