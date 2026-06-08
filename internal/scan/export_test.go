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

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// TestInferMatchedOperationKind covers the api-free precedence table and the
// glob-mismatch regression that motivated this change.
//
// Task 3.1 (Strict TDD RED test): must fail until Task 3.2 rewrites the
// function to accept only a single expression parameter.
func TestInferMatchedOperationKind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		expression string
		want       string
	}{
		{
			name:       "constructor invocation → call",
			expression: "new SHA3Digest(256)",
			want:       "call",
		},
		{
			name:       "fluent chain (invocation syntax) → call",
			expression: "Password.hash(p).withBcrypt()",
			want:       "call",
		},
		{
			name:       "bare type reference → type_usage",
			expression: "SHA3Digest",
			want:       "type_usage",
		},
		{
			name:       "dotted bare type → type_usage",
			expression: "javax.crypto.Cipher",
			want:       "type_usage",
		},
		{
			name:       "hyphenated string → expression",
			expression: "AES-256",
			want:       "expression",
		},
		{
			// REGRESSION: the old implementation would receive symbol=
			// "com.password4j.HashBuilder.with*" and expression=
			// "Password.hash(p).withBcrypt()"; the symbol lookup would hit the
			// default branch and return "expression" even though the source text
			// clearly contains an invocation. The new implementation never
			// consults the api/symbol string — source text is the only signal.
			name:       "glob-mismatch regression: fluent call with non-matching api → still call",
			expression: "Password.hash(p).withBcrypt()",
			want:       "call",
		},
		{
			name:       "empty expression → expression",
			expression: "",
			want:       "expression",
		},
		{
			name:       "simple method call → call",
			expression: "Cipher.getInstance(\"AES\")",
			want:       "call",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// New signature: inferMatchedOperationKind(expression string) string
			got := inferMatchedOperationKind(tt.expression)
			if got != tt.want {
				t.Errorf("inferMatchedOperationKind(%q) = %q, want %q", tt.expression, got, tt.want)
			}
		})
	}
}

// TestFindCryptoCallNode covers the position-based selection algorithm:
// column intersection, chain-root tie-break, columns-absent fallback, and the
// terminal-is-root regression that protects supporting-call derivation.
//
// Task 4.1 (Strict TDD RED test): must fail until Task 4.3 rewrites
// findCryptoCallNode with column-aware logic.
func TestFindCryptoCallNode(t *testing.T) {
	t.Parallel()

	// Helper to build a minimal graph with no resolved functions.
	emptyGraph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{},
	}

	t.Run("two calls on one line - column span selects second", func(t *testing.T) {
		// Line 5: callA at [1,15) and callB at [20,35).
		// Asset span is [20,35) — intersects only callB.
		callA := callgraph.FunctionCall{
			Callee:   callgraph.FunctionID{Type: "Foo", Name: "methodA#0"},
			Line:     5,
			StartCol: 1,
			EndCol:   15,
			Raw:      "foo.methodA()",
		}
		callB := callgraph.FunctionCall{
			Callee:   callgraph.FunctionID{Type: "Bar", Name: "methodB#0"},
			Line:     5,
			StartCol: 20,
			EndCol:   35,
			Raw:      "bar.methodB()",
		}
		fn := &callgraph.FunctionDecl{
			Calls: []callgraph.FunctionCall{callA, callB},
		}
		asset := entities.CryptographicAsset{
			StartLine: 5,
			EndLine:   5,
			StartCol:  20,
			EndCol:    35,
		}

		got := findCryptoCallNode(emptyGraph, fn, asset, 5, 5)
		if got == nil {
			t.Fatal("findCryptoCallNode returned nil, want callB")
		}
		if got.Callee.Name != "methodB#0" {
			t.Errorf("selected call = %q, want %q", got.Callee.Name, "methodB#0")
		}
	})

	t.Run("whole-chain span selects chain ROOT (AssignedVar set)", func(t *testing.T) {
		// Line 6: a 3-link fluent chain. The root is the one with AssignedVar set.
		// All three share ChainID "chain-1". Asset spans the entire line [1,50).
		chainRoot := callgraph.FunctionCall{
			Callee:      callgraph.FunctionID{Type: "HashBuilder", Name: "withBcrypt#0"},
			ChainID:     "chain-1",
			AssignedVar: "hash",
			Line:        6,
			StartCol:    1,
			EndCol:      50,
			Raw:         "Password.hash(p).addRandomSalt().withBcrypt()",
		}
		chainLink1 := callgraph.FunctionCall{
			Callee:   callgraph.FunctionID{Type: "Password", Name: "hash#1"},
			ChainID:  "chain-1",
			Line:     6,
			StartCol: 1,
			EndCol:   20,
			Raw:      "Password.hash(p)",
		}
		chainLink2 := callgraph.FunctionCall{
			Callee:   callgraph.FunctionID{Type: "HashBuilder", Name: "addRandomSalt#0"},
			ChainID:  "chain-1",
			Line:     6,
			StartCol: 1,
			EndCol:   35,
			Raw:      "Password.hash(p).addRandomSalt()",
		}
		fn := &callgraph.FunctionDecl{
			Calls: []callgraph.FunctionCall{chainLink1, chainLink2, chainRoot},
		}
		asset := entities.CryptographicAsset{
			StartLine: 6,
			EndLine:   6,
			StartCol:  1,
			EndCol:    50,
		}

		got := findCryptoCallNode(emptyGraph, fn, asset, 6, 6)
		if got == nil {
			t.Fatal("findCryptoCallNode returned nil, want chainRoot")
		}
		if got.AssignedVar != "hash" {
			t.Errorf("selected call AssignedVar = %q, want %q; Callee = %q",
				got.AssignedVar, "hash", got.Callee.Name)
		}
	})

	t.Run("columns absent (0) - line-only fallback does not panic", func(t *testing.T) {
		// No column info on either the asset or the call; expect line-only best-effort.
		call := callgraph.FunctionCall{
			Callee: callgraph.FunctionID{Type: "Cipher", Name: "getInstance#1"},
			Line:   10,
			// StartCol and EndCol deliberately left at 0 (no column info)
			Raw: "Cipher.getInstance(\"AES\")",
		}
		fn := &callgraph.FunctionDecl{
			Calls: []callgraph.FunctionCall{call},
		}
		asset := entities.CryptographicAsset{
			StartLine: 10,
			EndLine:   10,
			// StartCol and EndCol deliberately 0
		}

		got := findCryptoCallNode(emptyGraph, fn, asset, 10, 10)
		if got == nil {
			t.Error("findCryptoCallNode returned nil on column-absent input, want non-nil")
		}
	})

	t.Run("terminal-is-root regression: fluent chain root returned; supporting calls non-empty", func(t *testing.T) {
		// Mirrors the Password4J pattern from be9083e6.
		// findCryptoCallNode MUST return the chain root (AssignedVar="hash")
		// so that deriveObjectLifecycleCalls can enumerate the chain links.
		hashID := callgraph.FunctionID{Type: "Password", Name: "hash#1"}
		saltID := callgraph.FunctionID{Type: "HashBuilder", Name: "addRandomSalt#0"}
		bcryptID := callgraph.FunctionID{Type: "HashBuilder", Name: "withBcrypt#0"}
		getResultID := callgraph.FunctionID{Type: "Hash", Name: "getResult#0"}

		fn := &callgraph.FunctionDecl{
			ID: callgraph.FunctionID{Package: "com.example", Type: "Service", Name: "run#0"},
			Calls: []callgraph.FunctionCall{
				{Callee: hashID, ChainID: "c1", Line: 6, StartCol: 1, EndCol: 20, Raw: "Password.hash(p)"},
				{Callee: saltID, ChainID: "c1", Line: 6, StartCol: 1, EndCol: 35, Raw: "Password.hash(p).addRandomSalt()"},
				{
					Callee: bcryptID, ChainID: "c1", AssignedVar: "hash", Line: 6, StartCol: 1, EndCol: 50,
					Raw: "Password.hash(p).addRandomSalt().withBcrypt()",
				},
				{Callee: getResultID, ReceiverVar: "hash", Line: 7, StartCol: 1, EndCol: 20, Raw: "hash.getResult()"},
			},
		}
		asset := entities.CryptographicAsset{
			StartLine: 6,
			EndLine:   6,
			StartCol:  1,
			EndCol:    50,
		}

		terminal := findCryptoCallNode(emptyGraph, fn, asset, 6, 6)
		if terminal == nil {
			t.Fatal("findCryptoCallNode returned nil")
		}
		if terminal.AssignedVar == "" {
			t.Errorf("terminal is not the chain root: AssignedVar is empty; Callee = %q (want withBcrypt root)", terminal.Callee.Name)
		}

		// Now verify supporting calls are non-empty (regression guard for be9083e6).
		supporting := deriveObjectLifecycleCalls(fn, terminal)
		if len(supporting) == 0 {
			t.Error("deriveObjectLifecycleCalls returned empty slice; supporting-call derivation broken for fluent chain")
		}
	})
}

// TestBestChainRootCandidate isolates the chain-root tie-break (step 3a): only
// chain candidates with AssignedVar set are eligible, non-chain candidates are
// ignored, and ties between multiple chain roots resolve to the lowest StartCol.
func TestBestChainRootCandidate(t *testing.T) {
	t.Parallel()

	t.Run("no chain candidate carries AssignedVar - returns nil", func(t *testing.T) {
		candidates := []*callgraph.FunctionCall{
			{ChainID: "c1", StartCol: 1, Raw: "a()"},                 // chain link, no AssignedVar
			{ChainID: "", AssignedVar: "x", StartCol: 2, Raw: "b()"}, // non-chain, ignored
		}
		if got := bestChainRootCandidate(candidates); got != nil {
			t.Errorf("got %q, want nil (no eligible chain root)", got.Raw)
		}
	})

	t.Run("picks the chain candidate with AssignedVar", func(t *testing.T) {
		root := &callgraph.FunctionCall{ChainID: "c1", AssignedVar: "hash", StartCol: 1, Raw: "root()"}
		candidates := []*callgraph.FunctionCall{
			{ChainID: "c1", StartCol: 1, Raw: "link()"},
			root,
		}
		if got := bestChainRootCandidate(candidates); got != root {
			t.Errorf("got %v, want the AssignedVar-bearing root", got)
		}
	})

	t.Run("multiple chain roots - lowest StartCol wins", func(t *testing.T) {
		low := &callgraph.FunctionCall{ChainID: "c1", AssignedVar: "a", StartCol: 5, Raw: "low()"}
		high := &callgraph.FunctionCall{ChainID: "c2", AssignedVar: "b", StartCol: 12, Raw: "high()"}
		candidates := []*callgraph.FunctionCall{high, low}
		if got := bestChainRootCandidate(candidates); got != low {
			t.Errorf("got StartCol=%d, want StartCol=5 (lowest)", got.StartCol)
		}
	})
}

// TestLongestChainCandidate isolates the longest-Raw fallback (step 3a fallback):
// used when no chain candidate carries AssignedVar. Non-chain candidates are
// ignored; among chain candidates the longest Raw (outermost expression) wins.
func TestLongestChainCandidate(t *testing.T) {
	t.Parallel()

	t.Run("no chain candidates - returns nil", func(t *testing.T) {
		candidates := []*callgraph.FunctionCall{
			{ChainID: "", Raw: "standalone()"},
		}
		if got := longestChainCandidate(candidates); got != nil {
			t.Errorf("got %q, want nil (no chain candidates)", got.Raw)
		}
	})

	t.Run("longest Raw among chain links wins", func(t *testing.T) {
		outer := &callgraph.FunctionCall{ChainID: "c1", Raw: "Password.hash(p).addRandomSalt().withBcrypt()"}
		candidates := []*callgraph.FunctionCall{
			{ChainID: "c1", Raw: "Password.hash(p)"},
			{ChainID: "", Raw: "this.is.a.very.long.non.chain.call.that.should.be.ignored()"},
			outer,
		}
		if got := longestChainCandidate(candidates); got != outer {
			t.Errorf("got %q, want the outermost chain link", got.Raw)
		}
	})
}

// TestBestScoredCandidate isolates the non-chain scoring path (step 3b/3c):
// resolved callee (+4) dominates args (+2) and sources (+1); a score tie resolves
// to the lowest non-zero StartCol; and a nil graph must not panic.
func TestBestScoredCandidate(t *testing.T) {
	t.Parallel()

	resolvedID := callgraph.FunctionID{Type: "Resolved", Name: "m#0"}
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			resolvedID.String(): {ID: resolvedID},
		},
	}

	t.Run("resolved callee outranks args+sources", func(t *testing.T) {
		resolved := &callgraph.FunctionCall{Callee: resolvedID, StartCol: 30, Raw: "resolved()"}
		richUnresolved := &callgraph.FunctionCall{
			Callee:          callgraph.FunctionID{Type: "Unknown", Name: "m#2"},
			Arguments:       []string{"a", "b"},
			ArgumentSources: [][]callgraph.SourceNode{{}},
			StartCol:        10,
			Raw:             "unknown(a, b)",
		}
		candidates := []*callgraph.FunctionCall{richUnresolved, resolved}
		if got := bestScoredCandidate(graph, candidates); got != resolved {
			t.Errorf("got %q, want the resolved callee (score 4 beats 2+1)", got.Raw)
		}
	})

	t.Run("score tie - lowest StartCol wins", func(t *testing.T) {
		left := &callgraph.FunctionCall{Callee: callgraph.FunctionID{Type: "A", Name: "m#0"}, StartCol: 8, Raw: "a()"}
		right := &callgraph.FunctionCall{Callee: callgraph.FunctionID{Type: "B", Name: "m#0"}, StartCol: 3, Raw: "b()"}
		candidates := []*callgraph.FunctionCall{left, right}
		if got := bestScoredCandidate(graph, candidates); got != right {
			t.Errorf("got StartCol=%d, want StartCol=3 (lowest on a score tie)", got.StartCol)
		}
	})

	t.Run("nil graph does not panic", func(t *testing.T) {
		candidates := []*callgraph.FunctionCall{
			{Callee: resolvedID, Arguments: []string{"x"}, StartCol: 1, Raw: "x()"},
		}
		if got := bestScoredCandidate(nil, candidates); got == nil {
			t.Error("bestScoredCandidate(nil, ...) returned nil, want the single candidate")
		}
	})
}

func TestBuildCryptoEntryPointsPropagatesSupportingCallsThroughChains(t *testing.T) {
	t.Parallel()

	entry := callGraphChainNode{FunctionKey: "com.acme.Api.entry#0", FunctionName: "com.acme.Api.entry"}
	terminal := callGraphChainNode{FunctionKey: "com.acme.Service.hash#1", FunctionName: "com.acme.Service.hash"}
	points := buildCryptoEntryPoints(
		[]callGraphExportFinding{{
			FindingID: "finding-1",
			MatchedOperation: &callGraphMatchedOperation{
				Kind:   matchedOperationCall,
				Symbol: "com.password4j.Hash.withBcrypt",
				Line:   42,
			},
			SupportingCallIDs: []string{"support-1"},
			CallChains:        [][]callGraphChainNode{{entry, terminal}},
		}},
		[]callGraphSupportingCall{{
			SupportingID: "support-1",
			FunctionKey:  terminal.FunctionKey,
			FunctionName: terminal.FunctionName,
		}},
	)

	entryPoint := findCryptoEntryPointByFunctionKey(points, entry.FunctionKey)
	if entryPoint == nil {
		t.Fatalf("missing entry point %q: %#v", entry.FunctionKey, points)
	}
	if len(entryPoint.ReachableSupportingCalls) != 1 {
		t.Fatalf("entry reachable_supporting_calls = %#v, want support-1", entryPoint.ReachableSupportingCalls)
	}
	if got := entryPoint.ReachableSupportingCalls[0]; got.SupportingID != "support-1" || got.ChainDepth != 2 {
		t.Fatalf("entry reachable_supporting_calls[0] = %#v, want support-1 at depth 2", got)
	}
}

func findCryptoEntryPointByFunctionKey(points []callGraphCryptoEntryPoint, key string) *callGraphCryptoEntryPoint {
	for i := range points {
		if points[i].FunctionKey == key {
			return &points[i]
		}
	}
	return nil
}
