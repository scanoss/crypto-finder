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
	"bufio"
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
	"github.com/scanoss/crypto-finder/internal/engine"
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

	t.Run("nested invocation spans select the matched call", func(t *testing.T) {
		constructor := callgraph.FunctionCall{
			Callee:   callgraph.FunctionID{Type: "KeyParameter", Name: "<init>#1$byte[]"},
			Line:     5,
			StartCol: 20,
			EndCol:   38,
			Raw:      "new KeyParameter(key)",
		}
		encrypt := callgraph.FunctionCall{
			Callee:    callgraph.FunctionID{Type: "Cipher", Name: "encrypt#1$KeyParameter"},
			Line:      5,
			StartCol:  10,
			EndCol:    39,
			Raw:       "cipher.encrypt(new KeyParameter(key))",
			Arguments: []string{"new KeyParameter(key)"},
		}
		fn := &callgraph.FunctionDecl{Calls: []callgraph.FunctionCall{encrypt, constructor}}
		for _, tt := range []struct {
			name       string
			start, end int
			want       string
		}{
			{"nested constructor", 20, 38, "<init>#1$byte[]"},
			{"enclosing invocation", 10, 39, "encrypt#1$KeyParameter"},
		} {
			t.Run(tt.name, func(t *testing.T) {
				asset := entities.CryptographicAsset{
					StartLine: 5, EndLine: 5, StartCol: tt.start, EndCol: tt.end,
					Metadata: map[string]string{"api": "wrong.metadata.Api"},
				}
				got := findCryptoCallNode(emptyGraph, fn, asset, 5, 5)
				if got == nil {
					t.Fatal("findCryptoCallNode returned nil")
				}
				if got.Callee.Name != tt.want {
					t.Fatalf("selected call = %q, want %q", got.Callee.Name, tt.want)
				}
			})
		}
	})

	t.Run("fluent-chain spans preserve the chain ROOT (AssignedVar set)", func(t *testing.T) {
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
		for _, endCol := range []int{20, 50} {
			asset := entities.CryptographicAsset{StartLine: 6, EndLine: 6, StartCol: 1, EndCol: endCol}
			got := findCryptoCallNode(emptyGraph, fn, asset, 6, 6)
			if got == nil {
				t.Fatal("findCryptoCallNode returned nil, want chainRoot")
			}
			if got.AssignedVar != "hash" {
				t.Errorf("span [1,%d) selected AssignedVar = %q, want %q; Callee = %q",
					endCol, got.AssignedVar, "hash", got.Callee.Name)
			}
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
		nil,
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

// TestBuildCryptoEntryPointsPopulatesParameterRoles is the WU3 (issue-103)
// concrete target: a crypto_entry_points terminal whose function+arity
// matches a KB contract declaring parameter roles gets parameter_roles
// populated, index-aligned with parameter_types. KeyParameter.<init>(byte[])
// contributes keySize via argument_bit_length on param 0.
func TestBuildCryptoEntryPointsPopulatesParameterRoles(t *testing.T) {
	t.Parallel()

	terminal := callGraphChainNode{
		FunctionKey:    "org.bc.KeyParameter.<init>#1",
		FunctionName:   "org.bc.KeyParameter.<init>",
		ParameterTypes: []string{"byte[]"},
	}
	kb := &contracts.KnowledgeBase{
		Contracts: map[string][]contracts.Contract{
			"org.bc.KeyParameter.<init>#1": {{
				Method: "org.bc.KeyParameter.<init>",
				Arity:  1,
				Return: contracts.ContractReturn{Type: "org.bc.KeyParameter", Confidence: "high"},
				Parameters: []contracts.ParameterContract{{
					Index: intPtr(0),
					Name:  "key",
					Role:  "metadata-contributing",
					Contributes: &contracts.Contribution{
						Property:   "keySize",
						Derivation: "argument_bit_length",
					},
				}},
			}},
		},
	}
	points := buildCryptoEntryPoints(
		kb,
		[]callGraphExportFinding{{
			FindingID:        "finding-1",
			MatchedOperation: &callGraphMatchedOperation{Kind: matchedOperationCall, Symbol: "org.bc.KeyParameter.<init>", Line: 1},
			CallChains:       [][]callGraphChainNode{{terminal}},
		}},
		nil,
	)

	entryPoint := findCryptoEntryPointByFunctionKey(points, terminal.FunctionKey)
	if entryPoint == nil {
		t.Fatalf("missing entry point %q: %#v", terminal.FunctionKey, points)
	}
	if len(entryPoint.ParameterRoles) != 1 {
		t.Fatalf("ParameterRoles = %#v, want 1 entry", entryPoint.ParameterRoles)
	}
	pr := entryPoint.ParameterRoles[0]
	if pr.Index != 0 || pr.Role != "metadata-contributing" ||
		pr.Contributes == nil || pr.Contributes.Property != "keySize" || pr.Contributes.Derivation != "argument_bit_length" {
		t.Fatalf("ParameterRoles[0] = %#v, want index=0 metadata-contributing keySize/argument_bit_length", pr)
	}
}

func intPtr(i int) *int { return &i }

func TestBuildCallGraphExport_OperationContractExportsSupportingCallOnly(t *testing.T) {
	t.Parallel()

	terminalID := callgraph.FunctionID{Package: "org.bc.engines", Type: "AESEngine", Name: "<init>#0"}
	processBlockID := callgraph.FunctionID{Package: "org.bc.engines", Type: "AESEngine", Name: "processBlock#4"}
	ownerID := callgraph.FunctionID{Package: "app", Type: "App", Name: "run#0"}
	owner := &callgraph.FunctionDecl{
		ID:        ownerID,
		FilePath:  "App.java",
		StartLine: 1,
		EndLine:   20,
		Calls: []callgraph.FunctionCall{{
			Callee:      terminalID,
			AssignedVar: "engine",
			Raw:         "newEngine()",
			FilePath:    "App.java",
			Line:        10,
		}},
	}
	terminal := &callgraph.FunctionDecl{ID: terminalID, FilePath: "AESEngine.java", StartLine: 1}
	processBlock := &callgraph.FunctionDecl{ID: processBlockID, FilePath: "AESEngine.java", StartLine: 20}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		ownerID.String():        owner,
		terminalID.String():     terminal,
		processBlockID.String(): processBlock,
	}}
	kb := &contracts.KnowledgeBase{
		Contracts: map[string][]contracts.Contract{
			"org.bc.engines.AESEngine.<init>#0": {{
				Method: "org.bc.engines.AESEngine.<init>",
				Arity:  0,
				Return: contracts.ContractReturn{Type: "org.bc.engines.AESEngine", Confidence: "high"},
			}},
			"org.bouncycastle.crypto.BlockCipher.processBlock#4": {{
				Method: "org.bouncycastle.crypto.BlockCipher.processBlock",
				Arity:  4,
				Return: contracts.ContractReturn{Type: "int", Confidence: "high"},
				Role:   "operation",
			}},
		},
		Hierarchy: map[string][]string{
			"org.bc.engines.AESEngine": {"org.bouncycastle.crypto.BlockCipher"},
		},
	}
	result := &engine.DepScanResult{
		CallGraph: graph,
		Report: &entities.InterimReport{Findings: []entities.Finding{{
			FilePath: "App.java",
			CryptographicAssets: []entities.CryptographicAsset{{
				FindingID: "f1",
				StartLine: 10,
				EndLine:   10,
				Match:     "newEngine()",
				Metadata: map[string]string{
					"api":                "org.bc.engines.AESEngine.<init>",
					"algorithmFamily":    "AES",
					"algorithmPrimitive": "block-cipher",
				},
			}},
		}}},
	}

	ctx := &exportBuildContext{
		graph:                   graph,
		kb:                      kb,
		declIndex:               map[string][]*callgraph.FunctionDecl{"org.bc.engines.AESEngine.processBlock": {processBlock}},
		containingFunctionCache: make(map[string]cachedContainingFunction),
		callChainCache:          make(map[string][][]callGraphChainNode),
		callChainRemainingUses:  make(map[string]int),
	}
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	streamed, err := streamCallGraphExport(&graphFragmentJSONWriter{w: bw}, ctx, callGraphExportAssets(result.Report), buildCallGraphExportScanMeta(result))
	if err != nil {
		t.Fatal(err)
	}
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	export := callGraphExportV2{SupportingCalls: streamed.supportingCalls, CryptoEntryPoints: streamed.entryPoints}
	if err := json.Unmarshal(buf.Bytes(), &export); err != nil {
		t.Fatal(err)
	}
	var operationSupportID string
	for _, support := range export.SupportingCalls {
		if support.SupportingCall != nil && support.SupportingCall.FunctionName == "org.bc.engines.AESEngine.processBlock" {
			operationSupportID = support.SupportingID
			if support.Category != "operation" {
				t.Fatalf("operation supporting category = %q, want operation", support.Category)
			}
		}
	}
	if operationSupportID == "" {
		t.Fatalf("missing concrete operation supporting call: %#v", export.SupportingCalls)
	}
	if len(export.FindingGraphs) != 1 {
		t.Fatalf("finding_graphs = %#v, want 1", export.FindingGraphs)
	}
	foundID := false
	for _, id := range export.FindingGraphs[0].SupportingCallIDs {
		if id == operationSupportID {
			foundID = true
		}
	}
	if !foundID {
		t.Fatalf("finding supporting_call_ids = %#v, want %q", export.FindingGraphs[0].SupportingCallIDs, operationSupportID)
	}
	for _, entry := range export.CryptoEntryPoints {
		if entry.FunctionName == "org.bc.engines.AESEngine.processBlock" {
			t.Fatalf("operation method exported as crypto_entry_point: %#v", entry)
		}
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

func TestDeriveSupportingCallsForFinding_CombinesContractRolesForDirectAssets(t *testing.T) {
	t.Parallel()

	owner := callgraph.FunctionID{Package: "pkg", Type: "Svc", Name: "run"}
	structuralCall := callgraph.FunctionCall{
		Callee:      callgraph.FunctionID{Package: "pkg", Type: "Builder", Name: "prepare"},
		ReceiverVar: "builder",
		Raw:         "builder.prepare()",
		FilePath:    "lib.py",
		Line:        11,
	}
	terminalCall := callgraph.FunctionCall{
		Callee:      callgraph.FunctionID{Package: "pkg", Type: "Builder", Name: "terminal"},
		ReceiverVar: "builder",
		Raw:         "builder.terminal(secret)",
		FilePath:    "lib.py",
		Line:        12,
	}
	ownerDecl := &callgraph.FunctionDecl{
		ID:        owner,
		FilePath:  "lib.py",
		StartLine: 10,
		EndLine:   20,
		Calls:     []callgraph.FunctionCall{structuralCall, terminalCall},
	}
	contractDecl := &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: "pkg", Type: "Builder", Name: "configure"},
		FilePath:  "lib.py",
		StartLine: 8,
	}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{owner.String(): ownerDecl}}
	ctx := &exportBuildContext{
		graph:                   graph,
		containingFunctionCache: make(map[string]cachedContainingFunction),
		kb: &contracts.KnowledgeBase{
			Contracts: map[string][]contracts.Contract{
				"pkg.Builder.terminal#1": {{
					Method: "pkg.Builder.terminal",
					Arity:  1,
					Return: contracts.ContractReturn{Type: "pkg.Result", Confidence: "high"},
				}},
				"pkg.Builder.configure#0": {{
					Method: "pkg.Builder.configure",
					Arity:  0,
					Return: contracts.ContractReturn{Type: "pkg.Builder", Confidence: "high"},
					Role:   "config",
				}},
			},
			Hierarchy: map[string][]string{"pkg.Builder": {"builtins.object"}},
		},
		declIndex: map[string][]*callgraph.FunctionDecl{"pkg.Builder.configure": {contractDecl}},
	}
	asset := entities.CryptographicAsset{
		StartLine: 12,
		EndLine:   12,
		Match:     "builder.terminal(secret)",
		Metadata:  map[string]string{"api": "pkg.Builder.terminal"},
		Rules:     []entities.RuleInfo{{ID: "direct-rule"}},
	}
	finding := entities.Finding{FilePath: "lib.py"}

	got := deriveSupportingCallsForFinding(ctx, finding, asset)
	if len(got) != 2 {
		t.Fatalf("supporting calls = %d, want contract + structural", len(got))
	}
	if got[0].Category != "config" {
		t.Fatalf("contract category = %q, want config", got[0].Category)
	}
	if got[1].FunctionName != "pkg.Svc.run" {
		t.Fatalf("structural function = %q, want pkg.Svc.run", got[1].FunctionName)
	}
}

func TestDeriveContractSupportingCalls_PreservesOverloadsRegardlessOfInsertionOrder(t *testing.T) {
	t.Parallel()

	declarations := []*callgraph.FunctionDecl{
		{
			ID:         callgraph.FunctionID{Package: "pkg", Type: "Builder", Name: "configure#0"},
			FilePath:   "Builder.java",
			StartLine:  10,
			ReturnType: "pkg.Builder",
		},
		{
			ID:         callgraph.FunctionID{Package: "pkg", Type: "Builder", Name: "configure#1$int"},
			FilePath:   "Builder.java",
			StartLine:  14,
			ReturnType: "pkg.Builder",
			Parameters: []callgraph.FunctionParameter{{Type: "int"}},
		},
		{
			ID:         callgraph.FunctionID{Package: "pkg", Type: "Builder", Name: "salt#1$byte[]"},
			FilePath:   "Builder.java",
			StartLine:  18,
			ReturnType: "pkg.Builder",
			Parameters: []callgraph.FunctionParameter{{Type: "byte[]"}},
		},
		{
			ID:         callgraph.FunctionID{Package: "pkg", Type: "Builder", Name: "salt#1$String"},
			FilePath:   "Builder.java",
			StartLine:  22,
			ReturnType: "pkg.Builder",
			Parameters: []callgraph.FunctionParameter{{Type: "java.lang.String"}},
		},
	}
	kb := &contracts.KnowledgeBase{
		Contracts: map[string][]contracts.Contract{
			"pkg.Builder.configure#0": {{
				Method: "pkg.Builder.configure", Arity: 0,
				Return: contracts.ContractReturn{Type: "pkg.Builder", Confidence: "high"}, Role: "config",
			}},
			"pkg.Builder.configure#1": {{
				Method: "pkg.Builder.configure", Arity: 1,
				Return: contracts.ContractReturn{Type: "pkg.Builder", Confidence: "high"}, Role: "config",
			}},
			"pkg.Builder.salt#1": {{
				Method: "pkg.Builder.salt", Arity: 1,
				Return: contracts.ContractReturn{Type: "pkg.Builder", Confidence: "high"}, Role: "config",
			}},
			"pkg.Builder.finish#0": {{
				Method: "pkg.Builder.finish", Arity: 0,
				Return: contracts.ContractReturn{Type: "pkg.Result", Confidence: "high"},
			}},
		},
		Hierarchy: map[string][]string{
			"pkg.Builder": {"java.lang.Object"},
			"pkg.Result":  {"java.lang.Object"},
		},
	}
	asset := entities.CryptographicAsset{Metadata: map[string]string{"api": "pkg.Builder.finish"}}

	canonicalSet := func(t *testing.T, order []int) []string {
		t.Helper()
		graph := &callgraph.CallGraph{Functions: make(map[string]*callgraph.FunctionDecl, len(order))}
		for _, index := range order {
			decl := declarations[index]
			graph.Functions[decl.ID.String()] = decl
		}
		ctx := newExportBuildContext(&engine.DepScanResult{CallGraph: graph, Ecosystem: "java"})
		ctx.kb = kb
		calls := deriveContractSupportingCalls(ctx, asset)
		catalog := make(map[string]struct{}, len(calls))
		for _, call := range dedupSupportingCalls(calls) {
			catalog[call.SupportingID] = struct{}{}
		}
		for _, supportingID := range supportingCallIDsOf(calls) {
			if _, ok := catalog[supportingID]; !ok {
				t.Fatalf("supporting call reference %q does not resolve in catalog", supportingID)
			}
		}
		got := make([]string, 0, len(calls))
		for i := range calls {
			got = append(got, calls[i].CanonicalSignature)
		}
		sort.Strings(got)
		return got
	}

	want := []string{
		"pkg.Builder.configure(): pkg.Builder",
		"pkg.Builder.configure(int): pkg.Builder",
		"pkg.Builder.salt(byte[]): pkg.Builder",
		"pkg.Builder.salt(java.lang.String): pkg.Builder",
	}
	tests := []struct {
		name  string
		order []int
	}{
		{name: "forward insertion", order: []int{0, 1, 2, 3}},
		{name: "reverse insertion", order: []int{3, 2, 1, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canonicalSet(t, tt.order); !reflect.DeepEqual(got, want) {
				t.Fatalf("canonical signatures = %v, want %v", got, want)
			}
		})
	}
}

// TestBuildDerivedSupportingCall_CategoryFromKB verifies WU1 (issue-103): a
// structural (call-edge-derived) supporting call whose callee FQN+arity
// matches a role-tagged contract gets support.Category populated from that
// contract's role — closing the BC-coverage gap where only definition-based
// (deriveContractSupportingCalls) supporting calls carried a category.
func TestBuildDerivedSupportingCall_CategoryFromKB(t *testing.T) {
	t.Parallel()

	owner := callgraph.FunctionID{Package: "pkg", Type: "Svc", Name: "run"}
	structuralCall := callgraph.FunctionCall{
		Callee:      callgraph.FunctionID{Package: "pkg", Type: "Builder", Name: "prepare"},
		ReceiverVar: "builder",
		Raw:         "builder.prepare()",
		FilePath:    "lib.py",
		Line:        11,
	}
	terminalCall := callgraph.FunctionCall{
		Callee:      callgraph.FunctionID{Package: "pkg", Type: "Builder", Name: "terminal"},
		ReceiverVar: "builder",
		Raw:         "builder.terminal(secret)",
		FilePath:    "lib.py",
		Line:        12,
	}
	ownerDecl := &callgraph.FunctionDecl{
		ID:        owner,
		FilePath:  "lib.py",
		StartLine: 10,
		EndLine:   20,
		Calls:     []callgraph.FunctionCall{structuralCall, terminalCall},
	}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{owner.String(): ownerDecl}}
	ctx := &exportBuildContext{
		graph:                   graph,
		containingFunctionCache: make(map[string]cachedContainingFunction),
		kb: &contracts.KnowledgeBase{
			Contracts: map[string][]contracts.Contract{
				"pkg.Builder.terminal#1": {{
					Method: "pkg.Builder.terminal",
					Arity:  1,
					Return: contracts.ContractReturn{Type: "pkg.Result", Confidence: "high"},
				}},
				// Role-tagged via the call-edge path (no definition in
				// scanned source, unlike deriveContractSupportingCalls'
				// declIndex-gated lookup) — this is the WU1 target: a
				// contract-known callee reached only through the structural
				// call edge, not the fluent-lifecycle declIndex walk.
				"pkg.Builder.prepare#0": {{
					Method: "pkg.Builder.prepare",
					Arity:  0,
					Return: contracts.ContractReturn{Type: "void", Confidence: "high"},
					Role:   "operation",
				}},
			},
			Hierarchy: map[string][]string{"pkg.Builder": {"builtins.object"}},
		},
	}
	asset := entities.CryptographicAsset{
		StartLine: 12,
		EndLine:   12,
		Match:     "builder.terminal(secret)",
		Metadata:  map[string]string{"api": "pkg.Builder.terminal"},
		Rules:     []entities.RuleInfo{{ID: "direct-rule"}},
	}
	finding := entities.Finding{FilePath: "lib.py"}

	got := deriveSupportingCallsForFinding(ctx, finding, asset)
	if len(got) != 1 {
		t.Fatalf("supporting calls = %d, want 1 (structural only, no declIndex fluent match)", len(got))
	}
	if got[0].FunctionName != "pkg.Svc.run" {
		t.Fatalf("structural function = %q, want pkg.Svc.run", got[0].FunctionName)
	}
	if got[0].Category != "operation" {
		t.Fatalf("structural supporting call category = %q, want %q (from KB contract role)", got[0].Category, "operation")
	}
}

func TestContractMatchesForCall_CGlobalLinkage(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: c
library:
  name: test-c
contracts:
  - method: EVP_EncryptInit_ex
    arity: 5
    return:
      type: int
      confidence: high
    role: config
`))
	if err != nil {
		t.Fatalf("load test KB: %v", err)
	}
	localID := callgraph.FunctionID{Package: "app", Name: "EVP_EncryptInit_ex", Linkage: callgraph.LinkageExternal}
	ctx := &exportBuildContext{
		graph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
			localID.String(): {ID: localID},
		}},
		kb: kb,
	}

	tests := []struct {
		name string
		id   callgraph.FunctionID
		want int
	}{
		{name: "external unresolved", id: callgraph.FunctionID{Package: "app", Name: "EVP_EncryptInit_ex", Linkage: callgraph.LinkageExternal}, want: 0},
		{name: "static", id: callgraph.FunctionID{Package: "app/file.c", Name: "EVP_EncryptInit_ex", Linkage: callgraph.LinkageInternal}, want: 0},
		{name: "external from another package", id: callgraph.FunctionID{Package: "other", Name: "EVP_EncryptInit_ex", Linkage: callgraph.LinkageExternal}, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &callgraph.FunctionCall{Callee: tt.id}
			if got := contractMatchesForCall(ctx, call, 5); len(got) != tt.want {
				t.Fatalf("matches = %#v, want %d", got, tt.want)
			}
		})
	}
}

// TestBuildDerivedSupportingCall_UnknownCalleeStaysUncategorized verifies the
// negative scenario from the spec: a callee absent from the KB leaves
// support.Category empty — no structural guessing.
func TestBuildDerivedSupportingCall_UnknownCalleeStaysUncategorized(t *testing.T) {
	t.Parallel()

	owner := callgraph.FunctionID{Package: "pkg", Type: "Svc", Name: "run"}
	structuralCall := callgraph.FunctionCall{
		Callee:      callgraph.FunctionID{Package: "pkg", Type: "Builder", Name: "unknownMethod"},
		ReceiverVar: "builder",
		Raw:         "builder.unknownMethod()",
		FilePath:    "lib.py",
		Line:        11,
	}
	terminalCall := callgraph.FunctionCall{
		Callee:      callgraph.FunctionID{Package: "pkg", Type: "Builder", Name: "terminal"},
		ReceiverVar: "builder",
		Raw:         "builder.terminal(secret)",
		FilePath:    "lib.py",
		Line:        12,
	}
	ownerDecl := &callgraph.FunctionDecl{
		ID:        owner,
		FilePath:  "lib.py",
		StartLine: 10,
		EndLine:   20,
		Calls:     []callgraph.FunctionCall{structuralCall, terminalCall},
	}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{owner.String(): ownerDecl}}
	ctx := &exportBuildContext{
		graph:                   graph,
		containingFunctionCache: make(map[string]cachedContainingFunction),
		kb: &contracts.KnowledgeBase{
			Contracts: map[string][]contracts.Contract{
				"pkg.Builder.terminal#1": {{
					Method: "pkg.Builder.terminal",
					Arity:  1,
					Return: contracts.ContractReturn{Type: "pkg.Result", Confidence: "high"},
				}},
			},
			Hierarchy: map[string][]string{"pkg.Builder": {"builtins.object"}},
		},
	}
	asset := entities.CryptographicAsset{
		StartLine: 12,
		EndLine:   12,
		Match:     "builder.terminal(secret)",
		Metadata:  map[string]string{"api": "pkg.Builder.terminal"},
		Rules:     []entities.RuleInfo{{ID: "direct-rule"}},
	}
	finding := entities.Finding{FilePath: "lib.py"}

	got := deriveSupportingCallsForFinding(ctx, finding, asset)
	if len(got) != 1 {
		t.Fatalf("supporting calls = %d, want 1", len(got))
	}
	if got[0].Category != "" {
		t.Fatalf("structural supporting call category = %q, want empty (no contract match)", got[0].Category)
	}
}

// TestFindContainingFunctionByFinding_PicksTightestSpan guards against map-order
// nondeterminism: graph.Functions is an unordered map, and a wide-span decl
// (e.g. a synthetic <clinit> covering the whole class) can enclose the same
// line as the real method. The lookup must deterministically return the
// tightest enclosing span, not whichever match iterates first. The cache is
// cleared between iterations so every lookup re-runs the selection.
func TestFindContainingFunctionByFinding_PicksTightestSpan(t *testing.T) {
	wide := &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: "com.password4j", Type: "PBKDF2Function", Name: "<clinit>#0"},
		FilePath:  "com/password4j/PBKDF2Function.java",
		StartLine: 1,
		EndLine:   300,
	}
	tight := &callgraph.FunctionDecl{
		ID:        callgraph.FunctionID{Package: "com.password4j", Type: "PBKDF2Function", Name: "internalHash#5"},
		FilePath:  "com/password4j/PBKDF2Function.java",
		StartLine: 126,
		EndLine:   139,
	}
	ctx := &exportBuildContext{
		graph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
			wide.ID.String():  wide,
			tight.ID.String(): tight,
		}},
		containingFunctionCache: make(map[string]cachedContainingFunction),
	}

	for i := 0; i < 50; i++ {
		ctx.containingFunctionCache = make(map[string]cachedContainingFunction)
		got := ctx.findContainingFunctionByFinding("com/password4j/PBKDF2Function.java", 130)
		if got == nil {
			t.Fatalf("iteration %d: got nil, want internalHash", i)
		}
		if got.ID.Name != "internalHash#5" {
			t.Fatalf("iteration %d: got %s, want internalHash#5 (tightest span)", i, got.ID.Name)
		}
	}
}
