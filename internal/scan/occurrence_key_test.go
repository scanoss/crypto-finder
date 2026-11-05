// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"regexp"
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestAssignOccurrenceKeys(t *testing.T) {
	newResult := func(path, function string, line, col int, match string) *engine.DepScanResult {
		id := callgraph.FunctionID{Package: "com.example", Type: "Crypto", Name: function}
		return &engine.DepScanResult{
			RootModule:  "com.example:app",
			ProjectRoot: "/workspace",
			CallGraph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
				id.String(): {
					ID: id, FilePath: "/workspace/" + path, StartLine: 1, EndLine: 100,
					ReturnType: "void",
					Calls: []callgraph.FunctionCall{{
						FilePath: "/workspace/" + path, Line: line, StartCol: col, EndCol: col + 20,
						ASTKind: "method_invocation", NamedASTPath: "block[0]/expression_statement[0]/method_invocation[0]",
					}},
				},
			}},
			Report: &entities.InterimReport{Findings: []entities.Finding{{
				FilePath:            "/workspace/" + path,
				CryptographicAssets: []entities.CryptographicAsset{{StartLine: line, EndLine: line, StartCol: col, EndCol: col + 20, Match: match}},
			}}},
		}
	}

	result := newResult("Crypto.java", "run#0", 10, 5, `Cipher.getInstance("AES")`)
	AssignOccurrenceKeys(result)
	key := result.Report.Findings[0].CryptographicAssets[0].OccurrenceKey
	if !regexp.MustCompile(`^v1:[0-9a-f]{16}$`).MatchString(key) {
		t.Fatalf("occurrence_key = %q, want v1:<16 lowercase hex chars>", key)
	}

	for _, match := range []string{`Cipher.getInstance("AES/GCM/NoPadding")`, "changed evidence"} {
		candidate := newResult("Crypto.java", "run#0", 10, 5, match)
		AssignOccurrenceKeys(candidate)
		if got := candidate.Report.Findings[0].CryptographicAssets[0].OccurrenceKey; got != key {
			t.Errorf("evidence-only change occurrence_key = %q, want %q", got, key)
		}
	}

	for _, tc := range []struct {
		name     string
		path     string
		function string
	}{
		{name: "file relocation", path: "Moved.java", function: "run#0"},
		{name: "function relocation", path: "Crypto.java", function: "moved#0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := newResult(tc.path, tc.function, 10, 5, `Cipher.getInstance("AES")`)
			AssignOccurrenceKeys(candidate)
			if got := candidate.Report.Findings[0].CryptographicAssets[0].OccurrenceKey; got == key {
				t.Errorf("occurrence_key = %q, want relocation to change it", got)
			}
		})
	}
}

func TestAssignOccurrenceKeys_CollisionsAreDeterministic(t *testing.T) {
	result := &engine.DepScanResult{
		RootModule:  "com.example:app",
		ProjectRoot: "/workspace",
		CallGraph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
			"com.example.Crypto.run#0": {
				ID: callgraph.FunctionID{Package: "com.example", Type: "Crypto", Name: "run#0"}, FilePath: "/workspace/Crypto.java", StartLine: 1, EndLine: 100,
				Calls: []callgraph.FunctionCall{
					{FilePath: "/workspace/Crypto.java", Line: 10, StartCol: 5, EndCol: 25, ASTKind: "method_invocation", NamedASTPath: "block[0]/expression_statement[0]/method_invocation[0]"},
					{FilePath: "/workspace/Crypto.java", Line: 11, StartCol: 5, EndCol: 25, ASTKind: "method_invocation", NamedASTPath: "block[0]/expression_statement[0]/method_invocation[0]"},
				},
			},
		}},
		Report: &entities.InterimReport{Findings: []entities.Finding{{
			FilePath: "/workspace/Crypto.java",
			CryptographicAssets: []entities.CryptographicAsset{
				{StartLine: 10, EndLine: 10, StartCol: 5, EndCol: 25, Rules: []entities.RuleInfo{{ID: "java.cipher.a"}}},
				{StartLine: 10, EndLine: 10, StartCol: 5, EndCol: 25, Rules: []entities.RuleInfo{{ID: "java.cipher.b"}}},
				{StartLine: 11, EndLine: 11, StartCol: 5, EndCol: 25},
			},
		}}},
	}

	AssignOccurrenceKeys(result)
	assets := result.Report.Findings[0].CryptographicAssets
	if assets[0].OccurrenceKey == "" || assets[1].OccurrenceKey != assets[0].OccurrenceKey {
		t.Fatalf("same-call keys = %q, %q; want shared key across rules", assets[0].OccurrenceKey, assets[1].OccurrenceKey)
	}
	if assets[2].OccurrenceKey != assets[0].OccurrenceKey+"-2" {
		t.Fatalf("collision key = %q, want %q", assets[2].OccurrenceKey, assets[0].OccurrenceKey+"-2")
	}
}

// Per-value assets of one rule at one call differ only in the resolved
// condition, and must not share a key with each other or with a native asset.
func TestAssignOccurrenceKeys_PerValueAssetsGetDistinctKeys(t *testing.T) {
	result := &engine.DepScanResult{
		RootModule:  "com.example:app",
		ProjectRoot: "/workspace",
		CallGraph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
			"com.example.Crypto.run#0": {
				ID: callgraph.FunctionID{Package: "com.example", Type: "Crypto", Name: "run#0"}, FilePath: "/workspace/Crypto.java", StartLine: 1, EndLine: 100,
				Calls: []callgraph.FunctionCall{
					{FilePath: "/workspace/Crypto.java", Line: 10, StartCol: 5, EndCol: 25, ASTKind: "method_invocation", NamedASTPath: "block[0]/expression_statement[0]/method_invocation[0]"},
				},
			},
		}},
		Report: &entities.InterimReport{Findings: []entities.Finding{{
			FilePath: "/workspace/Crypto.java",
			CryptographicAssets: []entities.CryptographicAsset{
				{StartLine: 10, EndLine: 10, StartCol: 5, EndCol: 25},
				{StartLine: 10, EndLine: 10, StartCol: 5, EndCol: 25, ConditionedValue: "param[0]==SHA-256"},
				{StartLine: 10, EndLine: 10, StartCol: 5, EndCol: 25, ConditionedValue: "param[0]==SHA-512"},
			},
		}}},
	}

	AssignOccurrenceKeys(result)

	assets := result.Report.Findings[0].CryptographicAssets
	pattern := regexp.MustCompile(`^v1:[0-9a-f]{16}$`)
	for i := range assets {
		if !pattern.MatchString(assets[i].OccurrenceKey) {
			t.Fatalf("asset %d occurrence_key = %q, want a plain v1 key", i, assets[i].OccurrenceKey)
		}
	}
	if assets[0].OccurrenceKey == assets[1].OccurrenceKey || assets[1].OccurrenceKey == assets[2].OccurrenceKey || assets[0].OccurrenceKey == assets[2].OccurrenceKey {
		t.Fatalf("occurrence keys = %q, %q, %q; want three distinct keys", assets[0].OccurrenceKey, assets[1].OccurrenceKey, assets[2].OccurrenceKey)
	}
}

func TestAssignOccurrenceKeys_TopLevelFallbackPropagatesToExports(t *testing.T) {
	result := &engine.DepScanResult{
		RootModule:  "com.example:app",
		ProjectRoot: "/workspace",
		Ecosystem:   "python",
		CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Report: &entities.InterimReport{Findings: []entities.Finding{{
			FilePath: "/workspace/crypto.py",
			CryptographicAssets: []entities.CryptographicAsset{{
				FindingID: "finding-1", StartLine: 2, EndLine: 2, StartCol: 1, EndCol: 20,
				Match: "hashlib.sha256(data)",
			}},
		}}},
	}

	callgraphExport := buildCallGraphExportV2(result)
	if got := callgraphExport.FindingGraphs[0].OccurrenceKey; got == "" {
		t.Fatal("top-level callgraph finding omitted occurrence_key")
	}
	key := callgraphExport.FindingGraphs[0].OccurrenceKey

	fragmentExport := buildGraphFragmentExport(result)
	if got := fragmentExport.CryptoAnnotations[0].OccurrenceKey; got != key {
		t.Fatalf("graph-fragment occurrence_key = %q, want %q", got, key)
	}
}

func TestOccurrenceKeyGroupLess_UsesIdentityAfterLocation(t *testing.T) {
	left := &occurrenceKeyGroup{line: 10, col: 5, identity: "a"}
	right := &occurrenceKeyGroup{line: 10, col: 5, identity: "b"}
	if !occurrenceKeyGroupLess(left, right) || occurrenceKeyGroupLess(right, left) {
		t.Fatal("tied locations must be ordered by occurrence identity")
	}
}

// ternaryStatementResult models one Java statement spanning two lines that
// holds two calls of the same API:
//
//	SSLContext ctx = provider == null ? SSLContext.getInstance(protocol)
//	    : SSLContext.getInstance(protocol, provider);
//
// The first call ends on line 92; the second starts on line 92 and ends on
// line 93, so its EndCol is a column of the later line.
func ternaryStatementResult() *engine.DepScanResult {
	const file = "/workspace/SSLUtils.java"
	rule := []entities.RuleInfo{{ID: "java.jca.protocol.tls.sslcontext"}}
	return &engine.DepScanResult{
		RootModule:  "com.example:app",
		ProjectRoot: "/workspace",
		CallGraph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
			"com.example.SSLUtils.build#0": {
				ID: callgraph.FunctionID{Package: "com.example", Type: "SSLUtils", Name: "build#0"}, FilePath: file, StartLine: 80, EndLine: 100,
				Calls: []callgraph.FunctionCall{
					{FilePath: file, Line: 92, StartCol: 45, EndCol: 77, ASTKind: "method_invocation", NamedASTPath: "block[0]/local_variable_declaration[0]/ternary_expression[0]/method_invocation[0]"},
					{FilePath: file, Line: 92, StartCol: 80, EndCol: 45, ASTKind: "method_invocation", NamedASTPath: "block[0]/local_variable_declaration[0]/ternary_expression[0]/method_invocation[1]"},
				},
			},
		}},
		Report: &entities.InterimReport{Findings: []entities.Finding{{
			FilePath: file,
			CryptographicAssets: []entities.CryptographicAsset{
				{StartLine: 92, EndLine: 92, StartCol: 45, EndCol: 77, Rules: rule},
				{StartLine: 92, EndLine: 93, StartCol: 80, EndCol: 45, Rules: rule},
			},
		}}},
	}
}

func TestAssignOccurrenceKeys_TwoCallsInOneStatementGetDistinctKeys(t *testing.T) {
	result := ternaryStatementResult()
	engine.AssignFindingIDs(result.Report)
	AssignOccurrenceKeys(result)

	assets := result.Report.Findings[0].CryptographicAssets
	if assets[0].OccurrenceKey == "" || assets[1].OccurrenceKey == "" {
		t.Fatalf("keys = %q, %q; want both set", assets[0].OccurrenceKey, assets[1].OccurrenceKey)
	}
	if assets[0].OccurrenceKey == assets[1].OccurrenceKey {
		t.Fatalf("both calls share occurrence_key %q", assets[0].OccurrenceKey)
	}

	// finding_id is per file, line and rule, so the pair shares it; the
	// (finding_id, occurrence_key) pair is what must stay unique.
	export := buildCallGraphExportV2(result)
	seen := map[string]bool{}
	for _, graph := range export.FindingGraphs {
		pair := graph.FindingID + "|" + graph.OccurrenceKey
		if seen[pair] {
			t.Fatalf("duplicate finding graph for %s", pair)
		}
		seen[pair] = true
	}
	for _, asset := range assets {
		if !seen[asset.FindingID+"|"+asset.OccurrenceKey] {
			t.Errorf("asset %s has no finding graph of its own; graphs: %v", asset.OccurrenceKey, seen)
		}
	}
}

func TestAssignOccurrenceKeys_TwoCallsInOneStatementAreDeterministic(t *testing.T) {
	first, second := ternaryStatementResult(), ternaryStatementResult()
	AssignOccurrenceKeys(first)
	AssignOccurrenceKeys(second)
	a, b := first.Report.Findings[0].CryptographicAssets, second.Report.Findings[0].CryptographicAssets
	for i := range a {
		if a[i].OccurrenceKey != b[i].OccurrenceKey {
			t.Errorf("asset %d key differs between runs: %q vs %q", i, a[i].OccurrenceKey, b[i].OccurrenceKey)
		}
	}
}

// Keys are stored by consumers, so a call that never collided must keep the
// exact key it had before two-line statements were told apart.
func TestAssignOccurrenceKeys_NonCollidingKeysArePinned(t *testing.T) {
	result := ternaryStatementResult()
	AssignOccurrenceKeys(result)
	if got, want := result.Report.Findings[0].CryptographicAssets[0].OccurrenceKey, "v1:8c9eb83dcd4f3cb7"; got != want {
		t.Errorf("first call occurrence_key = %q, want pinned %q", got, want)
	}

	single := ternaryStatementResult()
	fn := single.CallGraph.Functions["com.example.SSLUtils.build#0"]
	fn.Calls = fn.Calls[:1]
	single.Report.Findings[0].CryptographicAssets = single.Report.Findings[0].CryptographicAssets[:1]
	AssignOccurrenceKeys(single)
	if got, want := single.Report.Findings[0].CryptographicAssets[0].OccurrenceKey, "v1:8c9eb83dcd4f3cb7"; got != want {
		t.Errorf("single call occurrence_key = %q, want pinned %q", got, want)
	}
}

// misanchoredTernaryResult is the ternary of ternaryStatementResult when the
// call graph cannot place its matches: the report's line holds one unrelated
// call, as when a published dependency report was produced from another
// revision of the source. Both matches of the rule fall back to that call.
// The protocol argument of the first call, matched by another rule, sits
// inside it.
func misanchoredTernaryResult() *engine.DepScanResult {
	const file = "/workspace/HttpsURLConnectionFactory.java"
	rule := []entities.RuleInfo{{ID: "java.jca.protocol.tls.sslcontext"}}
	return &engine.DepScanResult{
		RootModule:  "com.example:app",
		ProjectRoot: "/workspace",
		CallGraph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
			"com.example.Factory.decorate#1": {
				ID: callgraph.FunctionID{Package: "com.example", Type: "Factory", Name: "decorate#1"}, FilePath: file, StartLine: 120, EndLine: 170,
				Calls: []callgraph.FunctionCall{
					{FilePath: file, Line: 160, StartCol: 27, EndCol: 59, ASTKind: "method_invocation", NamedASTPath: "block[0]/if_statement[0]/block[0]/expression_statement[7]/method_invocation[0]"},
				},
			},
		}},
		Report: &entities.InterimReport{Findings: []entities.Finding{{
			FilePath: file,
			CryptographicAssets: []entities.CryptographicAsset{
				{StartLine: 160, EndLine: 160, StartCol: 49, EndCol: 81, Rules: rule},
				{StartLine: 160, EndLine: 160, StartCol: 72, EndCol: 80, Rules: []entities.RuleInfo{{ID: "java.jca.protocol.tls.protocol-version"}}},
				{StartLine: 160, EndLine: 161, StartCol: 84, EndCol: 49, Rules: rule},
			},
		}}},
	}
}

func TestAssignOccurrenceKeys_TwoMatchesOfOneRuleOnOneAnchorGetDistinctKeys(t *testing.T) {
	result := misanchoredTernaryResult()
	engine.AssignFindingIDs(result.Report)
	AssignOccurrenceKeys(result)

	assets := result.Report.Findings[0].CryptographicAssets
	first, argument, second := assets[0], assets[1], assets[2]
	if first.OccurrenceKey == "" || second.OccurrenceKey == "" {
		t.Fatalf("keys = %q, %q; want both set", first.OccurrenceKey, second.OccurrenceKey)
	}
	if first.OccurrenceKey == second.OccurrenceKey {
		t.Fatalf("both calls share occurrence_key %q", first.OccurrenceKey)
	}
	if second.OccurrenceKey != first.OccurrenceKey+"-2" {
		t.Errorf("second call occurrence_key = %q, want %q", second.OccurrenceKey, first.OccurrenceKey+"-2")
	}
	if first.FindingID == second.FindingID {
		t.Errorf("both calls share finding_id %q", first.FindingID)
	}
	if argument.OccurrenceKey != first.OccurrenceKey {
		t.Errorf("argument occurrence_key = %q, want the key of the call that holds it, %q", argument.OccurrenceKey, first.OccurrenceKey)
	}

	// The first call keeps the key it had before the second was told apart:
	// the key it gets when it is the only match on the anchor.
	alone := misanchoredTernaryResult()
	alone.Report.Findings[0].CryptographicAssets = alone.Report.Findings[0].CryptographicAssets[:2]
	AssignOccurrenceKeys(alone)
	if got, want := first.OccurrenceKey, alone.Report.Findings[0].CryptographicAssets[0].OccurrenceKey; got != want {
		t.Errorf("first call occurrence_key = %q, want %q, the key it has alone", got, want)
	}
	if got, want := first.OccurrenceKey, "v1:1555d5930ea969aa"; got != want {
		t.Errorf("first call occurrence_key = %q, want pinned %q", got, want)
	}
}

// An asset of another rule that sits inside the second call belongs to it, not
// to the first call it happens not to conflict with (review on #861: a
// provider-argument match inside getInstance(protocol, provider), on the line
// the fallback anchors).
func TestAssignOccurrenceKeys_AnotherRulesMatchJoinsTheCallThatHoldsIt(t *testing.T) {
	result := misanchoredTernaryResult()
	f := &result.Report.Findings[0]
	f.CryptographicAssets = append(f.CryptographicAssets, entities.CryptographicAsset{
		StartLine: 160, EndLine: 160, StartCol: 90, EndCol: 100,
		Rules: []entities.RuleInfo{{ID: "java.jca.protocol.tls.provider"}},
	})
	AssignOccurrenceKeys(result)

	assets := f.CryptographicAssets
	first, argument, second, provider := assets[0], assets[1], assets[2], assets[3]
	if provider.OccurrenceKey != second.OccurrenceKey {
		t.Errorf("provider occurrence_key = %q, want the second call's %q", provider.OccurrenceKey, second.OccurrenceKey)
	}
	if argument.OccurrenceKey != first.OccurrenceKey {
		t.Errorf("argument occurrence_key = %q, want the first call's %q", argument.OccurrenceKey, first.OccurrenceKey)
	}
}

// The first call in source order keeps the base key whatever order the report
// lists the matches in, and a second run gives the same keys.
func TestAssignOccurrenceKeys_TwoMatchesOfOneRuleOnOneAnchorAreDeterministic(t *testing.T) {
	forward := misanchoredTernaryResult()
	AssignOccurrenceKeys(forward)
	again := misanchoredTernaryResult()
	AssignOccurrenceKeys(again)
	reversed := misanchoredTernaryResult()
	slices.Reverse(reversed.Report.Findings[0].CryptographicAssets)
	AssignOccurrenceKeys(reversed)

	want := forward.Report.Findings[0].CryptographicAssets
	got := again.Report.Findings[0].CryptographicAssets
	rev := reversed.Report.Findings[0].CryptographicAssets
	for i := range want {
		if got[i].OccurrenceKey != want[i].OccurrenceKey {
			t.Errorf("asset %d key differs between runs: %q vs %q", i, got[i].OccurrenceKey, want[i].OccurrenceKey)
		}
		if r := rev[len(rev)-1-i]; r.OccurrenceKey != want[i].OccurrenceKey {
			t.Errorf("asset %d key in a reversed report = %q, want %q", i, r.OccurrenceKey, want[i].OccurrenceKey)
		}
	}
}
