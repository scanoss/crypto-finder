// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"regexp"
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

func TestOccurrenceKeyGroupLess_UsesIdentityAfterLocation(t *testing.T) {
	left := &occurrenceKeyGroup{line: 10, col: 5, identity: "a"}
	right := &occurrenceKeyGroup{line: 10, col: 5, identity: "b"}
	if !occurrenceKeyGroupLess(left, right) || occurrenceKeyGroupLess(right, left) {
		t.Fatal("tied locations must be ordered by occurrence identity")
	}
}
