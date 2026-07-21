// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestBuildGraphFragmentExport_ResolvesSelectorThroughWrapperAndReturn(t *testing.T) {
	t.Parallel()

	runID := callgraph.FunctionID{Package: "example", Type: "DigestFlow", Name: "run#0"}
	wrapID := callgraph.FunctionID{Package: "example", Type: "DigestFlow", Name: "wrap#1"}
	selectID := callgraph.FunctionID{Package: "example", Type: "DigestFlow", Name: "select#1"}
	helperID := callgraph.FunctionID{Package: "example", Type: "DigestFlow", Name: "algorithm#0"}
	digestID := callgraph.FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance#1"}

	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		runID.String(): {
			ID: runID, FilePath: "DigestFlow.java", StartLine: 1, EndLine: 8,
			Calls: []callgraph.FunctionCall{
				{Callee: wrapID, Arguments: []string{"\"SHA-512\""}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "\"SHA-512\""}}}},
				{Callee: digestID, FilePath: "DigestFlow.java", Line: 6, Arguments: []string{"algorithm()"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "CALL_RESULT", CallTarget: &helperID}}}},
			},
		},
		helperID.String(): {ID: helperID, ReturnSources: []callgraph.SourceNode{{Type: "VALUE", Value: "\"SHA-256\""}}},
		wrapID.String(): {
			ID: wrapID, Parameters: []callgraph.FunctionParameter{{Name: "algorithm", Type: "String"}},
			Calls: []callgraph.FunctionCall{{
				Callee: selectID, Arguments: []string{"algorithm"},
				ArgumentSources: [][]callgraph.SourceNode{{{Type: "PARAMETER", Name: "algorithm", ParameterIndex: 0}}},
			}},
			ReturnSources: []callgraph.SourceNode{{
				Type: "CALL_RESULT", CallTarget: &selectID,
				SourceNodes: []callgraph.SourceNode{{Type: "PARAMETER", Name: "algorithm", ParameterIndex: 0}},
			}},
		},
		selectID.String(): {
			ID: selectID, FilePath: "DigestFlow.java", StartLine: 20, EndLine: 22,
			Parameters: []callgraph.FunctionParameter{{Name: "algorithm", Type: "String"}},
			Calls: []callgraph.FunctionCall{{
				Callee: digestID, FilePath: "DigestFlow.java", Line: 21, Arguments: []string{"algorithm"},
				ArgumentSources: [][]callgraph.SourceNode{{{Type: "PARAMETER", Name: "algorithm", ParameterIndex: 0}}},
			}},
		},
	}}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "DigestFlow.java", Language: "java",
		CryptographicAssets: []entities.CryptographicAsset{
			{FindingID: "digest-return", StartLine: 6, EndLine: 6, Match: "MessageDigest.getInstance(algorithm())", Rules: []entities.RuleInfo{{ID: "java.digest.return"}}, Metadata: map[string]string{"api": "java.security.MessageDigest.getInstance"}},
			{FindingID: "digest-selector", StartLine: 21, EndLine: 21, Match: "MessageDigest.getInstance(algorithm)", Rules: []entities.RuleInfo{{ID: "java.digest.selector"}}, Metadata: map[string]string{"api": "java.security.MessageDigest.getInstance"}},
		},
	}}}

	payload := BuildGraphFragmentExport(&engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java"})
	if len(payload.CryptoAnnotations) != 2 {
		t.Fatalf("crypto annotations = %#v", payload.CryptoAnnotations)
	}
	byID := make(map[string]int, len(payload.CryptoAnnotations))
	for i := range payload.CryptoAnnotations {
		byID[payload.CryptoAnnotations[i].FindingID] = i
	}
	returnIndex, ok := byID["digest-return"]
	if !ok || payload.CryptoAnnotations[returnIndex].CryptoCall == nil || payload.CryptoAnnotations[returnIndex].CryptoCall.Parameters[0].ResolvedValue != "\"SHA-256\"" {
		t.Fatalf("return selector annotation = %#v, want helper literal", payload.CryptoAnnotations)
	}
	selectorIndex := byID["digest-selector"]
	param := payload.CryptoAnnotations[selectorIndex].CryptoCall.Parameters[0]
	if param.ResolvedValue != "\"SHA-512\"" {
		t.Fatalf("resolved_value = %q, want caller literal", param.ResolvedValue)
	}
	if len(param.SourceNodes) != 1 || param.SourceNodes[0].Type != "PARAMETER" || len(param.SourceNodes[0].SourceNodes) == 0 {
		t.Fatalf("selector provenance = %#v, want recursive wrapper provenance", param.SourceNodes)
	}
}

func TestBuildGraphFragmentExport_LeavesAmbiguousSelectorUnresolved(t *testing.T) {
	t.Parallel()

	firstID := callgraph.FunctionID{Package: "example", Type: "DigestFlow", Name: "first#0"}
	secondID := callgraph.FunctionID{Package: "example", Type: "DigestFlow", Name: "second#0"}
	selectID := callgraph.FunctionID{Package: "example", Type: "DigestFlow", Name: "select#1"}
	digestID := callgraph.FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance#1"}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		firstID.String():  {ID: firstID, Calls: []callgraph.FunctionCall{{Callee: selectID, Arguments: []string{"\"SHA-256\""}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "\"SHA-256\""}}}}}},
		secondID.String(): {ID: secondID, Calls: []callgraph.FunctionCall{{Callee: selectID, Arguments: []string{"\"SHA-512\""}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "\"SHA-512\""}}}}}},
		selectID.String(): {ID: selectID, FilePath: "DigestFlow.java", StartLine: 30, EndLine: 32, Parameters: []callgraph.FunctionParameter{{Name: "algorithm", Type: "String"}}, Calls: []callgraph.FunctionCall{{Callee: digestID, FilePath: "DigestFlow.java", Line: 31, Arguments: []string{"algorithm"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "PARAMETER", Name: "algorithm", ParameterIndex: 0}}}}}},
	}}
	report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "DigestFlow.java", Language: "java", CryptographicAssets: []entities.CryptographicAsset{{FindingID: "digest-dynamic", StartLine: 31, EndLine: 31, Match: "MessageDigest.getInstance(algorithm)", Rules: []entities.RuleInfo{{ID: "java.digest.dynamic"}}, Metadata: map[string]string{"api": "java.security.MessageDigest.getInstance"}}}}}}

	payload := BuildGraphFragmentExport(&engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java"})
	if len(payload.CryptoAnnotations) != 1 || payload.CryptoAnnotations[0].CryptoCall == nil {
		t.Fatalf("crypto annotations = %#v", payload.CryptoAnnotations)
	}
	if got := payload.CryptoAnnotations[0].CryptoCall.Parameters[0].ResolvedValue; got != "" {
		t.Fatalf("resolved_value = %q, want unresolved dynamic selector", got)
	}
}
