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

func TestBuildCallGraphExport_PreservesSelectorPerCallerPath(t *testing.T) {
	t.Parallel()

	firstID := callgraph.FunctionID{Package: "example", Type: "PGPFlow", Name: "first#0"}
	secondID := callgraph.FunctionID{Package: "example", Type: "PGPFlow", Name: "second#0"}
	buildID := callgraph.FunctionID{Package: "example", Type: "PGPFlow", Name: "build#1"}
	ctorID := callgraph.FunctionID{Package: "org.bouncycastle.openpgp.operator.jcajce", Type: "JcePGPDataEncryptorBuilder", Name: "<init>#1"}

	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		firstID.String(): {
			ID: firstID, FilePath: "PGPFlow.java", StartLine: 1, EndLine: 3,
			Calls: []callgraph.FunctionCall{{Callee: buildID, FilePath: "PGPFlow.java", Line: 2, Arguments: []string{"SymmetricKeyAlgorithmTags.AES_128"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "SymmetricKeyAlgorithmTags.AES_128"}}}}},
		},
		secondID.String(): {
			ID: secondID, FilePath: "PGPFlow.java", StartLine: 5, EndLine: 7,
			Calls: []callgraph.FunctionCall{{Callee: buildID, FilePath: "PGPFlow.java", Line: 6, Arguments: []string{"SymmetricKeyAlgorithmTags.DES"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "SymmetricKeyAlgorithmTags.DES"}}}}},
		},
		buildID.String(): {
			ID: buildID, FilePath: "PGPFlow.java", StartLine: 9, EndLine: 11,
			Parameters: []callgraph.FunctionParameter{{Name: "algorithm", Type: "int"}},
			Calls: []callgraph.FunctionCall{{
				Callee: ctorID, FilePath: "PGPFlow.java", Line: 10, StartCol: 16, EndCol: 63,
				Arguments: []string{"algorithm"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "PARAMETER", Name: "algorithm", ParameterIndex: 0}}},
			}},
		},
	}, Callers: map[string][]string{buildID.String(): {firstID.String(), secondID.String()}}}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "PGPFlow.java", Language: "java",
		CryptographicAssets: []entities.CryptographicAsset{{
			FindingID: "pgp-selector", StartLine: 10, EndLine: 10, StartCol: 16, EndCol: 63,
			Match: "new JcePGPDataEncryptorBuilder(algorithm)", Rules: []entities.RuleInfo{{ID: "java.pgp.dynamic"}},
			Metadata: map[string]string{"api": "org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>"},
		}},
	}}}

	payload := buildCallGraphExportV2(&engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java"})
	if len(payload.FindingGraphs) != 1 || len(payload.FindingGraphs[0].CallChains) != 2 {
		t.Fatalf("finding graphs = %#v, want two caller paths", payload.FindingGraphs)
	}
	got := make(map[string]bool)
	for _, chain := range payload.FindingGraphs[0].CallChains {
		last := chain[len(chain)-1]
		if last.CryptoCall == nil || len(last.CryptoCall.Parameters) != 1 {
			t.Fatalf("chain = %#v, want one crypto selector parameter", chain)
		}
		got[last.CryptoCall.Parameters[0].ResolvedValue] = true
	}
	for _, want := range []string{"SymmetricKeyAlgorithmTags.AES_128", "SymmetricKeyAlgorithmTags.DES"} {
		if !got[want] {
			t.Fatalf("resolved caller values = %#v, missing %q", got, want)
		}
	}
}

func TestBuildCallGraphExport_PreservesSelectorPerSameLineCallSite(t *testing.T) {
	t.Parallel()

	callerID := callgraph.FunctionID{Package: "example", Type: "PGPFlow", Name: "run#0"}
	buildID := callgraph.FunctionID{Package: "example", Type: "PGPFlow", Name: "build#1"}
	ctorID := callgraph.FunctionID{Package: "org.bouncycastle.openpgp.operator.jcajce", Type: "JcePGPDataEncryptorBuilder", Name: "<init>#1"}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		callerID.String(): {
			ID: callerID, FilePath: "PGPFlow.java", StartLine: 1, EndLine: 3,
			Calls: []callgraph.FunctionCall{
				{Callee: buildID, FilePath: "PGPFlow.java", Line: 2, StartCol: 4, EndCol: 37, Arguments: []string{"SymmetricKeyAlgorithmTags.AES_128"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "SymmetricKeyAlgorithmTags.AES_128"}}}},
				{Callee: buildID, FilePath: "PGPFlow.java", Line: 2, StartCol: 40, EndCol: 69, Arguments: []string{"SymmetricKeyAlgorithmTags.DES"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "SymmetricKeyAlgorithmTags.DES"}}}},
			},
		},
		buildID.String(): {
			ID: buildID, FilePath: "PGPFlow.java", StartLine: 5, EndLine: 7,
			Parameters: []callgraph.FunctionParameter{{Name: "algorithm", Type: "int"}},
			Calls: []callgraph.FunctionCall{{
				Callee: ctorID, FilePath: "PGPFlow.java", Line: 6, StartCol: 16, EndCol: 63,
				Arguments: []string{"algorithm"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "PARAMETER", Name: "algorithm", ParameterIndex: 0}}},
			}},
		},
	}, Callers: map[string][]string{buildID.String(): {callerID.String()}}}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "PGPFlow.java", Language: "java",
		CryptographicAssets: []entities.CryptographicAsset{{
			FindingID: "pgp-same-line", StartLine: 6, EndLine: 6, StartCol: 16, EndCol: 63,
			Match: "new JcePGPDataEncryptorBuilder(algorithm)", Rules: []entities.RuleInfo{{ID: "java.pgp.dynamic"}},
			Metadata: map[string]string{"api": "org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>"},
		}},
	}}}

	payload := buildCallGraphExportV2(&engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java"})
	if len(payload.FindingGraphs) != 1 || len(payload.FindingGraphs[0].CallChains) != 2 {
		t.Fatalf("finding graphs = %#v, want two same-line call-site paths", payload.FindingGraphs)
	}
	got := make(map[string]bool)
	for _, chain := range payload.FindingGraphs[0].CallChains {
		got[chain[len(chain)-1].CryptoCall.Parameters[0].ResolvedValue] = true
	}
	if !got["SymmetricKeyAlgorithmTags.AES_128"] || !got["SymmetricKeyAlgorithmTags.DES"] {
		t.Fatalf("resolved same-line values = %#v, want AES_128 and DES", got)
	}
}
