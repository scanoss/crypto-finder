// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

func TestResolvedKeyLength_JavaFixtureParserToLiveAndStitchedExports(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	fixtureDir := filepath.Join(filepath.Dir(testFile), "testdata", "resolved_key_length")

	builder := callgraph.NewBuilderForEcosystem("java", callgraph.NewJavaParser())
	graph, err := builder.BuildFromDirectories([]callgraph.PackageDir{{Dir: fixtureDir, ImportPath: "issue272"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	initCalls := make(map[int]callgraph.FunctionCall)
	for _, function := range graph.Functions {
		for _, call := range function.Calls {
			if call.Callee.Package == "javax.crypto" && call.Callee.Type == "KeyGenerator" && call.Callee.Name == "init#1" {
				initCalls[call.Line] = call
			}
		}
	}
	if len(initCalls) != 3 {
		t.Fatalf("parser captured KeyGenerator.init#1 calls = %d, want 3: %#v", len(initCalls), initCalls)
	}
	for _, tc := range []struct {
		line     int
		argument string
		declared string
	}{
		{line: 9, argument: "256"},
		{line: 14, argument: "keyBits", declared: "int"},
		{line: 19, argument: "parameters", declared: "java.security.spec.AlgorithmParameterSpec"},
	} {
		call := initCalls[tc.line]
		if len(call.Arguments) != 1 || call.Arguments[0] != tc.argument {
			t.Fatalf("parser line %d arguments = %#v, want [%q]", tc.line, call.Arguments, tc.argument)
		}
		if tc.declared != "" && (len(call.ArgumentSources) != 1 || len(call.ArgumentSources[0]) != 1 || call.ArgumentSources[0][0].DeclaredType != tc.declared) {
			t.Fatalf("parser line %d source = %#v, want declared type %q", tc.line, call.ArgumentSources, tc.declared)
		}
	}

	report := &entities.InterimReport{
		Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "KeyGeneratorUsage.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{
				{StartLine: 9, EndLine: 9, Match: "generator.init(256)", Rules: []entities.RuleInfo{{ID: "java.jca.keygenerator.init"}}, Metadata: map[string]string{"api": "javax.crypto.KeyGenerator.init"}},
				{StartLine: 14, EndLine: 14, Match: "generator.init(keyBits)", Rules: []entities.RuleInfo{{ID: "java.jca.keygenerator.init"}}, Metadata: map[string]string{"api": "javax.crypto.KeyGenerator.init"}},
				{StartLine: 19, EndLine: 19, Match: "generator.init(parameters)", Rules: []entities.RuleInfo{{ID: "java.jca.keygenerator.init"}}, Metadata: map[string]string{"api": "javax.crypto.KeyGenerator.init"}},
			},
		}},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	result := &engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java", ProjectRoot: fixtureDir}

	live := buildCallGraphExportV2(result)
	want := map[int]struct {
		provenance string
		bits       *int
	}{
		9:  {provenance: "constant", bits: intPointer(256)},
		14: {provenance: "unknown"},
		19: {provenance: "absent"},
	}
	for _, finding := range report.Findings[0].CryptographicAssets {
		keyLength := liveKeyLengthForFinding(live, finding.FindingID)
		expected := want[finding.StartLine]
		switch expected.provenance {
		case "absent":
			if keyLength != nil {
				t.Fatalf("live line %d ResolvedKeyLength = %#v, want absent for non-int overload", finding.StartLine, keyLength)
			}
		default:
			if keyLength == nil || keyLength.Provenance != expected.provenance {
				t.Fatalf("live line %d ResolvedKeyLength = %#v, want provenance %q", finding.StartLine, keyLength, expected.provenance)
			}
			if expected.bits == nil {
				if keyLength.Bits != nil {
					t.Fatalf("live line %d bits = %v, want absent for unresolved input", finding.StartLine, *keyLength.Bits)
				}
			} else if keyLength.Bits == nil || *keyLength.Bits != *expected.bits {
				t.Fatalf("live line %d bits = %#v, want %d", finding.StartLine, keyLength.Bits, *expected.bits)
			}
			if keyLength.SourceCall.FunctionName != "javax.crypto.KeyGenerator.init" ||
				keyLength.SourceCall.Line != finding.StartLine || keyLength.SourceCall.ParameterIndex != 0 {
				t.Fatalf("live line %d source_call = %#v, want init line %d parameter 0", finding.StartLine, keyLength.SourceCall, finding.StartLine)
			}
		}
	}

	fragmentExport := BuildGraphFragmentExport(result)
	fragmentBytes, err := json.Marshal(fragmentExport)
	if err != nil {
		t.Fatalf("json.Marshal fragment: %v", err)
	}
	component := graphfrag.ComponentKey{Purl: "pkg:maven/issue272/key-app", Version: "1.0.0"}
	fragment, err := graphfrag.DecodeFragment(component, fragmentBytes)
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}
	stitched, err := graphfrag.Stitch(component, graphfrag.DependencyGraph{component: nil}, map[graphfrag.ComponentKey]graphfrag.Fragment{component: fragment})
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	stitchedExport := stitched.ToCallgraphExport(component, graphfrag.ScanMeta{Ecosystem: "java"})
	for _, finding := range report.Findings[0].CryptographicAssets {
		keyLength := stitchedKeyLengthForFinding(stitchedExport, finding.FindingID)
		liveKeyLength := liveKeyLengthForFinding(live, finding.FindingID)
		if (keyLength == nil) != (liveKeyLength == nil) {
			t.Fatalf("line %d stitched/live presence mismatch: stitched=%#v live=%#v", finding.StartLine, keyLength, liveKeyLength)
		}
		if keyLength == nil {
			continue
		}
		if keyLength.Provenance != liveKeyLength.Provenance ||
			(keyLength.Bits == nil) != (liveKeyLength.Bits == nil) ||
			(keyLength.Bits != nil && *keyLength.Bits != *liveKeyLength.Bits) ||
			keyLength.SourceCall != liveKeyLength.SourceCall {
			t.Fatalf("line %d stitched/live key length mismatch: stitched=%#v live=%#v", finding.StartLine, keyLength, liveKeyLength)
		}
	}
}

func intPointer(value int) *int { return &value }

func liveKeyLengthForFinding(export callGraphExportV2, findingID string) *graphfrag.ResolvedKeyLength {
	for _, finding := range export.FindingGraphs {
		if finding.FindingID != findingID {
			continue
		}
		for _, chain := range finding.CallChains {
			for _, node := range chain {
				if node.CryptoCall != nil {
					return node.CryptoCall.ResolvedKeyLength
				}
			}
		}
	}
	return nil
}

func stitchedKeyLengthForFinding(export graphfrag.CallgraphExport, findingID string) *graphfrag.ResolvedKeyLength {
	for _, finding := range export.FindingGraphs {
		if finding.FindingID != findingID {
			continue
		}
		for _, chain := range finding.CallChains {
			for _, node := range chain {
				if node.CryptoCall != nil {
					return node.CryptoCall.ResolvedKeyLength
				}
			}
		}
	}
	return nil
}
