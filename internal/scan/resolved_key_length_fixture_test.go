// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"path/filepath"
	"reflect"
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

	initCalls := make(map[int]*callgraph.FunctionCall)
	generateKeyCalls := make(map[int]*callgraph.FunctionCall)
	for _, function := range graph.Functions {
		for i := range function.Calls {
			call := &function.Calls[i]
			if call.Callee.Package != "javax.crypto" || call.Callee.Type != "KeyGenerator" {
				continue
			}
			switch call.Callee.Name {
			case "init#1":
				initCalls[call.Line] = call
			case "generateKey#0":
				generateKeyCalls[call.Line] = call
			}
		}
	}
	if len(initCalls) != 3 || len(generateKeyCalls) != 3 {
		t.Fatalf("parser captured init#1=%d and generateKey#0=%d, want three of each", len(initCalls), len(generateKeyCalls))
	}
	for _, tc := range []struct {
		line     int
		argument string
		declared string
	}{
		{line: 9, argument: "256"},
		{line: 15, argument: "keyBits", declared: "int"},
		{line: 21, argument: "parameters", declared: "java.security.spec.AlgorithmParameterSpec"},
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
				{StartLine: 10, EndLine: 10, Match: "generator.generateKey()", Rules: []entities.RuleInfo{{ID: "java.jca.keygenerator.generate-key"}}, Metadata: map[string]string{"api": "javax.crypto.KeyGenerator.generateKey"}},
				{StartLine: 16, EndLine: 16, Match: "generator.generateKey()", Rules: []entities.RuleInfo{{ID: "java.jca.keygenerator.generate-key"}}, Metadata: map[string]string{"api": "javax.crypto.KeyGenerator.generateKey"}},
				{StartLine: 22, EndLine: 22, Match: "generator.generateKey()", Rules: []entities.RuleInfo{{ID: "java.jca.keygenerator.generate-key"}}, Metadata: map[string]string{"api": "javax.crypto.KeyGenerator.generateKey"}},
			},
		}},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	result := &engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java", ProjectRoot: fixtureDir}

	want := map[int]struct {
		initLine   int
		provenance string
		bits       *int
		wantAbsent bool
	}{
		10: {initLine: 9, provenance: "constant", bits: intPointer(256)},
		16: {initLine: 15, provenance: "unknown"},
		22: {initLine: 21, wantAbsent: true},
	}
	live := buildCallGraphExportV2(result)
	for i := range report.Findings[0].CryptographicAssets {
		finding := &report.Findings[0].CryptographicAssets[i]
		expected := want[finding.StartLine]
		assertNoTerminalKeyLength(t, live, finding.FindingID)
		assertSupportingKeyLength(t, live, finding.FindingID, expected.initLine, expected.provenance, expected.bits, expected.wantAbsent)
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
	annotated := BuildAnnotateExport(report, fragment)
	for i := range report.Findings[0].CryptographicAssets {
		finding := &report.Findings[0].CryptographicAssets[i]
		expected := want[finding.StartLine]
		assertNoTerminalKeyLength(t, annotated, finding.FindingID)
		assertSupportingKeyLength(t, annotated, finding.FindingID, expected.initLine, expected.provenance, expected.bits, expected.wantAbsent)
	}
	stitched, err := graphfrag.Stitch(component, graphfrag.DependencyGraph{component: nil}, map[graphfrag.ComponentKey]graphfrag.Fragment{component: fragment})
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	stitchedExport := stitched.ToCallgraphExport(component, graphfrag.ScanMeta{Ecosystem: "java"})
	for i := range report.Findings[0].CryptographicAssets {
		finding := &report.Findings[0].CryptographicAssets[i]
		expected := want[finding.StartLine]
		assertNoTerminalKeyLength(t, stitchedExport, finding.FindingID)
		assertSupportingKeyLength(t, stitchedExport, finding.FindingID, expected.initLine, expected.provenance, expected.bits, expected.wantAbsent)
		liveSupporting, liveOK := supportingKeyLengthForFinding(live, finding.FindingID)
		stitchedSupporting, stitchedOK := supportingKeyLengthForFinding(stitchedExport, finding.FindingID)
		if liveOK != stitchedOK || (liveOK && !reflect.DeepEqual(liveSupporting, stitchedSupporting)) {
			t.Fatalf("line %d stitched/live supporting-call mismatch: stitched=%#v live=%#v", finding.StartLine, stitchedSupporting, liveSupporting)
		}
	}
}

func intPointer(value int) *int { return &value }

func assertNoTerminalKeyLength(t *testing.T, export any, findingID string) {
	t.Helper()
	var got *graphfrag.ResolvedKeyLength
	switch value := export.(type) {
	case callGraphExportV2:
		got = terminalKeyLengthForFinding(value, findingID)
	case graphfrag.CallgraphExport:
		got = terminalKeyLengthForFinding(value, findingID)
	case graphfrag.GraphFragmentExport:
		got = terminalKeyLengthForFinding(value, findingID)
	}
	if got != nil {
		t.Fatalf("finding %s terminal crypto-call key-length field = %#v, want absent", findingID, got)
	}
}

func assertSupportingKeyLength(t *testing.T, export any, findingID string, initLine int, provenance string, bits *int, wantAbsent bool) {
	t.Helper()
	var supporting *graphfrag.ResolvedKeyLength
	var ok bool
	switch value := export.(type) {
	case callGraphExportV2:
		supporting, ok = supportingKeyLengthForFinding(value, findingID)
	case graphfrag.CallgraphExport:
		supporting, ok = supportingKeyLengthForFinding(value, findingID)
	case graphfrag.GraphFragmentExport:
		supporting, ok = supportingKeyLengthForFinding(value, findingID)
	}
	if !ok {
		t.Fatalf("finding %s has no derived KeyGenerator.init supporting call", findingID)
	}
	if wantAbsent && supporting != nil {
		t.Fatalf("finding %s non-int supporting call ResolvedKeyLength = %#v, want absent", findingID, supporting)
	}
	if wantAbsent {
		return
	}
	if supporting == nil {
		t.Fatalf("finding %s supporting ResolvedKeyLength = nil, want %q", findingID, provenance)
	}
	if supporting.Provenance != provenance || supporting.SourceCall.FunctionName != "javax.crypto.KeyGenerator.init" || supporting.SourceCall.Line != initLine || supporting.SourceCall.ParameterIndex != 0 {
		t.Fatalf("finding %s supporting key-length evidence = %#v, want provenance=%q init line %d parameter 0", findingID, supporting, provenance, initLine)
	}
	if bits == nil && supporting.Bits != nil {
		t.Fatalf("finding %s supporting bits = %v, want absent for unresolved input", findingID, *supporting.Bits)
	}
	if bits != nil && (supporting.Bits == nil || *supporting.Bits != *bits) {
		t.Fatalf("finding %s supporting bits = %#v, want %d", findingID, supporting.Bits, *bits)
	}
}

func supportingKeyLengthForFinding(export any, findingID string) (*graphfrag.ResolvedKeyLength, bool) {
	var ids []string
	var supportingCalls []struct {
		ID   string
		Call any
	}
	switch value := export.(type) {
	case callGraphExportV2:
		for i := range value.FindingGraphs {
			finding := &value.FindingGraphs[i]
			if finding.FindingID == findingID {
				ids = append(ids, finding.SupportingCallIDs...)
				break
			}
		}
		for i := range value.SupportingCalls {
			supportingCalls = append(supportingCalls, struct {
				ID   string
				Call any
			}{value.SupportingCalls[i].SupportingID, value.SupportingCalls[i].SupportingCall})
		}
	case graphfrag.CallgraphExport:
		for i := range value.FindingGraphs {
			finding := &value.FindingGraphs[i]
			if finding.FindingID == findingID {
				ids = append(ids, finding.SupportingCallIDs...)
				break
			}
		}
		for i := range value.SupportingCalls {
			supportingCalls = append(supportingCalls, struct {
				ID   string
				Call any
			}{value.SupportingCalls[i].SupportingID, value.SupportingCalls[i].SupportingCall})
		}
	case graphfrag.GraphFragmentExport:
		for i := range value.CryptoAnnotations {
			finding := &value.CryptoAnnotations[i]
			if finding.FindingID == findingID {
				ids = append(ids, finding.SupportingCallIDs...)
				break
			}
		}
		for i := range value.SupportingCalls {
			supportingCalls = append(supportingCalls, struct {
				ID   string
				Call any
			}{value.SupportingCalls[i].SupportingID, value.SupportingCalls[i].SupportingCall})
		}
	}
	for i := range ids {
		id := ids[i]
		for j := range supportingCalls {
			supporting := &supportingCalls[j]
			if supporting.ID != id {
				continue
			}
			switch call := supporting.Call.(type) {
			case *callGraphCalledFunction:
				if call != nil && call.FunctionName == "javax.crypto.KeyGenerator.init" {
					return call.ResolvedKeyLength, true
				}
			case *graphfrag.ExportCryptoCall:
				if call != nil && call.FunctionName == "javax.crypto.KeyGenerator.init" {
					return call.ResolvedKeyLength, true
				}
			case *graphfrag.GraphFragmentCryptoCall:
				if call != nil && call.FunctionName == "javax.crypto.KeyGenerator.init" {
					return call.ResolvedKeyLength, true
				}
			}
		}
	}
	return nil, false
}

func terminalKeyLengthForFinding(export any, findingID string) *graphfrag.ResolvedKeyLength {
	switch value := export.(type) {
	case callGraphExportV2:
		for i := range value.FindingGraphs {
			finding := &value.FindingGraphs[i]
			if finding.FindingID != findingID {
				continue
			}
			for chainIndex := range finding.CallChains {
				chain := finding.CallChains[chainIndex]
				for nodeIndex := range chain {
					node := &chain[nodeIndex]
					if node.CryptoCall != nil {
						return node.CryptoCall.ResolvedKeyLength
					}
				}
			}
		}
	case graphfrag.CallgraphExport:
		for i := range value.FindingGraphs {
			finding := &value.FindingGraphs[i]
			if finding.FindingID != findingID {
				continue
			}
			for chainIndex := range finding.CallChains {
				chain := finding.CallChains[chainIndex]
				for nodeIndex := range chain {
					node := &chain[nodeIndex]
					if node.CryptoCall != nil {
						return node.CryptoCall.ResolvedKeyLength
					}
				}
			}
		}
	case graphfrag.GraphFragmentExport:
		for i := range value.CryptoAnnotations {
			finding := &value.CryptoAnnotations[i]
			if finding.FindingID == findingID && finding.CryptoCall != nil {
				return finding.CryptoCall.ResolvedKeyLength
			}
		}
	}
	return nil
}
