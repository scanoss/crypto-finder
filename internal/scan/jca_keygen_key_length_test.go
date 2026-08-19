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

// TestJcaKeygenKeyLength_EntryPointsResolveConstantBits covers the canonical JCA
// key-generation entry points end to end: the parser builds the graph, the live
// export resolves each configured key size, and the stitched export preserves
// the same evidence.
func TestJcaKeygenKeyLength_EntryPointsResolveConstantBits(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	fixtureDir := filepath.Join(filepath.Dir(testFile), "testdata", "jca_keygen_key_length")

	builder := callgraph.NewBuilderForEcosystem("java", callgraph.NewJavaParser())
	graph, err := builder.BuildFromDirectories([]callgraph.PackageDir{{Dir: fixtureDir, ImportPath: "issue273"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	// Terminal findings, keyed by the line the rule would match.
	terminals := map[int]string{
		14: "generator.generateKeyPair()",
		20: "generator.generateKeyPair()",
		27: "generator.generateKeyPair()",
		34: "generator.generateKeyPair()",
		41: "cipher.doFinal(new byte[0])",
		48: "cipher.doFinal(new byte[0])",
		54: "generator.generateKeyPair()",
	}
	assets := make([]entities.CryptographicAsset, 0, len(terminals))
	for _, line := range []int{14, 20, 27, 34, 41, 48, 54} {
		assets = append(assets, entities.CryptographicAsset{
			StartLine: line,
			EndLine:   line,
			Match:     terminals[line],
			Rules:     []entities.RuleInfo{{ID: "java.jca.keygen"}},
		})
	}
	report := &entities.InterimReport{
		Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath:            "JcaKeygenUsage.java",
			Language:            "java",
			CryptographicAssets: assets,
		}},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	result := &engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java", ProjectRoot: fixtureDir}

	type expectation struct {
		entryPoint string
		provenance string
		bits       *int
	}
	want := map[int]expectation{
		14: {entryPoint: "java.security.KeyPairGenerator.initialize", provenance: "constant", bits: intPointer(2048)},
		20: {entryPoint: "java.security.KeyPairGenerator.initialize", provenance: "constant", bits: intPointer(3072)},
		27: {entryPoint: "java.security.spec.RSAKeyGenParameterSpec.<init>", provenance: "constant", bits: intPointer(4096)},
		34: {entryPoint: "java.security.spec.ECGenParameterSpec.<init>", provenance: "constant", bits: intPointer(256)},
		41: {entryPoint: "javax.crypto.spec.SecretKeySpec.<init>", provenance: "constant", bits: intPointer(256)},
		48: {entryPoint: "javax.crypto.spec.SecretKeySpec.<init>", provenance: "unknown"},
		54: {entryPoint: "java.security.KeyPairGenerator.initialize", provenance: "unknown"},
	}

	live := buildCallGraphExportV2(result)

	fragmentBytes, err := json.Marshal(BuildGraphFragmentExport(result))
	if err != nil {
		t.Fatalf("json.Marshal fragment: %v", err)
	}
	component := graphfrag.ComponentKey{Purl: "pkg:maven/issue273/keygen-app", Version: "1.0.0"}
	fragment, err := graphfrag.DecodeFragment(component, fragmentBytes)
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}
	stitched, err := graphfrag.Stitch(component, graphfrag.DependencyGraph{component: nil}, map[graphfrag.ComponentKey]graphfrag.Fragment{component: fragment})
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	stitchedExport := stitched.ToCallgraphExport(component, graphfrag.ScanMeta{Ecosystem: "java"})

	for _, export := range []struct {
		name  string
		value any
	}{{name: "live", value: live}, {name: "stitched", value: stitchedExport}} {
		for i := range report.Findings[0].CryptographicAssets {
			finding := &report.Findings[0].CryptographicAssets[i]
			expected := want[finding.StartLine]
			evidence := supportingKeyLengthEvidence(t, export.value, finding.FindingID)
			if len(evidence) != 1 {
				t.Fatalf("%s export line %d: %d supporting calls carry key-length evidence, want exactly 1", export.name, finding.StartLine, len(evidence))
			}
			got := evidence[0]
			if got.SourceCall.FunctionName != expected.entryPoint {
				t.Errorf("%s export line %d: source call = %q, want %q", export.name, finding.StartLine, got.SourceCall.FunctionName, expected.entryPoint)
			}
			if got.Provenance != expected.provenance {
				t.Errorf("%s export line %d: provenance = %q, want %q", export.name, finding.StartLine, got.Provenance, expected.provenance)
			}
			switch {
			case expected.bits == nil && got.Bits != nil:
				t.Errorf("%s export line %d: bits = %d, want absent for unresolved input", export.name, finding.StartLine, *got.Bits)
			case expected.bits != nil && (got.Bits == nil || *got.Bits != *expected.bits):
				t.Errorf("%s export line %d: bits = %#v, want %d", export.name, finding.StartLine, got.Bits, *expected.bits)
			}
		}
	}
}

// supportingKeyLengthEvidence collects the key-length evidence carried by a
// finding's supporting calls. It reads the serialized export so the live,
// fragment, and stitched shapes are all accepted through their wire contract.
func supportingKeyLengthEvidence(t *testing.T, export any, findingID string) []*graphfrag.ResolvedKeyLength {
	t.Helper()
	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("json.Marshal export: %v", err)
	}
	var decoded struct {
		FindingGraphs []struct {
			FindingID         string   `json:"finding_id"`
			SupportingCallIDs []string `json:"supporting_call_ids"`
		} `json:"finding_graphs"`
		SupportingCalls []struct {
			SupportingID   string `json:"supporting_id"`
			SupportingCall struct {
				ResolvedKeyLength *graphfrag.ResolvedKeyLength `json:"resolved_key_length"`
			} `json:"supporting_call"`
		} `json:"supporting_calls"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal export: %v", err)
	}

	keyLengths := make(map[string]*graphfrag.ResolvedKeyLength, len(decoded.SupportingCalls))
	for i := range decoded.SupportingCalls {
		if evidence := decoded.SupportingCalls[i].SupportingCall.ResolvedKeyLength; evidence != nil {
			keyLengths[decoded.SupportingCalls[i].SupportingID] = evidence
		}
	}

	var evidence []*graphfrag.ResolvedKeyLength
	for i := range decoded.FindingGraphs {
		if decoded.FindingGraphs[i].FindingID != findingID {
			continue
		}
		for _, id := range decoded.FindingGraphs[i].SupportingCallIDs {
			if keyLength, ok := keyLengths[id]; ok {
				evidence = append(evidence, keyLength)
			}
		}
	}
	return evidence
}
