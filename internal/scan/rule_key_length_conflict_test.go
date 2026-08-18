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

// TestRuleKeyLengthConflict_JavaFixtureAcrossExports drives the same Java
// fixture as the resolved key-length test, but varies the static keyLength the
// detection rule declares. The callgraph resolves 256 bits on line 9 and leaves
// line 15 unresolved, so the marker must appear only where the rule declared a
// different, comparable value.
func TestRuleKeyLengthConflict_JavaFixtureAcrossExports(t *testing.T) {
	for _, tc := range []struct {
		name string
		// declared is the rule's crypto.keyLength metadata value.
		declared string
		// wantConflict is the expectation for the finding whose supporting
		// KeyGenerator.init(256) resolves to 256 bits.
		wantConflict     bool
		wantDeclaredBits *int
	}{
		{name: "agreement", declared: "256"},
		{name: "disagreement", declared: "128", wantConflict: true, wantDeclaredBits: intPointer(128)},
		{name: "rule declares nothing", declared: ""},
		{name: "rule declares a non-numeric value", declared: "AES-256"},
		{name: "rule declares a non-positive value", declared: "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, graph, fixtureDir := ruleKeyLengthConflictFixture(t, tc.declared)
			result := &engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java", ProjectRoot: fixtureDir}

			live := buildCallGraphExportV2(result)
			fragmentExport := BuildGraphFragmentExport(result)
			fragmentBytes, err := json.Marshal(fragmentExport)
			if err != nil {
				t.Fatalf("json.Marshal fragment: %v", err)
			}
			component := graphfrag.ComponentKey{Purl: "pkg:maven/issue274/key-app", Version: "1.0.0"}
			fragment, err := graphfrag.DecodeFragment(component, fragmentBytes)
			if err != nil {
				t.Fatalf("DecodeFragment: %v", err)
			}
			annotated := BuildAnnotateExport(report, fragment)
			stitched, err := graphfrag.Stitch(component, graphfrag.DependencyGraph{component: nil}, map[graphfrag.ComponentKey]graphfrag.Fragment{component: fragment})
			if err != nil {
				t.Fatalf("Stitch: %v", err)
			}
			stitchedExport := stitched.ToCallgraphExport(component, graphfrag.ScanMeta{Ecosystem: "java"})

			resolvedID := findingIDForLine(t, report, 10)
			unresolvedID := findingIDForLine(t, report, 16)
			for _, export := range []struct {
				name  string
				value any
			}{
				{name: "live", value: live},
				{name: "annotate", value: annotated},
				{name: "stitched", value: stitchedExport},
			} {
				// The resolved 256-bit evidence keeps the callgraph value primary
				// and only retains the rule value when the two disagree.
				assertConflictMarker(t, export.name, export.value, resolvedID, intPointer(256), tc.wantConflict, tc.wantDeclaredBits)
				// An unresolved key length is not a disagreement, whatever the
				// rule declared.
				assertConflictMarker(t, export.name, export.value, unresolvedID, nil, false, nil)
			}
		})
	}
}

// TestApplyRuleKeyLengthConflict_ClearsStaleMarker pins the idempotence the
// annotate path relies on: evidence carried over from an earlier evaluation is
// reconciled against the rule metadata handed in now, not merged with it.
func TestApplyRuleKeyLengthConflict_ClearsStaleMarker(t *testing.T) {
	resolved := &graphfrag.ResolvedKeyLength{
		Bits:             intPointer(256),
		Provenance:       "constant",
		RuleDeclaredBits: intPointer(128),
		RuleConflict:     true,
	}

	applyRuleKeyLengthConflict(resolved, 256)

	if resolved.RuleConflict || resolved.RuleDeclaredBits != nil {
		t.Fatalf("stale marker survived agreement: %#v", resolved)
	}
	if resolved.Bits == nil || *resolved.Bits != 256 {
		t.Fatalf("primary bits = %#v, want 256", resolved.Bits)
	}
}

// ruleKeyLengthConflictFixture builds the Java fixture graph plus a report whose
// findings carry the given rule-declared keyLength metadata.
func ruleKeyLengthConflictFixture(t *testing.T, declared string) (*entities.InterimReport, *callgraph.CallGraph, string) {
	t.Helper()
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

	assets := make([]entities.CryptographicAsset, 0, 3)
	for _, line := range []int{10, 16, 22} {
		metadata := map[string]string{"api": "javax.crypto.KeyGenerator.generateKey"}
		if declared != "" {
			metadata["keyLength"] = declared
		}
		assets = append(assets, entities.CryptographicAsset{
			StartLine: line,
			EndLine:   line,
			Match:     "generator.generateKey()",
			Rules:     []entities.RuleInfo{{ID: "java.jca.keygenerator.generate-key"}},
			Metadata:  metadata,
		})
	}
	report := &entities.InterimReport{
		Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath:            "KeyGeneratorUsage.java",
			Language:            "java",
			CryptographicAssets: assets,
		}},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	return report, graph, fixtureDir
}

func findingIDForLine(t *testing.T, report *entities.InterimReport, line int) string {
	t.Helper()
	for i := range report.Findings[0].CryptographicAssets {
		asset := &report.Findings[0].CryptographicAssets[i]
		if asset.StartLine == line {
			return asset.FindingID
		}
	}
	t.Fatalf("no finding at line %d", line)
	return ""
}

func assertConflictMarker(t *testing.T, exportName string, export any, findingID string, wantBits *int, wantConflict bool, wantDeclaredBits *int) {
	t.Helper()
	supporting, ok := supportingKeyLengthForFinding(export, findingID)
	if !ok || supporting == nil {
		t.Fatalf("%s export: finding %s has no supporting key-length evidence", exportName, findingID)
	}
	if wantBits == nil && supporting.Bits != nil {
		t.Fatalf("%s export: finding %s bits = %d, want absent", exportName, findingID, *supporting.Bits)
	}
	if wantBits != nil && (supporting.Bits == nil || *supporting.Bits != *wantBits) {
		t.Fatalf("%s export: finding %s bits = %#v, want %d — the callgraph value stays primary", exportName, findingID, supporting.Bits, *wantBits)
	}
	if supporting.RuleConflict != wantConflict {
		t.Fatalf("%s export: finding %s rule_conflict = %t, want %t (evidence %#v)", exportName, findingID, supporting.RuleConflict, wantConflict, supporting)
	}
	switch {
	case wantDeclaredBits == nil && supporting.RuleDeclaredBits != nil:
		t.Fatalf("%s export: finding %s rule_declared_bits = %d, want absent", exportName, findingID, *supporting.RuleDeclaredBits)
	case wantDeclaredBits != nil && (supporting.RuleDeclaredBits == nil || *supporting.RuleDeclaredBits != *wantDeclaredBits):
		t.Fatalf("%s export: finding %s rule_declared_bits = %#v, want %d", exportName, findingID, supporting.RuleDeclaredBits, *wantDeclaredBits)
	}
}
