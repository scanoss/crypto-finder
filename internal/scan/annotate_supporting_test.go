// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// supportingFixtureSrc has two independent crypto-object lifecycles so the tests
// can treat one as already-mined (R1) and the other as introduced by a new rule
// (R2). Each object: constructor -> config call -> terminal, the receiver-var
// idiom the supporting-call derivation keys on.
const supportingFixtureSrc = `package com.app;

class Svc {
    void run() {
        Maker a = new Maker();
        a.configure();
        a.finish();
        Other b = new Other();
        b.prepare();
        b.execute();
    }
}
`

func buildSupportingGraph(t *testing.T) (*callgraph.CallGraph, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Svc.java"), []byte(supportingFixtureSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.app:app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph, dir
}

// reportForTerminal hand-builds a detection report with a single terminal crypto
// finding on the given line (relative file path, as the scanner emits).
func reportForTerminal(t *testing.T, line int, match, api string) *entities.InterimReport {
	t.Helper()
	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "Svc.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: line,
				EndLine:   line,
				Match:     match,
				Rules:     []entities.RuleInfo{{ID: "test.rule"}},
				Metadata:  map[string]string{"api": api, "assetType": "algorithm"},
			}},
		}},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	return report
}

func decodeFragmentForTest(t *testing.T, data []byte) graphfrag.Fragment {
	t.Helper()
	frag, err := graphfrag.DecodeFragment(graphfrag.ComponentKey{}, data)
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}
	return frag
}

func marshalSorted(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestAnnotateSupportingCalls_ByteIdenticalToFullExport is the Option-B identity
// gate: re-deriving supporting_calls from the cached fragment (no live callgraph)
// must reproduce a full --export-graph-fragment for the SAME source + rules.
func TestAnnotateSupportingCalls_ByteIdenticalToFullExport(t *testing.T) {
	t.Parallel()
	graph, dir := buildSupportingGraph(t)
	report := reportForTerminal(t, 7, "a.finish()", "com.app.Maker.finish")

	full := BuildGraphFragmentExport(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java",
	})
	if len(full.SupportingCalls) == 0 {
		t.Fatal("fixture produced no supporting calls; cannot test equivalence")
	}

	fragment := decodeFragmentForTest(t, marshalSorted(t, full))
	annotate := BuildAnnotateExport(report, fragment)

	if got, want := marshalSorted(t, annotate.SupportingCalls), marshalSorted(t, full.SupportingCalls); !bytes.Equal(got, want) {
		t.Fatalf("supporting_calls diverge (identity case).\n full:     %s\n annotate: %s", want, got)
	}
}

// TestAnnotateSupportingCalls_ChangedRules_NewFinding is the core Option-B promise:
// a component mined under R1 (its fragment carries the full, rules-independent
// edge structure) can have supporting_calls for a finding a NEW rule (R2)
// introduces re-derived from that cached fragment alone — matching a full scan @ R2.
func TestAnnotateSupportingCalls_ChangedRules_NewFinding(t *testing.T) {
	t.Parallel()
	graph, dir := buildSupportingGraph(t)

	// R1: only object A is a finding. The fragment is built from this run.
	reportR1 := reportForTerminal(t, 7, "a.finish()", "com.app.Maker.finish")
	fullR1 := BuildGraphFragmentExport(&engine.DepScanResult{
		Report: reportR1, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java",
	})
	fragmentR1 := decodeFragmentForTest(t, marshalSorted(t, fullR1))

	// R2: a new rule now flags object B's terminal (line 10) instead.
	reportR2 := reportForTerminal(t, 10, "b.execute()", "com.app.Other.execute")
	fullR2 := BuildGraphFragmentExport(&engine.DepScanResult{
		Report: reportR2, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java",
	})
	if len(fullR2.SupportingCalls) == 0 {
		t.Fatal("R2 fixture produced no supporting calls; cannot test equivalence")
	}

	// Annotate the R1-era fragment with the R2 report — no live callgraph.
	annotateR2 := BuildAnnotateExport(reportR2, fragmentR1)

	if got, want := marshalSorted(t, annotateR2.SupportingCalls), marshalSorted(t, fullR2.SupportingCalls); !bytes.Equal(got, want) {
		t.Fatalf("changed-rules supporting_calls diverge: a new rule's finding did not re-derive its lifecycle from the cached fragment.\n full@R2:     %s\n annotate@R2: %s", want, got)
	}
}

// TestAnnotateCryptoCall_ReDerivedFromStructuralOnlyFragment models the
// mining-service reality: the cached fragment is structural-only (code graph,
// NO crypto operations — those are rules-versioned elsewhere). Carry-forward
// therefore finds no prior crypto_call, so the terminal crypto_call must be
// re-derived from the cached edges and match a full export's crypto_annotations.
func TestAnnotateCryptoCall_ReDerivedFromStructuralOnlyFragment(t *testing.T) {
	t.Parallel()
	graph, dir := buildSupportingGraph(t)
	report := reportForTerminal(t, 7, "a.finish()", "com.app.Maker.finish")

	full := BuildGraphFragmentExport(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java",
	})
	if len(full.CryptoAnnotations) == 0 {
		t.Fatal("fixture produced no crypto annotations")
	}

	// Decode then STRIP crypto operations — exactly what component_code_graphs holds.
	fragment := decodeFragmentForTest(t, marshalSorted(t, full))
	fragment.CryptoOperations = nil

	annotate := BuildAnnotateExport(report, fragment)

	if got, want := marshalSorted(t, annotate.CryptoAnnotations), marshalSorted(t, full.CryptoAnnotations); !bytes.Equal(got, want) {
		t.Fatalf("crypto_annotations diverge from a structural-only fragment (crypto_call not re-derived).\n full:     %s\n annotate: %s", want, got)
	}
}
