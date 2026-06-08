// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
	"github.com/scanoss/crypto-finder/pkg/graphfrag/equiv"
)

// clinitFixtureSrc places a crypto finding inside a `static { ... }` initializer
// block — code that lives OUTSIDE any method or constructor body. Before the
// synthetic `<clinit>` fix, this finding had no containing function and surfaced
// as a degenerate single-node chain with a blank
// `{"function_name":"","file_path":""}` frame. The class has no methods, so the
// only function the finding can map to is the synthetic class-init function.
const clinitFixtureSrc = `package com.app;

class Registrar {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}
`

// TestEquivalence_StaticBlockFinding_MapsToClinit is the end-to-end recall gate
// for the class-init fix. A crypto finding inside a static initializer block must
// (1) be live<->stitch equivalent and (2) produce a NON-EMPTY chain whose
// terminal frame is populated with the synthetic `<clinit>` function — not the
// blank `{"function_name":"","file_path":""}` frame the old code emitted.
func TestEquivalence_StaticBlockFinding_MapsToClinit(t *testing.T) {
	t.Parallel()
	key := graphfrag.ComponentKey{Purl: "pkg:maven/com.app/app", Version: "1.0"}

	// Finding sits on line 5 — `Security.addProvider(...)` inside the static block.
	report := reportForStaticBlock(t, 5, "Security.addProvider(new BouncyCastleProvider())", map[string]string{"api": "", "assetType": "algorithm"})

	// A — live export of the component scanned directly.
	live := liveCallgraphExport(t, "Registrar.java", clinitFixtureSrc, report)

	// B — stitched export from the component's cached fragment.
	frag := buildModuleFragment(t, key, "com.app:app", "Registrar.java", clinitFixtureSrc, reportForStaticBlock(t, 5, "Security.addProvider(new BouncyCastleProvider())", map[string]string{"api": "", "assetType": "algorithm"}))
	res, err := graphfrag.Stitch(key, graphfrag.DependencyGraph{}, map[graphfrag.ComponentKey]graphfrag.Fragment{key: frag})
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	stitched := res.ToCallgraphExport(key, graphfrag.ScanMeta{RootModule: "com.app:app", Ecosystem: "java"})

	// Live and stitched must agree on the whole callgraph contract.
	rep := equiv.Compare(decodeEquiv(t, live), decodeEquiv(t, stitched), res.Suppressed, equiv.Options{})
	assertEquivClean(t, rep)

	// Recall: the finding must have a non-empty chain whose terminal frame is the
	// `<clinit>` function — the blank-frame regression must be gone.
	assertClinitFrame(t, decodeEquiv(t, live), "live")
	assertClinitFrame(t, decodeEquiv(t, stitched), "stitched")
}

// assertClinitFrame fails unless the export has at least one finding_graph with a
// non-empty call chain whose nodes all carry a populated function_name, and at
// least one node resolves to the synthetic `<clinit>` function.
func assertClinitFrame(t *testing.T, cg equiv.CallgraphExportJSON, label string) {
	t.Helper()
	if len(cg.FindingGraphs) == 0 {
		t.Fatalf("%s: no finding_graphs", label)
	}
	sawChain := false
	sawClinit := false
	for _, fg := range cg.FindingGraphs {
		for _, chain := range fg.CallChains {
			if len(chain) == 0 {
				continue
			}
			sawChain = true
			for i := range chain {
				node := &chain[i]
				if node.FunctionName == "" {
					t.Errorf("%s: blank frame regression — chain node has empty function_name: %+v", label, node)
				}
				id := node.FunctionName
				if node.CanonicalSignature != "" {
					id = node.CanonicalSignature
				}
				if strings.Contains(id, "<clinit>") {
					sawClinit = true
				}
			}
		}
	}
	if !sawChain {
		t.Errorf("%s: finding produced no non-empty call chain (recall failure — orphan finding)", label)
	}
	if !sawClinit {
		t.Errorf("%s: no chain node maps to the synthetic <clinit> function", label)
	}
}

// reportForStaticBlock hand-builds a detection report with a single terminal
// crypto finding on the given line of Registrar.java.
func reportForStaticBlock(t *testing.T, line int, match string, metadata map[string]string) *entities.InterimReport {
	t.Helper()
	if metadata == nil {
		metadata = map[string]string{"assetType": "algorithm"}
	}
	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "Registrar.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: line,
				EndLine:   line,
				Match:     match,
				Rules:     []entities.RuleInfo{{ID: "test.static.provider"}},
				Metadata:  metadata,
			}},
		}},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	return report
}
