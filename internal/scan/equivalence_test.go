// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
	"github.com/scanoss/crypto-finder/pkg/graphfrag/equiv"
)

// decodeEquiv marshals any callgraph export (live callGraphExportV2 or stitched
// graphfrag.CallgraphExport — same JSON contract) and decodes it into the shared
// equiv comparison shape.
func decodeEquiv(t *testing.T, v any) equiv.CallgraphExportJSON {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}
	var out equiv.CallgraphExportJSON
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal into equiv shape: %v", err)
	}
	return out
}

// assertEquivClean fails on any HARD divergence between A (live) and B (stitched):
// missing/extra chains, node field mismatches, crypto_entry_points inconsistency,
// or a dangling supporting_call_ids foreign key. KnownDivergences (file_path,
// inferred_return, confidence — documented v1 limitations) are allowed.
func assertEquivClean(t *testing.T, rep *equiv.DiffReport) {
	t.Helper()
	if len(rep.MissingInB) != 0 {
		t.Errorf("chains present in live (A) but MISSING from stitched (B): %v", rep.MissingInB)
	}
	if len(rep.ExtraInB) != 0 {
		t.Errorf("chains only in stitched (B), not produced by live (A): %v", rep.ExtraInB)
	}
	if len(rep.NodeFieldMismatches) != 0 {
		t.Errorf("node field mismatches (live vs stitched): %v", rep.NodeFieldMismatches)
	}
	if len(rep.EntryPointDivergences) != 0 {
		t.Errorf("crypto_entry_points inconsistent with stitched chains: %v", rep.EntryPointDivergences)
	}
	if len(rep.SupportingCallIDDivergences) != 0 {
		t.Errorf("supporting_call_ids foreign key broken in stitched export: %v", rep.SupportingCallIDDivergences)
	}
	if len(rep.KnownDivergences) != 0 {
		t.Logf("known (allowed) divergences: %v", rep.KnownDivergences)
	}
}

// liveCallgraphExport parses one module's source with the real builder and runs
// the live callgraph export path (buildCallGraphExportV2) — the schema-6.1
// callgraph a `crypto-finder --export-callgraph` of that component produces.
func liveCallgraphExport(t *testing.T, importPath, file, src string, report *entities.InterimReport) callGraphExportV2 {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: importPath}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return buildCallGraphExportV2(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: importPath, Ecosystem: "java",
	})
}

// TestEquivalence_SingleComponent_StitchMatchesLive is the headline live<->stitch
// contract on REAL parser output: the callgraph a live scan exports for a
// component must equal the callgraph the stitcher builds from that component's
// cached fragment — same finding_graphs, same crypto_entry_points, same
// supporting_calls, and the same per-finding supporting_call_ids foreign key.
//
// This is the automated form of the manual check "stitching a purl reproduces a
// live --export-callgraph". The fixture has a crypto-object lifecycle
// (constructor -> config -> terminal) so the comparison exercises all four
// projections, not just bare chains.
func TestEquivalence_SingleComponent_StitchMatchesLive(t *testing.T) {
	t.Parallel()
	key := graphfrag.ComponentKey{Purl: "pkg:maven/com.app/app", Version: "1.0"}
	report := reportForTerminal(t, 7, "a.finish()", "com.app.Maker.finish")

	// A — live export of the component scanned directly.
	live := liveCallgraphExport(t, "com.app:app", "Svc.java", supportingFixtureSrc, report)

	// B — stitched export from the component's cached fragment (no live callgraph
	// at stitch time; the structure comes from the decoded fragment).
	frag := buildModuleFragment(t, key, "com.app:app", "Svc.java", supportingFixtureSrc, report)
	res, err := graphfrag.Stitch(key, graphfrag.DependencyGraph{}, map[graphfrag.ComponentKey]graphfrag.Fragment{key: frag})
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	stitched := res.ToCallgraphExport(key, graphfrag.ScanMeta{RootModule: "com.app:app", Ecosystem: "java"})

	// Preconditions: the fixture must actually exercise the projections, else a
	// vacuously-clean comparison would give false confidence.
	if len(live.FindingGraphs) == 0 || len(stitched.FindingGraphs) == 0 {
		t.Fatalf("no finding_graphs to compare (live=%d stitched=%d)", len(live.FindingGraphs), len(stitched.FindingGraphs))
	}
	if len(stitched.SupportingCalls) == 0 {
		t.Fatal("fixture produced no supporting_calls; cannot validate the supporting_call_ids FK")
	}

	rep := equiv.Compare(decodeEquiv(t, live), decodeEquiv(t, stitched), res.Suppressed, equiv.Options{})
	assertEquivClean(t, rep)
}

// chainShapes returns the set of root-to-crypto chain shapes in a callgraph
// export, each rendered as its ordered canonical_signature sequence. It is the
// representation-independent identity of a reachability path — independent of how
// the terminal finding_id is keyed (the live scan keys dep findings off the raw
// path; the stitcher off a module@version-prefixed path, a representation detail
// the single-component equiv test pins exactly).
func chainShapes(cg equiv.CallgraphExportJSON) map[string]bool {
	out := make(map[string]bool)
	for _, fg := range cg.FindingGraphs {
		for _, chain := range fg.CallChains {
			parts := make([]string, len(chain))
			for i, node := range chain {
				sig := node.CanonicalSignature
				if sig == "" {
					sig = node.FunctionName
				}
				parts[i] = sig
			}
			out[strings.Join(parts, " -> ")] = true
		}
	}
	return out
}

// TestEquivalence_MultiDep_StitchMatchesLiveScanDependencies is the cross-component
// form of the contract: stitching a component WITH ITS DEPENDENCIES must reproduce
// the same root-to-crypto reachability paths a live `--scan-dependencies` run
// finds. Three modules — app A, a crypto-free bridge B, crypto leaf C — are mined
// in isolation and stitched (A->B->C); the same three parsed together are the live
// reference. The set of chain shapes must be identical.
//
// This compares chain SHAPES (canonical-signature sequences) rather than running
// full equiv.Compare, because dep findings are keyed off different paths in the
// two pipelines (raw vs module@version-prefixed) — that representation detail is
// pinned exactly by the single-component test above; here we validate that the
// stitched closure surfaces neither fewer nor more reachability paths than live.
func TestEquivalence_MultiDep_StitchMatchesLiveScanDependencies(t *testing.T) {
	t.Parallel()

	appSrc := `package com.app;
import com.bridge.Bridge;
class App {
    Bridge bridge;
    void execute() {
        bridge.run();
    }
}
`
	bridgeSrc := `package com.bridge;
import com.crypto.CryptoLeaf;
class Bridge {
    CryptoLeaf leaf;
    void run() {
        leaf.generate();
    }
}
`
	cryptoSrc := `package com.crypto;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
class CryptoLeaf {
    void generate() {
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.generateKeyPair();
    }
}
`
	cReport := func() *entities.InterimReport {
		r := &entities.InterimReport{
			Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
			Rules: entities.RulesInfo{Version: "v-test"},
			Findings: []entities.Finding{{
				FilePath: "CryptoLeaf.java",
				Language: "java",
				CryptographicAssets: []entities.CryptographicAsset{{
					StartLine: 6, EndLine: 6,
					Match:    "gen.generateKeyPair()",
					Rules:    []entities.RuleInfo{{ID: "java.bouncycastle.keygen.ec"}},
					Metadata: map[string]string{"api": "org.bouncycastle.crypto.generators.ECKeyPairGenerator.generateKeyPair", "assetType": "algorithm"},
				}},
			}},
		}
		engine.EnsureFindingSources(r)
		engine.AssignFindingIDs(r)
		return r
	}

	// --- live --scan-dependencies reference: all three modules parsed as one graph ---
	dir := t.TempDir()
	for _, f := range []struct{ name, src string }{
		{"App.java", appSrc}, {"Bridge.java", bridgeSrc}, {"CryptoLeaf.java", cryptoSrc},
	} {
		if err := os.WriteFile(filepath.Join(dir, f.name), []byte(f.src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	liveGraph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.app:app"}}, nil)
	if err != nil {
		t.Fatalf("live BuildFromDirectories: %v", err)
	}
	live := buildCallGraphExportV2(&engine.DepScanResult{
		Report: cReport(), CallGraph: liveGraph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java",
	})

	// --- stitched: each module mined in isolation, then stitched A->B->C ---
	a := graphfrag.ComponentKey{Purl: "pkg:maven/com.app/a", Version: "1.0"}
	b := graphfrag.ComponentKey{Purl: "pkg:maven/com.bridge/b", Version: "1.0"}
	c := graphfrag.ComponentKey{Purl: "pkg:maven/com.crypto/c", Version: "1.0"}
	frags := map[graphfrag.ComponentKey]graphfrag.Fragment{
		a: buildModuleFragment(t, a, "com.app:a", "App.java", appSrc, nil),
		b: buildModuleFragment(t, b, "com.bridge:b", "Bridge.java", bridgeSrc, nil),
		c: buildModuleFragment(t, c, "com.crypto:c", "CryptoLeaf.java", cryptoSrc, cReport()),
	}
	res, err := graphfrag.Stitch(a, graphfrag.DependencyGraph{a: {b}, b: {c}}, frags)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	stitched := res.ToCallgraphExport(a, graphfrag.ScanMeta{RootModule: "com.app:app", Ecosystem: "java"})

	liveShapes := chainShapes(decodeEquiv(t, live))
	stitchedShapes := chainShapes(decodeEquiv(t, stitched))

	if len(liveShapes) == 0 || len(stitchedShapes) == 0 {
		t.Fatalf("no chain shapes to compare (live=%d stitched=%d)", len(liveShapes), len(stitchedShapes))
	}

	// Both must surface the full A->B->C path to C's keygen call.
	var spanning string
	for s := range stitchedShapes {
		if strings.Contains(s, "com.app.App") && strings.Contains(s, "com.bridge.Bridge") && strings.Contains(s, "com.crypto.CryptoLeaf") {
			spanning = s
		}
	}
	if spanning == "" {
		t.Fatalf("stitched export has no A->B->C spanning chain; shapes=%v", sortedKeys(stitchedShapes))
	}

	if missing := diffShapes(liveShapes, stitchedShapes); len(missing) != 0 {
		t.Errorf("live reachability paths MISSING from stitched closure: %v", missing)
	}
	if extra := diffShapes(stitchedShapes, liveShapes); len(extra) != 0 {
		t.Errorf("stitched closure invented reachability paths absent from live: %v", extra)
	}
}

// diffShapes returns the chain shapes in a that are not in b.
func diffShapes(a, b map[string]bool) []string {
	var out []string
	for s := range a {
		if !b[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
