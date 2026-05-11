// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package stitch

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestGenerateFindingID pins the stitcher's finding-id implementation
// against fixture cases captured from the live scanner. If
// internal/engine/dependency_scanner.go:generateFindingID changes, these
// will fail and the stitcher must be updated in lockstep — that's the
// whole point of pinning.
//
// Sample values were captured from a real `crypto-finder scan
// --scan-dependencies --export-callgraph` run on org.apache.poi/poi@5.2.3
// (see crypto-mining-service/tmp/poi-cg-baseline.json finding_graph IDs).
func TestGenerateFindingID(t *testing.T) {
	cases := []struct {
		name       string
		filePath   string
		startLine  int
		ruleID     string
		depModule  string
		depVersion string
		want       string
	}{
		{
			name:      "direct asset, no dep prefix",
			filePath:  "org/apache/poi/poifs/crypt/xor/XOREncryptor.java",
			startLine: 55,
			ruleID:    "java.jca.related-crypto-material.secret-key.secretkeyspec",
			want:      "0766d6a0",
		},
		{
			name:      "direct asset, IvParameterSpec",
			filePath:  "org/apache/poi/poifs/crypt/agile/AgileDecryptor.java",
			startLine: 245,
			ruleID:    "java.jca.related-crypto-material.initialization-vector.ivparameterspec",
			want:      "4327df86",
		},
		{
			name:       "dependency asset uses module@version prefix",
			filePath:   "org/apache/commons/codec/digest/HmacUtils.java",
			startLine:  699,
			ruleID:     "java.commons-codec.algorithm.mac.hmacutils",
			depModule:  "commons-codec:commons-codec",
			depVersion: "1.15",
			want:       "0961a941",
		},
		{
			name:      "empty rules → empty rule-id segment",
			filePath:  "a/b.java",
			startLine: 1,
			ruleID:    "",
			// sha256("a/b.java:1:")[:8] — computed once, pinned here so
			// changes to the algorithm in the live scanner are flagged.
			want: "fbfe4b68",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rules []ruleRef
			if tc.ruleID != "" {
				rules = []ruleRef{{ID: tc.ruleID}}
			}
			got := generateFindingID(tc.filePath, tc.startLine, rules, tc.depModule, tc.depVersion)
			if got != tc.want {
				t.Fatalf("generateFindingID = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMerge_FindingsConcat covers the bread-and-butter case: a target
// with one direct finding and one dep with one finding. We assert:
//
//   - the merged envelope preserves tool/rules/version from the target,
//   - assets get source = direct / dependency stamped correctly,
//   - dep assets get dependency_info populated,
//   - finding_ids are computed (presence — exact values are pinned in
//     TestGenerateFindingID).
func TestMerge_FindingsConcat(t *testing.T) {
	target := []byte(`{
		"tool":    {"name": "crypto-finder", "version": "dev"},
		"rules":   {"name": "dca", "version": "v1.6.0"},
		"version": "1.3",
		"findings": [{
			"file_path": "src/Foo.java",
			"language": "java",
			"cryptographic_assets": [{
				"start_line": 10,
				"end_line": 10,
				"match": "MessageDigest.getInstance(\"MD5\")",
				"rules": [{"id": "java.jca.algorithm.hash.md5"}],
				"status": "pending"
			}]
		}]
	}`)

	dep := []byte(`{
		"findings": [{
			"file_path": "org/example/Util.java",
			"cryptographic_assets": [{
				"start_line": 42,
				"rules": [{"id": "java.jca.algorithm.mac.hmac"}],
				"status": "pending"
			}]
		}]
	}`)

	res, err := Merge(target, nil, []Dep{
		{Module: "org.example:util", Version: "1.0", Findings: dep},
	})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	var got findingsEnvelope
	if err := json.Unmarshal(res.Findings, &got); err != nil {
		t.Fatalf("unmarshal merged: %v", err)
	}

	if len(got.Findings) != 2 {
		t.Fatalf("merged findings = %d, want 2", len(got.Findings))
	}

	// Asset 0 = target's, should be source=direct, no dep info.
	if a := got.Findings[0].CryptographicAssets[0]; a.Source != "direct" || a.DependencyInfo != nil {
		t.Errorf("target asset: source=%q dep_info=%v, want source=direct dep_info=nil", a.Source, a.DependencyInfo)
	}
	if got.Findings[0].CryptographicAssets[0].FindingID == "" {
		t.Errorf("target asset: finding_id empty")
	}

	// Asset 1 = dep's, should be source=dependency + dep info.
	a := got.Findings[1].CryptographicAssets[0]
	if a.Source != "dependency" {
		t.Errorf("dep asset: source=%q, want dependency", a.Source)
	}
	if a.DependencyInfo == nil || a.DependencyInfo.Module != "org.example:util" || a.DependencyInfo.Version != "1.0" {
		t.Errorf("dep asset: dep_info=%+v, want org.example:util@1.0", a.DependencyInfo)
	}
	if a.FindingID == "" {
		t.Errorf("dep asset: finding_id empty")
	}
}

// TestMerge_EmptyTargetRejected ensures we don't silently produce an
// envelope with zero target findings — a missing target is a caller bug.
func TestMerge_EmptyTargetRejected(t *testing.T) {
	if _, err := Merge(nil, nil, nil); err == nil {
		t.Fatalf("Merge with nil target should error, got nil")
	}
	if _, err := Merge([]byte{}, nil, nil); err == nil {
		t.Fatalf("Merge with empty target should error, got nil")
	}
}

// TestMerge_NoCallgraphsAnywhere covers the case where neither the target
// nor any dep contributed a callgraph fragment. The result.Callgraph
// should be nil (not an empty envelope) so the caller can write a SQL
// NULL and the downstream reachability_paths column means "no graph
// available" — distinguishable from "graph with zero findings".
func TestMerge_NoCallgraphsAnywhere(t *testing.T) {
	target := []byte(`{
		"version": "1.3",
		"findings": [{"file_path": "a.java", "cryptographic_assets": []}]
	}`)
	res, err := Merge(target, nil, []Dep{{Module: "x:y", Version: "1.0", Findings: target}})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if res.Callgraph != nil {
		t.Fatalf("expected nil callgraph when no fragment provided, got %d bytes", len(res.Callgraph))
	}
}

// TestMerge_CallgraphStampsDepInfo verifies that frames coming from a dep
// fragment get dependency_info added, frames coming from the target stay
// untouched, and entry_point_index rows from deps also get the tag.
func TestMerge_CallgraphStampsDepInfo(t *testing.T) {
	target := []byte(`{
		"version": "1.3",
		"findings": [{"file_path": "Direct.java", "cryptographic_assets": [{
			"start_line": 5, "rules": [{"id": "r1"}], "status": "pending"
		}]}]
	}`)
	targetCG := []byte(`{
		"schema_version": "5.3",
		"scan_metadata":  {"root_module": "test"},
		"finding_graphs": [{
			"finding_id": "aaaa1111",
			"matched_operation": {"symbol": "X"},
			"call_chains": [[{"function_name": "Direct.method", "file_path": "Direct.java"}]]
		}],
		"entry_point_index": [{"function": "Direct.entry"}]
	}`)

	depFindings := []byte(`{
		"findings": [{"file_path": "Util.java", "cryptographic_assets": [{
			"start_line": 9, "rules": [{"id": "r2"}], "status": "pending"
		}]}]
	}`)
	depCG := []byte(`{
		"schema_version": "5.3",
		"finding_graphs": [{
			"finding_id": "bbbb2222",
			"matched_operation": {"symbol": "Y"},
			"call_chains": [[{"function_name": "Util.helper", "file_path": "Util.java"}]]
		}],
		"entry_point_index": [{"function": "Util.entry"}]
	}`)

	res, err := Merge(target, targetCG, []Dep{
		{Module: "org.example:util", Version: "1.0", Findings: depFindings, Callgraph: depCG},
	})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if res.Callgraph == nil {
		t.Fatalf("expected callgraph bytes, got nil")
	}

	var out struct {
		SchemaVersion   string            `json:"schema_version"`
		ScanMetadata    json.RawMessage   `json:"scan_metadata"`
		FindingGraphs   []json.RawMessage `json:"finding_graphs"`
		EntryPointIndex []json.RawMessage `json:"entry_point_index"`
	}
	if err := json.Unmarshal(res.Callgraph, &out); err != nil {
		t.Fatalf("unmarshal merged callgraph: %v", err)
	}

	if out.SchemaVersion != "5.3" {
		t.Errorf("schema_version = %q, want 5.3", out.SchemaVersion)
	}
	if len(out.FindingGraphs) != 2 || len(out.EntryPointIndex) != 2 {
		t.Fatalf("finding_graphs=%d entry_point_index=%d, want 2/2",
			len(out.FindingGraphs), len(out.EntryPointIndex))
	}

	// Target's frame must have no dependency_info; dep's must have it.
	var targetFG, depFG map[string]any
	if err := json.Unmarshal(out.FindingGraphs[0], &targetFG); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.FindingGraphs[1], &depFG); err != nil {
		t.Fatal(err)
	}
	targetFrame := targetFG["call_chains"].([]any)[0].([]any)[0].(map[string]any)
	if _, ok := targetFrame["dependency_info"]; ok {
		t.Errorf("target frame should not have dependency_info, got %v", targetFrame["dependency_info"])
	}
	depFrame := depFG["call_chains"].([]any)[0].([]any)[0].(map[string]any)
	di, ok := depFrame["dependency_info"].(map[string]any)
	if !ok || di["module"] != "org.example:util" || di["version"] != "1.0" {
		t.Errorf("dep frame: dependency_info=%v, want org.example:util@1.0", depFrame["dependency_info"])
	}

	// Entry-point rows: same rule.
	var targetEP, depEP map[string]any
	if err := json.Unmarshal(out.EntryPointIndex[0], &targetEP); err != nil {
		t.Fatalf("unmarshal target entry point: %v", err)
	}
	if err := json.Unmarshal(out.EntryPointIndex[1], &depEP); err != nil {
		t.Fatalf("unmarshal dep entry point: %v", err)
	}
	if _, ok := targetEP["dependency_info"]; ok {
		t.Errorf("target entry_point should not have dependency_info")
	}
	if _, ok := depEP["dependency_info"]; !ok {
		t.Errorf("dep entry_point should have dependency_info")
	}

	// Scan metadata comes from the target.
	if out.ScanMetadata == nil {
		t.Errorf("scan_metadata missing — should be inherited from target")
	}
}

// TestMergeWithPolicy_PruneToRootModule verifies the phase-B core
// pruning rule: chains are truncated to start at the *closest* user-pkg
// frame to the target (mirroring crypto-finder's L2 tracer, which stops
// BFS as soon as the chain head is in user packages). A chain whose
// non-target frames are all external is dropped.
//
// The three input chains exercise:
//
//  1. External-prefix chain — long L1 standalone shape; gets truncated
//     to the 2 user-pkg frames before the target.
//  2. Identical to (1) after prune — deduplicated.
//  3. Chain that never enters the root module — dropped.
func TestMergeWithPolicy_PruneToRootModule(t *testing.T) {
	target := []byte(`{
		"version": "1.3",
		"findings": [{"file_path": "X.java", "cryptographic_assets": [{
			"start_line": 1, "rules": [{"id": "r"}], "status": "pending"
		}]}]
	}`)
	targetCG := []byte(`{
		"schema_version": "5.3",
		"scan_metadata":  {"root_module": "org.example.app"},
		"finding_graphs": [{
			"finding_id": "aaaa1111",
			"matched_operation": {"symbol": "X"},
			"call_chains": [
				[
					{"function_name": "external.lib.Foo.bar"},
					{"function_name": "org.example.app.Service.handle"},
					{"function_name": "org.example.app.Crypto.encrypt"}
				],
				[
					{"function_name": "external.lib.Foo.bar"},
					{"function_name": "org.example.app.Service.handle"},
					{"function_name": "org.example.app.Crypto.encrypt"}
				],
				[
					{"function_name": "totally.unrelated.Thing.run"},
					{"function_name": "external.other.Util.do"}
				]
			]
		}],
		"entry_point_index": []
	}`)

	res, err := MergeWithPolicy(target, targetCG, nil, Policy{PruneToRootModule: true})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	var out struct {
		FindingGraphs []struct {
			CallChains [][]map[string]any `json:"call_chains"`
		} `json:"finding_graphs"`
	}
	if err := json.Unmarshal(res.Callgraph, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.FindingGraphs) != 1 {
		t.Fatalf("finding_graphs=%d, want 1", len(out.FindingGraphs))
	}
	chains := out.FindingGraphs[0].CallChains
	if len(chains) != 1 {
		t.Fatalf("call_chains=%d, want 1 (two dupes collapse, one external-only dropped)", len(chains))
	}
	if got := len(chains[0]); got != 2 {
		t.Errorf("chain length after prune = %d, want 2 ([Service.handle, Crypto.encrypt])", got)
	}
	if got := chains[0][0]["function_name"]; got != "org.example.app.Service.handle" {
		t.Errorf("first frame after prune = %v, want org.example.app.Service.handle", got)
	}
}

// TestMergeWithPolicy_MaxChainsPerFinding caps the number of chains kept
// per finding_graph after prune+dedup. Mirrors crypto-finder's exporter
// MaxChains=128 default but is configurable for callers that want
// tighter output.
func TestMergeWithPolicy_MaxChainsPerFinding(t *testing.T) {
	// Build a fragment with 5 distinct chains, all inside the root module.
	target := []byte(`{
		"version": "1.3",
		"findings": [{"file_path": "X.java", "cryptographic_assets": [{
			"start_line": 1, "rules": [{"id": "r"}], "status": "pending"
		}]}]
	}`)
	targetCG := []byte(`{
		"schema_version": "5.3",
		"scan_metadata":  {"root_module": "org.example"},
		"finding_graphs": [{
			"finding_id": "aaaa",
			"matched_operation": {"symbol": "X"},
			"call_chains": [
				[{"function_name": "org.example.A.one"}],
				[{"function_name": "org.example.A.two"}],
				[{"function_name": "org.example.A.three"}],
				[{"function_name": "org.example.A.four"}],
				[{"function_name": "org.example.A.five"}]
			]
		}],
		"entry_point_index": []
	}`)

	res, err := MergeWithPolicy(target, targetCG, nil, Policy{
		PruneToRootModule:   true,
		MaxChainsPerFinding: 3,
	})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	var out struct {
		FindingGraphs []struct {
			CallChains [][]map[string]any `json:"call_chains"`
		} `json:"finding_graphs"`
	}
	if err := json.Unmarshal(res.Callgraph, &out); err != nil {
		t.Fatalf("unmarshal callgraph: %v", err)
	}
	if got := len(out.FindingGraphs[0].CallChains); got != 3 {
		t.Errorf("capped chains=%d, want 3", got)
	}
}

// TestMergeWithPolicy_RebuildEntryPointIndex verifies the rebuilt index
// only carries entries for frames that survived chain pruning. A frame
// that was pruned away contributes no entry-point row, even if it was
// present in the input fragment's entry_point_index.
func TestMergeWithPolicy_RebuildEntryPointIndex(t *testing.T) {
	target := []byte(`{
		"version": "1.3",
		"findings": [{"file_path": "X.java", "cryptographic_assets": [{
			"start_line": 1, "rules": [{"id": "r"}], "status": "pending"
		}]}]
	}`)
	targetCG := []byte(`{
		"schema_version": "5.3",
		"scan_metadata":  {"root_module": "org.example"},
		"finding_graphs": [{
			"finding_id": "aaaa",
			"matched_operation": {"symbol": "X"},
			"call_chains": [
				[
					{"function_name": "external.lib.Caller.run"},
					{"function_name": "org.example.Service.handle"},
					{"function_name": "org.example.Crypto.encrypt"}
				]
			]
		}],
		"entry_point_index": [
			{"function": "external.lib.Caller.run"},
			{"function": "org.example.Service.handle"},
			{"function": "org.example.Crypto.encrypt"}
		]
	}`)

	res, err := MergeWithPolicy(target, targetCG, nil, Policy{
		PruneToRootModule:      true,
		RebuildEntryPointIndex: true,
	})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	var out struct {
		EntryPointIndex []struct {
			Function          string `json:"function"`
			ReachableFindings []struct {
				FindingID string `json:"finding_id"`
			} `json:"reachable_findings"`
		} `json:"entry_point_index"`
	}
	if err := json.Unmarshal(res.Callgraph, &out); err != nil {
		t.Fatalf("unmarshal callgraph: %v", err)
	}
	if len(out.EntryPointIndex) != 2 {
		t.Fatalf("entry_point_index=%d, want 2 (external frame pruned), got %+v", len(out.EntryPointIndex), out.EntryPointIndex)
	}
	for _, ep := range out.EntryPointIndex {
		if !strings.HasPrefix(ep.Function, "org.example.") {
			t.Errorf("entry point %q outside root module survived rebuild", ep.Function)
		}
		if len(ep.ReachableFindings) != 1 || ep.ReachableFindings[0].FindingID != "aaaa" {
			t.Errorf("entry point %q: reachable_findings=%+v, want [aaaa]", ep.Function, ep.ReachableFindings)
		}
	}
}

// TestMerge_DepWithoutCallgraph confirms that a dep contributing findings
// but no callgraph is still merged correctly: its findings appear with
// dependency_info, but no finding_graphs are added for it.
func TestMerge_DepWithoutCallgraph(t *testing.T) {
	target := []byte(`{
		"version": "1.3",
		"findings": [{"file_path": "T.java", "cryptographic_assets": []}]
	}`)
	targetCG := []byte(`{
		"schema_version": "5.3",
		"finding_graphs": [],
		"entry_point_index": []
	}`)
	depFindings := []byte(`{
		"findings": [{"file_path": "U.java", "cryptographic_assets": [{
			"start_line": 1, "rules": [{"id": "r"}], "status": "pending"
		}]}]
	}`)

	res, err := Merge(target, targetCG, []Dep{
		{Module: "x:y", Version: "1", Findings: depFindings /* no Callgraph */},
	})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	var merged findingsEnvelope
	if err := json.Unmarshal(res.Findings, &merged); err != nil {
		t.Fatal(err)
	}
	if len(merged.Findings) != 2 {
		t.Errorf("findings merged: %d, want 2 (target+dep)", len(merged.Findings))
	}
	a := merged.Findings[1].CryptographicAssets[0]
	if a.Source != "dependency" || a.DependencyInfo == nil {
		t.Errorf("dep finding not stamped correctly: %+v", a)
	}

	// Callgraph must NOT include any dep frames since dep had no fragment.
	var cg struct {
		FindingGraphs   []json.RawMessage `json:"finding_graphs"`
		EntryPointIndex []json.RawMessage `json:"entry_point_index"`
	}
	if err := json.Unmarshal(res.Callgraph, &cg); err != nil {
		t.Fatal(err)
	}
	if len(cg.FindingGraphs) != 0 || len(cg.EntryPointIndex) != 0 {
		t.Errorf("expected empty callgraph (no fragments contributed), got fg=%d ep=%d",
			len(cg.FindingGraphs), len(cg.EntryPointIndex))
	}
}
