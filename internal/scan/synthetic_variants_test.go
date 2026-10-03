// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"regexp"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/paramcondition"
)

const syntheticVariantsFile = "/workspace/Pbkdf2.java"

func syntheticVariantAsset(name, hash, condition string) entities.CryptographicAsset {
	md := map[string]string{
		"algorithmFamily": "PBKDF2",
		"algorithmName":   name,
		"api":             "com.example.Pbkdf2.<init>",
		"assetType":       "algorithm",
	}
	asset := entities.CryptographicAsset{
		StartLine: 29, EndLine: 29, Match: "com.example.Pbkdf2.<init>",
		Rules:  []entities.RuleInfo{{ID: engine.SyntheticEntryPointRuleID}},
		Source: "direct",
	}
	if hash != "" {
		md["algorithmHashFunction"] = hash
	}
	if condition != "" {
		md["parameterCondition"] = condition
		asset.ParameterConditions, _ = paramcondition.ParseAll(condition)
	}
	asset.Metadata = md
	return asset
}

// syntheticVariantsResult is one library constructor declared at line 29 with a
// base block and three variants, as a knowledge base entry produces them.
func syntheticVariantsResult() *engine.DepScanResult {
	id := callgraph.FunctionID{Package: "com.example", Type: "Pbkdf2", Name: "<init>"}
	return &engine.DepScanResult{
		RootModule:  "com.example:lib",
		ProjectRoot: "/workspace",
		CallGraph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
			id.String(): {ID: id, FilePath: syntheticVariantsFile, StartLine: 29, EndLine: 40},
		}},
		Report: &entities.InterimReport{Findings: []entities.Finding{{
			FilePath: syntheticVariantsFile,
			CryptographicAssets: []entities.CryptographicAsset{
				syntheticVariantAsset("PBKDF2", "", ""),
				syntheticVariantAsset("PBKDF2-SHA-1", "SHA-1", "param[0]:type==com.example.digests.SHA1Digest"),
				syntheticVariantAsset("PBKDF2-SHA-256", "SHA-256", "param[0]:type==com.example.digests.SHA256Digest"),
				syntheticVariantAsset("PBKDF2-SHA3-256", "SHA3-256", ""),
			},
		}}},
	}
}

// A synthesized entry point is anchored by the declaration that holds it, and
// its finding graph carries the same key.
func TestAssignOccurrenceKeys_SynthesizedEntryPointJoinsItsGraph(t *testing.T) {
	result := syntheticVariantsResult()
	engine.AssignFindingIDs(result.Report)

	export := buildCallGraphExportV2(result)

	assets := result.Report.Findings[0].CryptographicAssets
	if len(export.FindingGraphs) != len(assets) {
		t.Fatalf("finding graphs = %d, want %d", len(export.FindingGraphs), len(assets))
	}
	pattern := regexp.MustCompile(`^v1:[0-9a-f]{16}$`)
	for i := range assets {
		if !pattern.MatchString(assets[i].OccurrenceKey) {
			t.Fatalf("asset %d occurrence_key = %q, want a v1 key", i, assets[i].OccurrenceKey)
		}
		joined := false
		for _, graph := range export.FindingGraphs {
			joined = joined || (graph.FindingID == assets[i].FindingID && graph.OccurrenceKey == assets[i].OccurrenceKey)
		}
		if !joined {
			t.Errorf("no finding graph joins on (%q, %q)", assets[i].FindingID, assets[i].OccurrenceKey)
		}
	}
}

// Variants of one API at one declaration are separate findings; the base block
// keeps the identity it always had.
func TestSyntheticVariants_GetDistinctIdentityAndBaseKeepsIt(t *testing.T) {
	result := syntheticVariantsResult()
	engine.AssignFindingIDs(result.Report)
	AssignOccurrenceKeys(result)

	assets := result.Report.Findings[0].CryptographicAssets
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, asset := range assets {
		ids[asset.FindingID] = true
		keys[asset.OccurrenceKey] = true
	}
	if len(ids) != len(assets) || len(keys) != len(assets) {
		t.Fatalf("%d assets share %d finding ids and %d occurrence keys, want one each", len(assets), len(ids), len(keys))
	}

	// The base block is pinned: its ids are what a lone entry point has.
	base := assets[0]
	if base.ConditionedValue != "" {
		t.Fatalf("base block was specialized: %q", base.ConditionedValue)
	}
	if want := "1bb2190b"; base.FindingID != want {
		t.Errorf("base finding_id = %q, want pinned %q", base.FindingID, want)
	}
	lone := syntheticVariantsResult()
	lone.Report.Findings[0].CryptographicAssets = lone.Report.Findings[0].CryptographicAssets[:1]
	engine.AssignFindingIDs(lone.Report)
	AssignOccurrenceKeys(lone)
	if got := lone.Report.Findings[0].CryptographicAssets[0]; got.FindingID != base.FindingID || got.OccurrenceKey != base.OccurrenceKey {
		t.Errorf("base identity (%q, %q) differs from a lone entry point (%q, %q)", base.FindingID, base.OccurrenceKey, got.FindingID, got.OccurrenceKey)
	}

	// Determinism: another run, and the opposite block order, give the same ids.
	again := syntheticVariantsResult()
	blocks := again.Report.Findings[0].CryptographicAssets
	blocks[0], blocks[3] = blocks[3], blocks[0]
	engine.AssignFindingIDs(again.Report)
	AssignOccurrenceKeys(again)
	byName := map[string]entities.CryptographicAsset{}
	for _, asset := range again.Report.Findings[0].CryptographicAssets {
		byName[asset.Metadata["algorithmName"]] = asset
	}
	for _, asset := range assets {
		got := byName[asset.Metadata["algorithmName"]]
		if got.FindingID != asset.FindingID || got.OccurrenceKey != asset.OccurrenceKey {
			t.Errorf("%s identity depends on block order: (%q, %q) vs (%q, %q)", asset.Metadata["algorithmName"], got.FindingID, got.OccurrenceKey, asset.FindingID, asset.OccurrenceKey)
		}
	}
}

// A rule match with no call to anchor it, such as a cast or a declaration, is
// keyed by its function and position, and its graph carries the key.
func TestAssignOccurrenceKeys_TypeUsageWithoutCallIsKeyed(t *testing.T) {
	id := callgraph.FunctionID{Package: "com.example", Type: "Verifier", Name: "check"}
	result := &engine.DepScanResult{
		RootModule:  "com.example:app",
		ProjectRoot: "/workspace",
		CallGraph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
			id.String(): {
				ID: id, FilePath: "/workspace/Verifier.java", StartLine: 1, EndLine: 50,
				Calls: []callgraph.FunctionCall{{FilePath: "/workspace/Verifier.java", Line: 30, StartCol: 5, EndCol: 25, ASTKind: "method_invocation", NamedASTPath: "block[0]/expression_statement[0]/method_invocation[0]"}},
			},
		}},
		Report: &entities.InterimReport{Findings: []entities.Finding{{
			FilePath: "/workspace/Verifier.java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 20, EndLine: 20, StartCol: 10, EndCol: 59,
				Match: "X509Certificate cert = (X509Certificate)certs[k];",
				Rules: []entities.RuleInfo{{ID: "jca.certificate.x509.usage"}},
			}},
		}}},
	}
	engine.AssignFindingIDs(result.Report)

	export := buildCallGraphExportV2(result)

	asset := result.Report.Findings[0].CryptographicAssets[0]
	if asset.OccurrenceKey == "" {
		t.Fatal("type usage without a call has no occurrence_key")
	}
	if got := export.FindingGraphs[0].OccurrenceKey; got != asset.OccurrenceKey {
		t.Errorf("graph occurrence_key = %q, want %q", got, asset.OccurrenceKey)
	}
}

// Assets that were never keyless and are not variants keep their identity.
func TestOccurrenceKeyAndFindingID_PlainAndPerValueRuleFindingsArePinned(t *testing.T) {
	id := callgraph.FunctionID{Package: "com.example", Type: "Crypto", Name: "run#0"}
	call := callgraph.FunctionCall{FilePath: "/workspace/Crypto.java", Line: 10, StartCol: 5, EndCol: 25, ASTKind: "method_invocation", NamedASTPath: "block[0]/expression_statement[0]/method_invocation[0]"}
	rule := []entities.RuleInfo{{ID: "java.jca.algorithm.hash.sha-2"}}
	result := &engine.DepScanResult{
		RootModule:  "com.example:app",
		ProjectRoot: "/workspace",
		CallGraph: &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
			id.String(): {ID: id, FilePath: "/workspace/Crypto.java", StartLine: 1, EndLine: 100, Calls: []callgraph.FunctionCall{call}},
		}},
		Report: &entities.InterimReport{Findings: []entities.Finding{{
			FilePath: "/workspace/Crypto.java",
			CryptographicAssets: []entities.CryptographicAsset{
				{StartLine: 10, EndLine: 10, StartCol: 5, EndCol: 25, Rules: rule},
				{StartLine: 10, EndLine: 10, StartCol: 5, EndCol: 25, Rules: rule, ConditionedValue: "param[0]==SHA-256"},
			},
		}}},
	}
	engine.AssignFindingIDs(result.Report)
	AssignOccurrenceKeys(result)

	assets := result.Report.Findings[0].CryptographicAssets
	for i, want := range []struct{ id, key string }{
		{"5f201a0b", "v1:113330dfc25a404d"},
		{"1bab1631", "v1:958dafa89bcb52ba"},
	} {
		if assets[i].FindingID != want.id || assets[i].OccurrenceKey != want.key {
			t.Errorf("asset %d identity = (%q, %q), want pinned (%q, %q)", i, assets[i].FindingID, assets[i].OccurrenceKey, want.id, want.key)
		}
	}
}
