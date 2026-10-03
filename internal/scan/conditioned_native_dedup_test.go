// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/paramcondition"
)

const nativeDedupRules = `rules:
  - id: java.jca.algorithm.hash.md5
    message: MD5
    severity: INFO
    pattern: MessageDigest.getInstance($ALGO)
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: MD5
        parameterCondition: param[0]==MD5
        api: MessageDigest.getInstance
  - id: java.jca.algorithm.hash.sha1
    message: SHA-1
    severity: INFO
    pattern: MessageDigest.getInstance($ALGO)
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: SHA-1
        parameterCondition: param[0]==SHA-1
        api: MessageDigest.getInstance
`

// nativeDedupFixture is one MessageDigest.getInstance call resolving to value
// whose finding already holds nativeAssets, the matches the scanner reported,
// and the generic anchor of the call that specialization starts from.
func nativeDedupFixture(t *testing.T, value string, nativeAssets ...entities.CryptographicAsset) (*entities.InterimReport, *engine.DepScanResult, string) {
	t.Helper()
	rules := writeConditionedRules(t, nativeDedupRules)
	fnID := callgraph.FunctionID{Package: "example", Type: "DigestFlow", Name: "main#0"}
	callee := callgraph.FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance#1"}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		fnID.String(): {
			ID: fnID, FilePath: "DigestFlow.java", StartLine: 1, EndLine: 5,
			Calls: []callgraph.FunctionCall{{Callee: callee, FilePath: "DigestFlow.java", Line: 3, StartCol: 5, EndCol: 40, Arguments: []string{value}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: value}}}}},
		},
	}}
	report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "DigestFlow.java", Language: "java", CryptographicAssets: append([]entities.CryptographicAsset{{
		StartLine: 3, EndLine: 3, StartCol: 5, EndCol: 40, Rules: []entities.RuleInfo{{ID: "java.jca.generic"}},
		Metadata: map[string]string{"api": "MessageDigest.getInstance"},
	}}, nativeAssets...)}}}
	return report, &engine.DepScanResult{CallGraph: graph, Ecosystem: "java"}, rules
}

func nativeAsset(ruleID, algorithm, condition string) entities.CryptographicAsset {
	return entities.CryptographicAsset{
		FindingID: "native-" + algorithm,
		StartLine: 3, EndLine: 3, StartCol: 5, EndCol: 40,
		Rules:               []entities.RuleInfo{{ID: ruleID}},
		Metadata:            map[string]string{"algorithmName": algorithm, "parameterCondition": condition},
		ParameterConditions: []paramcondition.Condition{{Raw: condition}},
	}
}

func TestMaterializeConditionedFindings_NativeTaintMatchSurvivesSpecialization(t *testing.T) {
	t.Parallel()

	native := nativeAsset("jca.algorithm.hash.md5.java.jca.algorithm.hash.md5", "MD5", "param[0]==MD5")
	report, result, rules := nativeDedupFixture(t, `"MD5"`, native)

	if got := MaterializeConditionedFindings(report, result, []string{rules}); got != 0 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want 0 for a value the scanner already reported", got)
	}
	assets := report.Findings[0].CryptographicAssets
	if len(assets) != 1 || assets[0].FindingID != "native-MD5" {
		t.Fatalf("assets = %#v, want the native asset alone, identity unchanged and the blank anchor dropped as before", assets)
	}
}

func TestMaterializeConditionedFindings_NativeRegexConditionDedupsResolvedValue(t *testing.T) {
	t.Parallel()

	native := nativeAsset("jca.algorithm.hash.sha1.java.jca.algorithm.hash.sha1", "SHA-1", "param[0]~=^SHA-?1?$")
	report, result, rules := nativeDedupFixture(t, `"SHA-1"`, native)

	if got := MaterializeConditionedFindings(report, result, []string{rules}); got != 0 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want 0", got)
	}
	if got := len(report.Findings[0].CryptographicAssets); got != 1 {
		t.Fatalf("assets = %#v, want one asset for SHA-1", report.Findings[0].CryptographicAssets)
	}
}

func TestMaterializeConditionedFindings_KeepsDifferentValueAtSameLine(t *testing.T) {
	t.Parallel()

	// The scanner reported MD5 only; the call resolves to SHA-1 as well.
	native := nativeAsset("jca.algorithm.hash.md5.java.jca.algorithm.hash.md5", "MD5", "param[0]==MD5")
	report, result, rules := nativeDedupFixture(t, `"SHA-1"`, native)

	if got := MaterializeConditionedFindings(report, result, []string{rules}); got != 1 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want the SHA-1 specialization", got)
	}
	names := map[string]int{}
	for _, asset := range report.Findings[0].CryptographicAssets {
		if len(asset.ParameterConditions) > 0 {
			names[asset.Metadata["algorithmName"]]++
		}
	}
	if names["MD5"] != 1 || names["SHA-1"] != 1 {
		t.Fatalf("algorithms = %#v, want MD5 and SHA-1 once each", names)
	}
}

func TestMaterializeConditionedFindings_KeepsNativeMatchOfAnotherRule(t *testing.T) {
	t.Parallel()

	// Same algorithm and span, different rule: not a duplicate of the specialization.
	native := nativeAsset("jca.algorithm.hash.other.java.jca.algorithm.hash.other", "MD5", "param[0]==MD5")
	report, result, rules := nativeDedupFixture(t, `"MD5"`, native)

	if got := MaterializeConditionedFindings(report, result, []string{rules}); got != 1 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want 1", got)
	}
	if got := len(report.Findings[0].CryptographicAssets); got != 2 {
		t.Fatalf("assets = %#v, want the other rule's native asset kept beside the specialization", report.Findings[0].CryptographicAssets)
	}
}

func TestIndexNativeAsset_MatchesOnlyWholeDotSegments(t *testing.T) {
	t.Parallel()

	asset := nativeAsset("a.b.java.x.md5", "MD5", "")
	index := map[string]struct{}{}
	indexNativeAsset(index, "f.java", asset, "a.b.java.x.md5")
	for id, want := range map[string]bool{"java.x.md5": true, "md5": true, "a.b.java.x.md5": true, "x.md5": true, "5": false, "ava.x.md5": false} {
		if _, got := index[nativeAssetKey("f.java", asset, id)]; got != want {
			t.Errorf("rule %q indexed = %v, want %v", id, got, want)
		}
	}
}
