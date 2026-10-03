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

// wantSpecialized runs the materialization and expects the finding to hold the
// specialized asset of algorithm alone: the native match is gone and the
// materialization is idempotent.
func wantSpecialized(t *testing.T, report *entities.InterimReport, result *engine.DepScanResult, rules, algorithm, condition string) {
	t.Helper()
	if got := MaterializeConditionedFindings(report, result, []string{rules}); got != 1 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want 1", got)
	}
	assets := report.Findings[0].CryptographicAssets
	if len(assets) != 1 || assets[0].Metadata["algorithmName"] != algorithm || assets[0].Metadata["parameterCondition"] != condition || assets[0].FindingID == "native-"+algorithm {
		t.Fatalf("assets = %#v, want the %s specialization alone", assets, algorithm)
	}
	if got := MaterializeConditionedFindings(report, result, []string{rules}); got != 0 || len(report.Findings[0].CryptographicAssets) != 1 {
		t.Fatalf("second run = %d with %d assets, want idempotent", got, len(report.Findings[0].CryptographicAssets))
	}
}

func TestMaterializeConditionedFindings_SpecializationSurvivesNativeTaintMatch(t *testing.T) {
	t.Parallel()

	native := nativeAsset("jca.algorithm.hash.md5.java.jca.algorithm.hash.md5", "MD5", "param[0]==MD5")
	report, result, rules := nativeDedupFixture(t, `"MD5"`, native)

	wantSpecialized(t, report, result, rules, "MD5", "param[0]==MD5")
}

func TestMaterializeConditionedFindings_SpecializationSurvivesNativeRegexCondition(t *testing.T) {
	t.Parallel()

	native := nativeAsset("jca.algorithm.hash.sha1.java.jca.algorithm.hash.sha1", "SHA-1", "param[0]~=^SHA-?1?$")
	report, result, rules := nativeDedupFixture(t, `"SHA-1"`, native)

	wantSpecialized(t, report, result, rules, "SHA-1", "param[0]==SHA-1")
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

func TestMaterializeConditionedFindings_KeepsNativeMatchWithoutSpecialization(t *testing.T) {
	t.Parallel()

	// The regex pattern of the native SHA-1 match also accepts other values,
	// but the call resolves to MD5 only: the SHA-1 native asset has no
	// specialization of its value and stays.
	native := nativeAsset("jca.algorithm.hash.sha1.java.jca.algorithm.hash.sha1", "SHA-1", "param[0]~=^SHA-?1?$")
	report, result, rules := nativeDedupFixture(t, `"MD5"`, native)

	if got := MaterializeConditionedFindings(report, result, []string{rules}); got != 1 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want the MD5 specialization", got)
	}
	var kept bool
	for _, asset := range report.Findings[0].CryptographicAssets {
		kept = kept || asset.FindingID == "native-SHA-1"
	}
	if !kept {
		t.Fatalf("assets = %#v, want the unspecialized native SHA-1 asset kept", report.Findings[0].CryptographicAssets)
	}
}
