// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestMaterializeConditionedFindings_SpecializesWrapperPaths(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, `rules:
  - id: java.pgp.aes128
    message: AES-128 PGP
    severity: INFO
    pattern: new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_128)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: AES
        algorithmName: AES-128
        operation: encrypt
        parameterCondition: param[0]==SymmetricKeyAlgorithmTags.AES_128
        api: org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>
  - id: java.pgp.des
    message: DES PGP
    severity: INFO
    pattern: new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.DES)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: DES
        algorithmName: DES
        operation: encrypt
        parameterCondition: param[0]==SymmetricKeyAlgorithmTags.DES
        api: org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>
`)
	firstID := callgraph.FunctionID{Package: "example", Type: "PGPFlow", Name: "first#0"}
	secondID := callgraph.FunctionID{Package: "example", Type: "PGPFlow", Name: "second#0"}
	buildID := callgraph.FunctionID{Package: "example", Type: "PGPFlow", Name: "build#1"}
	ctorID := callgraph.FunctionID{Package: "org.bouncycastle.openpgp.operator.jcajce", Type: "JcePGPDataEncryptorBuilder", Name: "<init>#1"}
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			firstID.String():  {ID: firstID, FilePath: "PGPFlow.java", Calls: []callgraph.FunctionCall{{Callee: buildID, Arguments: []string{"SymmetricKeyAlgorithmTags.AES_128"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "SymmetricKeyAlgorithmTags.AES_128"}}}}}},
			secondID.String(): {ID: secondID, FilePath: "PGPFlow.java", Calls: []callgraph.FunctionCall{{Callee: buildID, Arguments: []string{"SymmetricKeyAlgorithmTags.DES"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "SymmetricKeyAlgorithmTags.DES"}}}}}},
			buildID.String(): {
				ID: buildID, FilePath: "PGPFlow.java", StartLine: 10, EndLine: 12,
				Parameters: []callgraph.FunctionParameter{{Name: "algorithm", Type: "int"}},
				Calls:      []callgraph.FunctionCall{{Callee: ctorID, FilePath: "PGPFlow.java", Line: 11, StartCol: 16, EndCol: 63, Arguments: []string{"algorithm"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "PARAMETER", Name: "algorithm", ParameterIndex: 0}}}}},
			},
		},
		Callers: map[string][]string{buildID.String(): {firstID.String(), secondID.String()}},
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "PGPFlow.java", Language: "java", CryptographicAssets: []entities.CryptographicAsset{{
		StartLine: 11, EndLine: 11, StartCol: 16, EndCol: 63, Match: "new JcePGPDataEncryptorBuilder(algorithm)",
		Rules: []entities.RuleInfo{{ID: "java.pgp.dynamic"}}, Metadata: map[string]string{"api": "org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>"},
	}}}}}

	if got := MaterializeConditionedFindings(report, graph, []string{rules}, "java"); got != 2 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want 2", got)
	}
	if got := MaterializeConditionedFindings(report, graph, []string{rules}, "java"); got != 0 {
		t.Fatalf("second MaterializeConditionedFindings() = %d, want idempotent 0", got)
	}
	byRule := make(map[string]entities.CryptographicAsset)
	for _, asset := range report.Findings[0].CryptographicAssets {
		byRule[asset.Rules[0].ID] = asset
	}
	if byRule["java.pgp.aes128"].Metadata["algorithmName"] != "AES-128" || byRule["java.pgp.des"].Metadata["algorithmName"] != "DES" {
		t.Fatalf("materialized assets = %#v", byRule)
	}
	for _, ruleID := range []string{"java.pgp.aes128", "java.pgp.des"} {
		asset := byRule[ruleID]
		ctx := newExportBuildContext(&engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java"})
		fg := buildFindingGraph(ctx, report.Findings[0], asset)
		if len(fg.CallChains) != 1 {
			t.Fatalf("%s call chains = %#v, want only applicable path", ruleID, fg.CallChains)
		}
	}
	for i := range report.Findings[0].CryptographicAssets {
		asset := &report.Findings[0].CryptographicAssets[i]
		asset.FindingID = asset.Rules[0].ID
	}
	fragment := BuildGraphFragmentExport(&engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java"})
	for entryID, wantFinding := range map[string]string{
		firstID.String():  "java.pgp.aes128",
		secondID.String(): "java.pgp.des",
	} {
		entry := findGraphFragmentEntryPoint(fragment.CryptoEntryPoints, entryID)
		if entry == nil {
			t.Fatalf("fragment entry %s missing", entryID)
		}
		got := make(map[string]bool)
		for _, reachable := range entry.ReachableFindings {
			got[reachable.FindingID] = true
		}
		otherFinding := "java.pgp.aes128"
		if wantFinding == otherFinding {
			otherFinding = "java.pgp.des"
		}
		if !got[wantFinding] || !got["java.pgp.dynamic"] || got[otherFinding] {
			t.Fatalf("fragment entry %s findings = %#v, want generic + %s only", entryID, got, wantFinding)
		}
	}
}

func TestMaterializeConditionedFindings_ResolvesGuardedHelperReturnWithoutGuessing(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, `rules:
  - id: java.digest.sha2
    message: SHA-2 digest
    severity: INFO
    pattern: MessageDigest.getInstance($ALGO)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: SHA-2
        algorithmName: SHA-$variant
        parameterCondition: param[0]~=SHA-?(?<variant>224|256|384|512)
        operation: digest
        api: MessageDigest.getInstance
  - id: java.cipher.wrong-api
    message: Unrelated cipher rule
    severity: INFO
    pattern: Cipher.getInstance($ALGO)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: WRONG
        algorithmName: WRONG-$variant
        parameterCondition: param[0]~=SHA-?(?<variant>224|256|384|512)
        operation: encrypt
        api: Cipher.getInstance
`)
	mainID := callgraph.FunctionID{Package: "example", Type: "DigestFlow", Name: "main#0"}
	nameID := callgraph.FunctionID{Package: "example", Type: "DigestFlow", Name: "name#1"}
	digestID := callgraph.FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance#1"}
	selector := callgraph.SourceNode{Type: "VALUE", Value: "HashAlgorithmTags.SHA256", ParameterIndex: 0}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		mainID.String(): {
			ID: mainID, FilePath: "DigestFlow.java", StartLine: 1, EndLine: 8,
			Calls: []callgraph.FunctionCall{
				{Callee: digestID, FilePath: "DigestFlow.java", Line: 5, StartCol: 9, EndCol: 67, Arguments: []string{"name(HashAlgorithmTags.SHA256)"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "CALL_RESULT", CallTarget: &nameID, SourceNodes: []callgraph.SourceNode{selector}}}}},
				{Callee: nameID, FilePath: "DigestFlow.java", Line: 5, StartCol: 35, EndCol: 66, Arguments: []string{"HashAlgorithmTags.SHA256"}, ArgumentSources: [][]callgraph.SourceNode{{selector}}},
			},
		},
		nameID.String(): {
			ID: nameID, Parameters: []callgraph.FunctionParameter{{Name: "algorithm", Type: "int"}},
			ReturnSources: []callgraph.SourceNode{
				{Type: "VALUE", Value: `"SHA-256"`, Flow: &callgraph.SourceFlow{Guard: &callgraph.SourceGuard{ParameterIndex: 0, Value: "HashAlgorithmTags.SHA256"}}},
				{Type: "VALUE", Value: `"SHA-512"`, Flow: &callgraph.SourceFlow{Guard: &callgraph.SourceGuard{ParameterIndex: 0, Default: true}}},
			},
		},
	}}
	report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "DigestFlow.java", Language: "java", CryptographicAssets: []entities.CryptographicAsset{{
		StartLine: 5, EndLine: 5, StartCol: 35, EndCol: 66, Match: "name(HashAlgorithmTags.SHA256)",
		Rules: []entities.RuleInfo{{ID: "java.digest.dynamic"}}, Metadata: map[string]string{"api": "Cipher.getInstance"},
	}}}}}

	if got := MaterializeConditionedFindings(report, graph, []string{rules}, "java"); got != 1 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want 1", got)
	}
	asset := report.Findings[0].CryptographicAssets[1]
	if asset.Metadata["algorithmName"] != "SHA-256" || asset.Rules[0].ID != "java.digest.sha2" {
		t.Fatalf("materialized digest = %#v", asset)
	}
	if asset.Metadata["parameterCondition"] != "param[0]==SHA-256" || len(asset.ParameterConditions) != 1 || asset.ParameterConditions[0].Value != "SHA-256" {
		t.Fatalf("materialized digest conditions = %#v / %q, want exact resolved selector", asset.ParameterConditions, asset.Metadata["parameterCondition"])
	}

	graph.Functions[mainID.String()].Calls[0].ArgumentSources[0][0].SourceNodes = []callgraph.SourceNode{{Type: "PARAMETER", Name: "algorithm", ParameterIndex: 0}}
	report.Findings[0].CryptographicAssets = report.Findings[0].CryptographicAssets[:1]
	if got := MaterializeConditionedFindings(report, graph, []string{rules}, "java"); got != 0 {
		t.Fatalf("dynamic MaterializeConditionedFindings() = %d, want no guessed asset", got)
	}
}

func TestConditionedRule_UsesPatternCaptureNamesForBroadVariants(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, `rules:
  - id: java.jca.algorithm.hash.sha-2
    message: SHA-2 digest
    severity: INFO
    pattern-sources:
      - patterns:
          - pattern: $ALGO
          - metavariable-regex:
              metavariable: $ALGO
              regex: '"SHA-?(?<variant>224|256|384|512)(?:/(?<subvariant>224|256))?"'
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: MessageDigest.getInstance($ALGO)
              - pattern: MessageDigest.getInstance($ALGO, $PROVIDER)
          - focus-metavariable: $ALGO
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: SHA-2
        algorithmName: SHA-$variant
        algorithmParameterSetIdentifier: $variant
        parameterCondition: param[0]~=SHA-?(224|256|384|512)(?:/(224|256))?
        operation: digest
        api: Wrong.getInstance
`)
	rule := engine.LoadRuleCryptoMetadata([]string{rules})["MessageDigest.getInstance"][0]
	finding := &entities.Finding{FilePath: "DigestFlow.java"}
	seen := make(map[string]struct{})
	existing := make(map[string]struct{})
	anchor := entities.CryptographicAsset{StartLine: 4, Metadata: map[string]string{"api": "MessageDigest.getInstance"}}

	for _, value := range []string{"SHA-256", "SHA-512"} {
		if !appendConditionedAsset(finding, anchor, rule, []callGraphParameter{{ResolvedValue: value}}, seen, existing) {
			t.Fatalf("appendConditionedAsset(%q) = false", value)
		}
	}
	if len(finding.CryptographicAssets) != 2 {
		t.Fatalf("materialized assets = %#v, want two exact variants", finding.CryptographicAssets)
	}
	if finding.CryptographicAssets[0].Metadata["algorithmName"] != "SHA-256" || finding.CryptographicAssets[1].Metadata["algorithmName"] != "SHA-512" {
		t.Fatalf("algorithm names = %#v, want normalized SHA-256 and SHA-512", finding.CryptographicAssets)
	}
	if finding.CryptographicAssets[0].Metadata["algorithmParameterSetIdentifier"] != "256" || finding.CryptographicAssets[1].Metadata["algorithmParameterSetIdentifier"] != "512" {
		t.Fatalf("parameter identifiers = %#v, want normalized 256 and 512", finding.CryptographicAssets)
	}
}

func TestMaterializeConditionedFindings_DoesNotAttachNestedBuilderToOuterAnchor(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, `rules:
  - id: java.pgp.aes128
    message: AES-128 PGP builder
    severity: INFO
    pattern: new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_128)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: AES
        algorithmName: AES-128
        parameterCondition: param[0]==SymmetricKeyAlgorithmTags.AES_128
        operation: encrypt
        api: JcePGPDataEncryptorBuilder.<init>
`)
	ownerID := callgraph.FunctionID{Package: "example", Type: "PGPFlow", Name: "build#0"}
	outerID := callgraph.FunctionID{Package: "org.bouncycastle.openpgp", Type: "PGPEncryptedDataGenerator", Name: "<init>#1"}
	builderID := callgraph.FunctionID{Package: "org.bouncycastle.openpgp.operator.jcajce", Type: "JcePGPDataEncryptorBuilder", Name: "<init>#1"}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		ownerID.String(): {
			ID: ownerID, FilePath: "PGPFlow.java", StartLine: 1, EndLine: 5,
			Calls: []callgraph.FunctionCall{
				{Callee: outerID, FilePath: "PGPFlow.java", Line: 3, StartCol: 9, EndCol: 91, Arguments: []string{"new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_128)"}},
				{Callee: builderID, FilePath: "PGPFlow.java", Line: 3, StartCol: 39, EndCol: 90, Arguments: []string{"SymmetricKeyAlgorithmTags.AES_128"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "SymmetricKeyAlgorithmTags.AES_128"}}}},
			},
		},
	}}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "PGPFlow.java", Language: "java", CryptographicAssets: []entities.CryptographicAsset{
			{StartLine: 3, EndLine: 3, StartCol: 9, EndCol: 91, Match: "new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_128))", Rules: []entities.RuleInfo{{ID: "java.pgp.generator"}}, Metadata: map[string]string{"assetType": "protocol"}},
			{StartLine: 3, EndLine: 3, StartCol: 39, EndCol: 90, Match: "new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_128)", Rules: []entities.RuleInfo{{ID: "java.pgp.builder.dynamic"}}, Metadata: map[string]string{"assetType": "algorithm"}},
		},
	}}}

	if got := MaterializeConditionedFindings(report, graph, []string{rules}, "java"); got != 1 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want only nested builder specialization", got)
	}
	asset := report.Findings[0].CryptographicAssets[2]
	if asset.StartCol != 39 || asset.Rules[0].ID != "java.pgp.aes128" {
		t.Fatalf("materialized asset = %#v, want builder anchor only", asset)
	}
}

func writeConditionedRules(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
