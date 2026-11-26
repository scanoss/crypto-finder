// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/paramcondition"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestMaterializeConditionedFindings_SpecializesWrapperPaths(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, `rules:
  - id: java.pgp.aes128
    message: AES-128 PGP
    severity: INFO
    pattern: new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.FX_ONE)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: AES
        algorithmName: AES-128
        operation: encrypt
        parameterCondition: param[0]==SymmetricKeyAlgorithmTags.FX_ONE
        api: org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>
  - id: java.pgp.des
    message: DES PGP
    severity: INFO
    pattern: new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.FX_TWO)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: DES
        algorithmName: DES
        operation: encrypt
        parameterCondition: param[0]==SymmetricKeyAlgorithmTags.FX_TWO
        api: org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>
`)
	firstID := callgraph.FunctionID{Package: "example", Type: "PGPFlow", Name: "first#0"}
	secondID := callgraph.FunctionID{Package: "example", Type: "PGPFlow", Name: "second#0"}
	buildID := callgraph.FunctionID{Package: "example", Type: "PGPFlow", Name: "build#1"}
	ctorID := callgraph.FunctionID{Package: "org.bouncycastle.openpgp.operator.jcajce", Type: "JcePGPDataEncryptorBuilder", Name: "<init>#1"}
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			firstID.String():  {ID: firstID, FilePath: "PGPFlow.java", Calls: []callgraph.FunctionCall{{Callee: buildID, Arguments: []string{"SymmetricKeyAlgorithmTags.FX_ONE"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "SymmetricKeyAlgorithmTags.FX_ONE"}}}}}},
			secondID.String(): {ID: secondID, FilePath: "PGPFlow.java", Calls: []callgraph.FunctionCall{{Callee: buildID, Arguments: []string{"SymmetricKeyAlgorithmTags.FX_TWO"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "SymmetricKeyAlgorithmTags.FX_TWO"}}}}}},
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

	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: "java"}, []string{rules}); got != 2 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want 2", got)
	}
	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: "java"}, []string{rules}); got != 0 {
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
	fragment := buildGraphFragmentExport(&engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java"})
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
		if !got[wantFinding] || got["java.pgp.dynamic"] || got[otherFinding] {
			t.Fatalf("fragment entry %s findings = %#v, want %s only, without the blank generic anchor", entryID, got, wantFinding)
		}
	}
}

func TestMaterializeConditionedFindings_ResolvesGuardedHelperReturnWithoutGuessing(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, `rules:
  - id: java.digest.sha2
    message: SHA-2 digest
    severity: INFO
    pattern: MessageDigest.getInstance($A)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: SHA-2
        algorithmName: SHA-$bits
        parameterCondition: param[0]~=SHA-?(?<bits>224|256|384|512)
        operation: digest
        api: MessageDigest.getInstance
  - id: java.cipher.wrong-api
    message: Unrelated cipher rule
    severity: INFO
    pattern: Cipher.getInstance($A)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: WRONG
        algorithmName: WRONG-$bits
        parameterCondition: param[0]~=SHA-?(?<bits>224|256|384|512)
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

	anchor := report.Findings[0].CryptographicAssets[0]
	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: "java"}, []string{rules}); got != 1 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want 1", got)
	}
	if len(report.Findings[0].CryptographicAssets) != 1 {
		t.Fatalf("assets = %#v, want the specialized asset in place of the blank anchor", report.Findings[0].CryptographicAssets)
	}
	asset := report.Findings[0].CryptographicAssets[0]
	if asset.Metadata["algorithmName"] != "SHA-256" || asset.Rules[0].ID != "java.digest.sha2" {
		t.Fatalf("materialized digest = %#v", asset)
	}
	if asset.Metadata["parameterCondition"] != "param[0]==SHA-256" || len(asset.ParameterConditions) != 1 || asset.ParameterConditions[0].Value != "SHA-256" {
		t.Fatalf("materialized digest conditions = %#v / %q, want exact resolved selector", asset.ParameterConditions, asset.Metadata["parameterCondition"])
	}

	graph.Functions[mainID.String()].Calls[0].ArgumentSources[0][0].SourceNodes = []callgraph.SourceNode{{Type: "PARAMETER", Name: "algorithm", ParameterIndex: 0}}
	report.Findings[0].CryptographicAssets = []entities.CryptographicAsset{anchor}
	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: "java"}, []string{rules}); got != 0 {
		t.Fatalf("dynamic MaterializeConditionedFindings() = %d, want no guessed asset", got)
	}
	if len(report.Findings[0].CryptographicAssets) != 1 {
		t.Fatalf("assets = %#v, want the anchor kept when nothing resolved", report.Findings[0].CryptographicAssets)
	}
}

func TestConditionedRule_UsesPatternCaptureNamesForBroadVariants(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, `rules:
  - id: fixture.java.jca.sha-2
    message: SHA-2 digest
    severity: INFO
    pattern-sources:
      - patterns:
          - pattern: $A
          - metavariable-regex:
              metavariable: $A
              regex: '"SHA-?(?<bits>224|256|384|512)(?:/(?<inner>224|256))?"'
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: MessageDigest.getInstance($A)
              - pattern: MessageDigest.getInstance($A, $PROV)
          - focus-metavariable: $A
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: SHA-2
        algorithmName: SHA-$bits
        algorithmParameterSetIdentifier: $bits
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

// The condition names (or omits) its groups independently of the rule's own
// named groups, so a placeholder must be bound by name from the value, never by
// the position of a condition group.
func TestConditionedRule_BindsPlaceholdersByName(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, `rules:
  - id: java.cipher.aes
    message: AES
    severity: INFO
    pattern-sources:
      - patterns:
          - pattern: $A
          - metavariable-regex:
              metavariable: $A
              regex: '"(?<fam>AES)/(?<md>CBC|ECB)/(?<pad>NoPadding|PKCS5Padding)"'
    pattern-sinks:
      - patterns:
          - pattern: Cipher.getInstance($A)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: $fam
        algorithmName: $fam-$md-$pad
        algorithmMode: $md
        algorithmPadding: $pad
        parameterCondition: param[0]~=AES/(CBC|ECB)/(NoPadding|PKCS5Padding)
        api: Cipher.getInstance
  - id: java.cipher.gcm
    message: AES-GCM
    severity: INFO
    pattern-sources:
      - patterns:
          - pattern: $A
          - metavariable-regex:
              metavariable: $A
              regex: '"(?<fam>AES)/(?<md>GCM|CCM)/(?<pad>NoPadding)"'
    pattern-sinks:
      - patterns:
          - pattern: Cipher.getInstance($A)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: $fam
        algorithmName: $fam-$md-$pad
        parameterCondition: param[0]~=AES/(GCM|CCM)/NoPadding
        api: Cipher.getInstance
  - id: java.cipher.rc4
    message: RC4
    severity: INFO
    pattern-sources:
      - patterns:
          - pattern: $A
          - metavariable-regex:
              metavariable: $A
              regex: '"(?<fam>RC4)"'
    pattern-sinks:
      - patterns:
          - pattern: Cipher.getInstance($A)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: $fam
        algorithmName: $fam
        parameterCondition: param[0]==RC4
        api: Cipher.getInstance
  - id: java.cipher.named
    message: condition names its own groups
    severity: INFO
    pattern: Cipher.getInstance($A)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: $md
        algorithmName: $md-$fam
        parameterCondition: param[0]~=^(?P<md>[A-Z]+)/(?P<fam>[A-Z]+)$
        api: Cipher.getInstance
`)
	byAPI := engine.LoadRuleCryptoMetadata([]string{rules})["Cipher.getInstance"]
	byID := make(map[string]engine.RuleCryptoMetadata, len(byAPI))
	for _, rule := range byAPI {
		byID[rule.Rule.ID] = rule
	}
	cases := []struct {
		rule, value, wantName, wantFamily string
	}{
		{"java.cipher.aes", "AES/CBC/PKCS5Padding", "AES-CBC-PKCS5Padding", "AES"},
		{"java.cipher.gcm", "AES/GCM/NoPadding", "AES-GCM-NoPadding", "AES"},
		{"java.cipher.rc4", "RC4", "RC4", "RC4"},
		{"java.cipher.named", "CBC/AES", "CBC-AES", "CBC"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			t.Parallel()
			finding := &entities.Finding{FilePath: "CipherFlow.java"}
			anchor := entities.CryptographicAsset{StartLine: 4, Metadata: map[string]string{"api": "Cipher.getInstance"}}
			rule := byID[tc.rule]
			if !appendConditionedAsset(finding, anchor, rule, []callGraphParameter{{ResolvedValue: tc.value}}, map[string]struct{}{}, map[string]struct{}{}) {
				t.Fatalf("appendConditionedAsset(%q) = false", tc.value)
			}
			got := finding.CryptographicAssets[0].Metadata
			if got["algorithmName"] != tc.wantName || got["algorithmFamily"] != tc.wantFamily {
				t.Fatalf("metadata = %#v, want name %q family %q", got, tc.wantName, tc.wantFamily)
			}
			if tc.rule == "java.cipher.aes" && (got["algorithmMode"] != "CBC" || got["algorithmPadding"] != "PKCS5Padding") {
				t.Fatalf("metadata = %#v, want mode CBC and padding PKCS5Padding", got)
			}
		})
	}
}

// An anchor that names an algorithm is a finding in its own right; only the
// blank dynamic-selector anchor is redundant beside the per-value assets.
func TestMaterializeConditionedFindings_KeepsNamedAnchor(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, `rules:
  - id: java.digest.sha1
    message: SHA-1
    severity: INFO
    pattern: MessageDigest.getInstance($A)
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: SHA-1
        parameterCondition: param[0]==SHA-1
        api: MessageDigest.getInstance
`)
	fnID := callgraph.FunctionID{Package: "example", Type: "DigestFlow", Name: "main#0"}
	callee := callgraph.FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance#1"}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		fnID.String(): {
			ID: fnID, FilePath: "DigestFlow.java", StartLine: 1, EndLine: 5,
			Calls: []callgraph.FunctionCall{{Callee: callee, FilePath: "DigestFlow.java", Line: 3, StartCol: 5, EndCol: 40, Arguments: []string{`"SHA-1"`}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: `"SHA-1"`}}}}},
		},
	}}
	report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "DigestFlow.java", Language: "java", CryptographicAssets: []entities.CryptographicAsset{{
		StartLine: 3, EndLine: 3, StartCol: 5, EndCol: 40, Rules: []entities.RuleInfo{{ID: "java.digest.named"}},
		Metadata: map[string]string{"algorithmName": "SHA-1", "api": "MessageDigest.getInstance"},
	}}}}}

	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: "java"}, []string{rules}); got != 1 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want 1", got)
	}
	if got := len(report.Findings[0].CryptographicAssets); got != 2 {
		t.Fatalf("assets = %#v, want the named anchor kept beside the specialized one", report.Findings[0].CryptographicAssets)
	}
}

func TestNormalizeSelectorValue(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		`"SHA-1"`:         "SHA-1",
		`'sha1'`:          "sha1",
		"`sha1`":          "sha1",
		"  'sha1'  ":      "sha1",
		"`sha${bits}`":    "`sha${bits}`",
		`'mixed"`:         `'mixed"`,
		`'`:               `'`,
		`sha1`:            "sha1",
		`"a" + suffix`:    `"a" + suffix`,
		`''`:              "",
		`consts.HASH_SHA`: "consts.HASH_SHA",
	} {
		if got := normalizeSelectorValue(in); got != want {
			t.Errorf("normalizeSelectorValue(%q) = %q, want %q", in, got, want)
		}
	}
}

// A Python or JavaScript call spells its literal with single quotes, and the
// exact condition a rule carries is written without any.
func TestConditionedRule_MatchesSingleQuotedLiteral(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, `rules:
  - id: python.hashlib.fixture-h
    message: SHA-1
    severity: INFO
    pattern: hashlib.new($A)
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: SHA-1
        parameterCondition: param[0]==fixture-h
        api: hashlib.new
`)
	rule := engine.LoadRuleCryptoMetadata([]string{rules})["hashlib.new"][0]
	for _, literal := range []string{`'fixture-h'`, `"fixture-h"`, "`fixture-h`"} {
		finding := &entities.Finding{FilePath: "app.py"}
		anchor := entities.CryptographicAsset{StartLine: 3, Metadata: map[string]string{"api": "hashlib.new"}}
		if !appendConditionedAsset(finding, anchor, rule, []callGraphParameter{{ResolvedValue: literal}}, map[string]struct{}{}, map[string]struct{}{}) {
			t.Errorf("literal %s did not match param[0]==fixture-h", literal)
		}
	}
}

func TestMaterializeConditionedFindings_DoesNotAttachNestedBuilderToOuterAnchor(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, `rules:
  - id: java.pgp.aes128
    message: AES-128 PGP builder
    severity: INFO
    pattern: new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.FX_ONE)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: AES
        algorithmName: AES-128
        parameterCondition: param[0]==SymmetricKeyAlgorithmTags.FX_ONE
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
				{Callee: outerID, FilePath: "PGPFlow.java", Line: 3, StartCol: 9, EndCol: 91, Arguments: []string{"new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.FX_ONE)"}},
				{Callee: builderID, FilePath: "PGPFlow.java", Line: 3, StartCol: 39, EndCol: 90, Arguments: []string{"SymmetricKeyAlgorithmTags.FX_ONE"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "SymmetricKeyAlgorithmTags.FX_ONE"}}}},
			},
		},
	}}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "PGPFlow.java", Language: "java", CryptographicAssets: []entities.CryptographicAsset{
			{StartLine: 3, EndLine: 3, StartCol: 9, EndCol: 91, Match: "new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.FX_ONE))", Rules: []entities.RuleInfo{{ID: "java.pgp.generator"}}, Metadata: map[string]string{"assetType": "protocol"}},
			{StartLine: 3, EndLine: 3, StartCol: 39, EndCol: 90, Match: "new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.FX_ONE)", Rules: []entities.RuleInfo{{ID: "java.pgp.builder.dynamic"}}, Metadata: map[string]string{"assetType": "algorithm"}},
		},
	}}}

	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: "java"}, []string{rules}); got != 1 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want only nested builder specialization", got)
	}
	if len(report.Findings[0].CryptographicAssets) != 2 {
		t.Fatalf("assets = %#v, want the outer anchor and the specialized builder", report.Findings[0].CryptographicAssets)
	}
	asset := report.Findings[0].CryptographicAssets[1]
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

const bindRuleTemplate = `rules:
  - id: java.bind.test
    message: bind
    severity: INFO
    pattern-sources:
      - patterns:
          - pattern: $A
          - metavariable-regex:
              metavariable: $A
              regex: '%s'
    pattern-sinks:
      - patterns:
          - pattern: Cipher.getInstance($A)
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: %s
        parameterCondition: param[0]~=%s
        api: Cipher.getInstance
`

// A binder is start-anchored like semgrep's metavariable-regex: it may stop
// short of the end of the value unless the rule's own regex ends in $.
func TestConditionedRule_BindsLikeSemgrepMetavariableRegex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, regex, name2, condition, value, wantName string
	}{
		{"alternation with end anchor reaches the longer branch", `(?P<m>CBC|CBC-MAC)$`, "$m", `CBC(-MAC)?`, "CBC-MAC", "CBC-MAC"},
		{"alternation without end anchor binds the prefix", `(?P<m>CBC|CBC-MAC)`, "$m", `CBC(-MAC)?`, "CBC-MAC", "CBC"},
		{"regex without end anchor", `(?P<f>AES)`, "$f", `AES.*`, "AES-GCM", "AES"},
		{"double-quoted spelling", `"(?P<v>x)"`, "$v", `x`, `x`, "x"},
		{"single-quoted spelling", `''(?P<v>x)''`, "$v", `x`, `x`, "x"},
		{"a match must start at the value", `(?P<f>GCM)`, "$f", `.*GCM`, "AES-GCM", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rules := writeConditionedRules(t, fmt.Sprintf(bindRuleTemplate, tc.regex, tc.name2, tc.condition))
			rule := engine.LoadRuleCryptoMetadata([]string{rules})["Cipher.getInstance"][0]
			finding := &entities.Finding{FilePath: "Flow.java"}
			anchor := entities.CryptographicAsset{StartLine: 4, Metadata: map[string]string{"api": "Cipher.getInstance"}}
			if !appendConditionedAsset(finding, anchor, rule, []callGraphParameter{{ResolvedValue: tc.value}}, map[string]struct{}{}, map[string]struct{}{}) {
				t.Fatalf("appendConditionedAsset(%q) = false", tc.value)
			}
			if got := finding.CryptographicAssets[0].Metadata["algorithmName"]; got != tc.wantName {
				t.Fatalf("algorithmName = %q, want %q", got, tc.wantName)
			}
		})
	}
}

// A rule with no named group has no binder, and its metadata is untouched.
func TestConditionedRule_WithoutNamedGroupsBindsNothing(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, fmt.Sprintf(bindRuleTemplate, `"RC4"`, "RC4", "RC4"))
	rule := engine.LoadRuleCryptoMetadata([]string{rules})["Cipher.getInstance"][0]
	if len(rule.CaptureBinders) != 0 {
		t.Fatalf("CaptureBinders = %v, want none", rule.CaptureBinders)
	}
	finding := &entities.Finding{FilePath: "Flow.java"}
	anchor := entities.CryptographicAsset{StartLine: 4, Metadata: map[string]string{"api": "Cipher.getInstance"}}
	if !appendConditionedAsset(finding, anchor, rule, []callGraphParameter{{ResolvedValue: "RC4"}}, map[string]struct{}{}, map[string]struct{}{}) {
		t.Fatal("appendConditionedAsset(RC4) = false")
	}
	if got := finding.CryptographicAssets[0].Metadata["algorithmName"]; got != "RC4" {
		t.Fatalf("algorithmName = %q, want RC4", got)
	}
}

func TestDropBlankAnchor(t *testing.T) {
	t.Parallel()

	rule := func(id string) []entities.RuleInfo { return []entities.RuleInfo{{ID: id}} }
	at := func(id string, line, startCol, endCol int) entities.CryptographicAsset {
		return entities.CryptographicAsset{StartLine: line, EndLine: line, StartCol: startCol, EndCol: endCol, Rules: rule(id)}
	}
	perValue := entities.CryptographicAsset{StartLine: 3, EndLine: 3, StartCol: 5, EndCol: 40, Rules: rule("r.value"), ParameterConditions: []paramcondition.Condition{{}}}

	t.Run("same span and rule is dropped", func(t *testing.T) {
		t.Parallel()
		finding := &entities.Finding{CryptographicAssets: []entities.CryptographicAsset{at("r.dyn", 3, 5, 40), perValue}}
		dropBlankAnchor(finding, at("r.dyn", 3, 5, 40))
		if len(finding.CryptographicAssets) != 1 || len(finding.CryptographicAssets[0].ParameterConditions) == 0 {
			t.Fatalf("assets = %#v, want only the per-value asset", finding.CryptographicAssets)
		}
	})
	t.Run("another rule at the same span is kept", func(t *testing.T) {
		t.Parallel()
		finding := &entities.Finding{CryptographicAssets: []entities.CryptographicAsset{at("r.dyn", 3, 5, 40), at("r.other", 3, 5, 40), perValue}}
		dropBlankAnchor(finding, at("r.dyn", 3, 5, 40))
		if len(finding.CryptographicAssets) != 2 || finding.CryptographicAssets[0].Rules[0].ID != "r.other" {
			t.Fatalf("assets = %#v, want the other rule's anchor kept", finding.CryptographicAssets)
		}
	})
	t.Run("two calls on one line without columns stay separate", func(t *testing.T) {
		t.Parallel()
		finding := &entities.Finding{CryptographicAssets: []entities.CryptographicAsset{at("r.dyn", 3, 0, 0), at("r.dyn", 3, 0, 0), perValue}}
		dropBlankAnchor(finding, at("r.dyn", 3, 0, 0))
		if len(finding.CryptographicAssets) != 3 {
			t.Fatalf("assets = %#v, want both anchors kept", finding.CryptographicAssets)
		}
	})
	t.Run("an anchor of another kind than the per-value assets is kept", func(t *testing.T) {
		t.Parallel()
		typed := perValue
		typed.Metadata = map[string]string{"assetType": "algorithm"}
		algorithm := at("r.dyn", 3, 5, 40)
		algorithm.Metadata = map[string]string{"assetType": "algorithm"}
		material := at("r.key", 3, 5, 40)
		material.Metadata = map[string]string{"assetType": "related-crypto-material", "materialType": "private-key"}
		finding := &entities.Finding{CryptographicAssets: []entities.CryptographicAsset{algorithm, material, typed}}
		dropBlankAnchor(finding, material)
		dropBlankAnchor(finding, algorithm)
		if len(finding.CryptographicAssets) != 2 || finding.CryptographicAssets[0].Rules[0].ID != "r.key" {
			t.Fatalf("assets = %#v, want the material kept and the algorithm anchor dropped", finding.CryptographicAssets)
		}
	})
	t.Run("two calls on one line with columns stay separate", func(t *testing.T) {
		t.Parallel()
		finding := &entities.Finding{CryptographicAssets: []entities.CryptographicAsset{at("r.dyn", 3, 5, 40), at("r.dyn", 3, 50, 90), perValue}}
		dropBlankAnchor(finding, at("r.dyn", 3, 5, 40))
		if len(finding.CryptographicAssets) != 2 || finding.CryptographicAssets[0].StartCol != 50 {
			t.Fatalf("assets = %#v, want the second call's anchor kept", finding.CryptographicAssets)
		}
	})
}
