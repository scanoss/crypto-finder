// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

func TestSelectorMaterializationPublicExports(t *testing.T) {
	if testing.Short() {
		t.Skip("black-box CLI acceptance test")
	}
	t.Parallel()

	root := repositoryRoot(t)
	binary := buildCryptoFinder(t, root)
	target := filepath.Join(root, "testdata", "projects", "dependency_intelligence_java")
	sourcePath := filepath.Join(target, "src", "main", "java", "example", "Acceptance.java")
	source, err := os.ReadFile(sourcePath)
	require.NoError(t, err)

	tmp := t.TempDir()
	writeFakeScanner(t, tmp)
	rulesPath := filepath.Join(tmp, "rules.yaml")
	require.NoError(t, os.WriteFile(rulesPath, []byte(selectorAcceptanceRules), 0o600))
	fakeOutput := filepath.Join(tmp, "opengrep.json")
	writeSelectorScannerOutput(t, fakeOutput, sourcePath, string(source))
	findingsPath := filepath.Join(tmp, "findings.json")
	fragmentPath := filepath.Join(tmp, "fragment.json")
	callgraphPath := filepath.Join(tmp, "callgraph.json")

	cmd := exec.CommandContext(t.Context(), binary, "--error-format", "json", "scan", "--scanner", "opengrep", "--no-remote-rules",
		"--no-default-exclusions", "--languages", "java", "--rules", rulesPath, "--output", findingsPath,
		"--export-callgraph", callgraphPath, "--export-graph-fragment", fragmentPath, target)
	cmd.Env = append(os.Environ(), "HOME="+filepath.Join(tmp, "home"), "FAKE_OPENGREP_OUTPUT="+fakeOutput,
		"PATH="+tmp+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "crypto-finder scan output:\n%s", output)

	var report entities.InterimReport
	readJSON(t, findingsPath, &report)
	assets := allAssets(report)
	byRule := make(map[string]entities.CryptographicAsset)
	for _, asset := range assets {
		if len(asset.Rules) > 0 {
			byRule[asset.Rules[0].ID] = asset
		}
	}
	require.Equal(t, "AES-128", byRule["java.pgp.aes128"].Metadata["algorithmName"], "assets: %#v", byRule)
	require.Equal(t, "DES", byRule["java.pgp.des"].Metadata["algorithmName"], "assets: %#v", byRule)
	require.Equal(t, "SHA-256", byRule["java.digest.sha2"].Metadata["algorithmName"], "assets: %#v", byRule)
	require.NotContains(t, byRule, "java.digest.sha512", "dynamic helper input must not select the default branch")

	var fragment graphfrag.GraphFragmentExport
	readJSON(t, fragmentPath, &fragment)
	fragmentRules := make(map[string]bool)
	for _, operation := range fragment.CryptoAnnotations {
		fragmentRules[operation.RuleID] = true
	}
	for _, ruleID := range []string{"java.pgp.aes128", "java.pgp.des", "java.digest.sha2"} {
		require.Truef(t, fragmentRules[ruleID], "graph fragment missing conditioned %s", ruleID)
	}

	var live graphfrag.CallgraphExport
	readJSON(t, callgraphPath, &live)
	graphsByID := make(map[string]graphfrag.ExportFindingGraph)
	for _, graph := range live.FindingGraphs {
		graphsByID[graph.FindingID] = graph
	}
	for _, ruleID := range []string{"java.pgp.aes128", "java.pgp.des", "java.digest.sha2"} {
		asset := byRule[ruleID]
		graph, ok := graphsByID[asset.FindingID]
		require.Truef(t, ok, "callgraph missing conditioned %s", ruleID)
		require.Lenf(t, graph.CallChains, 1, "%s must retain only its applicable caller path", ruleID)
		last := graph.CallChains[0][len(graph.CallChains[0])-1]
		require.NotNil(t, last.CryptoCall)
		require.NotEmpty(t, last.CryptoCall.Parameters[0].ResolvedValue)
	}
}

func writeSelectorScannerOutput(t *testing.T, path, sourcePath, source string) {
	t.Helper()
	type anchor struct {
		needle string
		ruleID string
		api    string
	}
	anchors := []anchor{
		{"new JcePGPDataEncryptorBuilder(alg)", "java.pgp.dynamic", "org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>"},
		{"digestName(algorithm)", "java.digest.dynamic", "Wrong.getInstance"},
	}
	results := make([]map[string]any, 0, len(anchors))
	for _, anchor := range anchors {
		line, col := location(source, anchor.needle)
		require.NotZero(t, line)
		results = append(results, map[string]any{
			"check_id": anchor.ruleID, "path": sourcePath,
			"start": map[string]int{"line": line, "col": col}, "end": map[string]int{"line": line, "col": col + len(anchor.needle)},
			"extra": map[string]any{
				"message": "selector anchor", "severity": "INFO", "lines": anchor.needle,
				"metadata": map[string]any{"crypto": map[string]any{"assetType": "algorithm", "api": anchor.api}},
			},
		})
	}
	writeJSON(t, path, map[string]any{"results": results, "errors": []any{}})
}

const selectorAcceptanceRules = `rules:
  - id: java.pgp.dynamic
    message: PGP selector anchor
    severity: INFO
    languages: [java]
    pattern: $X
    metadata:
      crypto:
        assetType: algorithm
        api: org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>
  - id: java.pgp.aes128
    message: AES-128 PGP
    severity: INFO
    languages: [java]
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
    languages: [java]
    pattern: new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.DES)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: DES
        algorithmName: DES
        operation: encrypt
        parameterCondition: param[0]==SymmetricKeyAlgorithmTags.DES
        api: org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>
  - id: java.digest.dynamic
    message: Digest selector anchor
    severity: INFO
    languages: [java]
    pattern: $X
    metadata:
      crypto:
        assetType: algorithm
        api: MessageDigest.getInstance
  - id: java.digest.sha2
    message: SHA-2 digest
    severity: INFO
    languages: [java]
    mode: taint
    pattern-sources:
      - patterns:
          - pattern: $ALGO
          - metavariable-regex:
              metavariable: $ALGO
              regex: '"SHA-?(?<variant>224|256|384|512)"'
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
        operation: digest
        parameterCondition: param[0]~=SHA-?(?<variant>224|256|384|512)
        api: MessageDigest.getInstance
  - id: java.digest.sha512
    message: SHA-512 digest
    severity: INFO
    languages: [java]
    mode: taint
    pattern-sources:
      - patterns:
          - pattern: $ALGO
    pattern-sinks:
      - patterns:
          - pattern: MessageDigest.getInstance($ALGO)
          - focus-metavariable: $ALGO
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: SHA-2
        algorithmName: SHA-512
        operation: digest
        parameterCondition: param[0]==SHA-512
        api: MessageDigest.getInstance
`
