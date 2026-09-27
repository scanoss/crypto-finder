// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// A JavaScript string argument selects a conditioned rule whatever its
// spelling. Single quotes, backticks without a substitution and escapes all
// denote the same string as the double-quoted form; a template literal with a
// substitution is not a literal and must not select anything.
func TestSelectorMaterializationJavaScriptStringLiterals(t *testing.T) {
	if testing.Short() {
		t.Skip("black-box CLI acceptance test")
	}
	t.Parallel()

	root := repositoryRoot(t)
	binary := buildCryptoFinder(t, root)
	target := filepath.Join(root, "testdata", "projects", "selector_javascript_literals")
	sourcePath := filepath.Join(target, "handshake.js")
	source, err := os.ReadFile(sourcePath)
	require.NoError(t, err)

	tmp := t.TempDir()
	writeFakeScanner(t, tmp)
	rulesPath := filepath.Join(tmp, "rules.yaml")
	require.NoError(t, os.WriteFile(rulesPath, []byte(javascriptSelectorRules), 0o600))
	fakeOutput := filepath.Join(tmp, "opengrep.json")
	writeJavaScriptAnchorOutput(t, fakeOutput, sourcePath, string(source))
	findingsPath := filepath.Join(tmp, "findings.json")

	cmd := exec.CommandContext(t.Context(), binary, "--error-format", "json", "scan", "--scanner", "opengrep", "--no-remote-rules",
		"--no-default-exclusions", "--languages", "javascript", "--rules", rulesPath, "--output", findingsPath,
		"--export-callgraph", filepath.Join(tmp, "callgraph.json"), target)
	cmd.Env = append(os.Environ(), "HOME="+filepath.Join(tmp, "home"), "FAKE_OPENGREP_OUTPUT="+fakeOutput,
		"PATH="+tmp+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "crypto-finder scan output:\n%s", output)

	var report entities.InterimReport
	readJSON(t, findingsPath, &report)
	selected := make(map[string][]int)
	for _, asset := range allAssets(report) {
		if len(asset.Rules) > 0 && asset.Rules[0].ID != "js.noise.initialize" {
			selected[asset.Rules[0].ID] = append(selected[asset.Rules[0].ID], asset.StartLine)
		}
	}
	for _, lines := range selected {
		sort.Ints(lines)
	}
	lineOf := func(needle string) int {
		line, _ := location(string(source), needle)
		require.NotZero(t, line, needle)
		return line
	}
	require.Equal(t, map[string][]int{
		"js.noise.pattern-nn": {lineOf("doubleQuoted ="), lineOf("singleQuoted ="), lineOf("template ="), lineOf("escaped =")},
		"js.noise.pattern-kk": {lineOf("other =")},
	}, selected, "a substituted template literal selects nothing")
}

func writeJavaScriptAnchorOutput(t *testing.T, path, sourcePath, source string) {
	t.Helper()
	results := make([]map[string]any, 0)
	for index := 0; ; {
		offset := strings.Index(source[index:], "noise.initialize(")
		if offset < 0 {
			break
		}
		start := index + offset
		end := start + strings.Index(source[start:], ")") + 1
		index = end
		line, col := location(source, source[start:end])
		results = append(results, map[string]any{
			"check_id": "js.noise.initialize", "path": sourcePath,
			"start": map[string]int{"line": line, "col": col}, "end": map[string]int{"line": line, "col": col + end - start},
			"extra": map[string]any{
				"message": "noise handshake", "severity": "INFO", "lines": source[start:end],
				"metadata": map[string]any{"crypto": map[string]any{"assetType": "protocol", "api": "noise-protocol.initialize"}},
			},
		})
	}
	require.Len(t, results, 6)
	writeJSON(t, path, map[string]any{"results": results, "errors": []any{}})
}

const javascriptSelectorRules = `rules:
  - id: js.noise.initialize
    message: Noise handshake
    severity: INFO
    languages: [javascript]
    pattern: $NS.initialize($P, ...)
    metadata:
      crypto:
        assetType: protocol
        protocolName: Noise
        api: noise-protocol.initialize
  - id: js.noise.pattern-nn
    message: Noise NN handshake
    severity: INFO
    languages: [javascript]
    pattern: initialize("NN", ...)
    metadata:
      crypto:
        assetType: protocol
        protocolName: Noise
        protocolVariant: NN
        parameterCondition: 'param[0]=="NN"'
        api: noise-protocol.initialize
  - id: js.noise.pattern-kk
    message: Noise KK handshake
    severity: INFO
    languages: [javascript]
    pattern: initialize("KK", ...)
    metadata:
      crypto:
        assetType: protocol
        protocolName: Noise
        protocolVariant: KK
        parameterCondition: 'param[0]=="KK"'
        api: noise-protocol.initialize
`
