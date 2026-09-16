// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

func TestCallgraphCLIExportProfiles(t *testing.T) {
	if testing.Short() {
		t.Skip("compiled CLI export contract")
	}
	root := repositoryRoot(t)
	binary := os.Getenv("CRYPTO_FINDER_PROFILE_TEST_BINARY")
	if binary == "" {
		binary = buildCryptoFinder(t, root)
	}
	tmp := t.TempDir()
	target := filepath.Join(tmp, "source")
	require.NoError(t, os.Mkdir(target, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(target, "go.mod"), []byte("module example.com/profile\n\ngo 1.24\n"), 0o600))
	var source strings.Builder
	source.WriteString("package profile\nimport \"crypto/sha256\"\nfunc hash(data []byte) []byte { digest := sha256.New(); digest.Write(data); return digest.Sum(nil) }\n")
	for i := 0; i < 12; i++ {
		fmt.Fprintf(&source, "func Entry%d(data []byte) []byte { return hash(data) }\n", i)
	}
	sourcePath := filepath.Join(target, "profile.go")
	require.NoError(t, os.WriteFile(sourcePath, []byte(source.String()), 0o600))
	writeFakeScanner(t, tmp)
	rulesPath := filepath.Join(tmp, "rules.yaml")
	require.NoError(t, os.WriteFile(rulesPath, []byte(`rules:
  - id: go.sha256.profile
    message: SHA-256
    severity: INFO
    languages: [go]
    pattern: $DIGEST.Sum($DATA)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: SHA2
        algorithmPrimitive: hash
        algorithmName: SHA-256
`), 0o600))
	scannerOutput := filepath.Join(tmp, "scanner.json")
	needle := "digest.Sum(nil)"
	line, col := location(source.String(), needle)
	writeJSON(t, scannerOutput, map[string]any{"results": []any{map[string]any{
		"check_id": "go.sha256.profile", "path": sourcePath,
		"start": map[string]int{"line": line, "col": col}, "end": map[string]int{"line": line, "col": col + len(needle)},
		"extra": map[string]any{
			"message": "SHA-256", "severity": "INFO", "lines": needle,
			"metadata": map[string]any{"crypto": map[string]any{"assetType": "algorithm", "algorithmFamily": "SHA2", "algorithmPrimitive": "hash", "algorithmName": "SHA-256"}},
		},
	}}, "errors": []any{}})
	var reports []entities.InterimReport
	var exports []graphfrag.CallgraphExport
	for _, profile := range []struct {
		name   string
		flags  []string
		schema string
		max    int
		index  bool
	}{
		{"default", nil, "6.15", 8, false},
		{"detailed-legacy", []string{"--export-callgraph-max-chains", "128", "--export-callgraph-entry-points=true", "--export-callgraph-interned-frames=false"}, "6.14", 128, true},
	} {
		t.Run(profile.name, func(t *testing.T) {
			findings := filepath.Join(tmp, profile.name+"-findings.json")
			graphPath := filepath.Join(tmp, profile.name+"-graph.json")
			args := []string{"scan", "--scanner", "opengrep", "--no-remote-rules", "--no-default-exclusions", "--languages", "go", "--rules", rulesPath, "--output", findings, "--export-callgraph", graphPath}
			args = append(args, profile.flags...)
			cmd := exec.CommandContext(t.Context(), binary, append(args, target)...)
			cmd.Env = append(os.Environ(), "HOME="+filepath.Join(tmp, "home"), "FAKE_OPENGREP_OUTPUT="+scannerOutput, "PATH="+tmp+string(os.PathListSeparator)+os.Getenv("PATH"))
			output, err := cmd.CombinedOutput()
			require.NoErrorf(t, err, "CLI output: %s", output)
			var report entities.InterimReport
			readJSON(t, findings, &report)
			assets := allAssets(report)
			require.Len(t, assets, 1)
			require.Equal(t, "SHA-256", assets[0].Metadata["algorithmName"])
			var document map[string]json.RawMessage
			readJSON(t, graphPath, &document)
			if profile.index {
				require.Contains(t, document, "crypto_entry_points")
			} else {
				_, present := document["crypto_entry_points"]
				require.False(t, present, "default export must omit the optional entry-point index")
			}
			var graph graphfrag.CallgraphExport
			readJSON(t, graphPath, &graph)
			require.Equal(t, profile.schema, graph.SchemaVersion)
			require.Len(t, graph.FindingGraphs, 1)
			require.NotEmpty(t, graph.SupportingCalls, "real digest lifecycle evidence must survive index omission")
			finding := graph.FindingGraphs[0]
			require.Equal(t, assets[0].FindingID, finding.FindingID)
			require.Equal(t, "not_applicable", finding.Reachability, "standalone export has no dependency user-package universe")
			require.NotEmpty(t, finding.CallChains)
			if !profile.index {
				require.Len(t, finding.CallChains, 8, "twelve callers exercise the default eight-path sample")
			}
			require.NotEmpty(t, finding.SupportingCallIDs)
			for _, id := range finding.SupportingCallIDs {
				found := false
				for _, call := range graph.SupportingCalls {
					found = found || call.SupportingID == id
				}
				require.True(t, found, "supporting-call foreign key must resolve")
			}
			require.LessOrEqual(t, len(finding.CallChains), profile.max)
			if profile.index {
				require.Greater(t, len(finding.CallChains), 8)
				require.NotEmpty(t, graph.CryptoEntryPoints)
			}
			require.Len(t, finding.CallChainIndexes, len(finding.CallChains))
			for route, frames := range finding.CallChains {
				require.GreaterOrEqual(t, len(frames), 2, "actual caller-to-crypto path")
				require.LessOrEqual(t, len(frames), 32)
				require.Len(t, finding.CallChainIndexes[route], len(frames))
				for hop, frame := range frames {
					index := finding.CallChainIndexes[route][hop]
					require.GreaterOrEqual(t, index, 0)
					require.Less(t, index, len(graph.Functions))
					fn := graph.Functions[index]
					require.NotEmpty(t, fn.FunctionName)
					require.NotEmpty(t, fn.FilePath)
					if profile.index {
						require.Equal(t, fn.FunctionName, frame.FunctionName)
					} else {
						require.Empty(t, frame.FunctionName)
						require.Empty(t, frame.FilePath)
					}
					if hop == len(frames)-1 {
						require.Contains(t, fn.FunctionName, "hash")
						require.NotNil(t, frame.CryptoCall)
					}
				}
			}
			reports = append(reports, report)
			exports = append(exports, graph)
		})
	}
	require.Len(t, reports, 2)
	require.Equal(t, reports[0].Findings, reports[1].Findings, "sampling and rendering do not change findings")
	require.Equal(t, exports[0].SupportingCalls, exports[1].SupportingCalls, "index omission preserves supporting evidence")
}
