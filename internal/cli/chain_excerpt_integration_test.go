// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// A route that runs through dependency code shows the dependency's source at
// the hop, read from the directory the dependency scan resolved: main calls
// reachlib.Apply, which calls back into the application's hasher.Hash, whose
// SHA-512 is the finding.
func TestDependencyScanExportsChainExcerpts(t *testing.T) {
	if testing.Short() {
		t.Skip("black-box CLI test with real scanner and toolchains")
	}
	for _, tool := range []string{"opengrep", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	t.Parallel()

	root := repositoryRoot(t)
	binary := buildCryptoFinder(t, root)
	work := t.TempDir()
	fixture := filepath.Join(work, "fixture")
	require.NoError(t, os.CopyFS(fixture, os.DirFS(filepath.Join(root, "testdata", "projects", "project_reachability", "go"))))
	callgraphPath := filepath.Join(work, "callgraph.json")
	cmd := exec.CommandContext(t.Context(), binary,
		"--error-format", "json", "scan", "--scanner", "opengrep", "--no-remote-rules", "--findings-cache", "none",
		"--languages", "go", "--rules", filepath.Join(root, "testdata", "rules", "project-reachability.yaml"),
		"--output", filepath.Join(work, "findings.json"), "--scan-dependencies", "--export-callgraph", callgraphPath,
		filepath.Join(fixture, "app"))
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "crypto-finder output:\n%s", output)

	var export graphfrag.CallgraphExport
	readJSON(t, callgraphPath, &export)
	require.Equal(t, graphfrag.CallgraphInternedSchemaVersion, export.SchemaVersion)
	var route []graphfrag.ExportChainNode
	dependencyFrames := 0
	for i := range export.FindingGraphs {
		fg := &export.FindingGraphs[i]
		require.True(t, graphfrag.HydrateChainIdentities(export.Functions, fg.CallChains, fg.CallChainIndexes))
		for _, chain := range fg.CallChains {
			for j := range chain {
				frame := &chain[j]
				if frame.DependencyInfo != nil {
					dependencyFrames++
					require.NotNilf(t, frame.Excerpt, "dependency frame %s has no excerpt: %q", frame.FunctionName, frame.ExcerptUnavailable)
				}
			}
			if len(chain) == 3 && chain[1].FunctionName == "example.com/reachlib.Apply" {
				route = chain
			}
		}
	}
	require.Positive(t, dependencyFrames, "no chain crosses dependency code")
	require.Lenf(t, route, 3, "no main -> reachlib.Apply -> hasher.Hash route")

	main, apply, hash := route[0], route[1], route[2]
	require.Equal(t, "main", main.RootKind)
	require.Empty(t, main.EntryRule, "main is an entry point by language semantics, not a catalog entry")
	require.Equal(t, &graphfrag.ExportExcerpt{StartLine: 14, FocusLine: 17, Lines: []string{
		"\tfmt.Println(fingerprint(data))",
		"\tfmt.Println(reachlib.Digest(data))",
		"\treachlib.Visit([][]byte{data}, callback)",
		"\tfmt.Println(reachlib.Apply(hasher{}, data))",
		"}",
		"",
		"func fingerprint(data []byte) [32]byte {",
	}}, main.Excerpt)
	require.NotNil(t, apply.EntryCall)
	require.Equal(t, 14, apply.EntryCall.CallSiteColumn, "reachlib.Apply starts at column 14 of main.go:17")
	require.NotNil(t, apply.DependencyInfo)
	require.Equal(t, "example.com/reachlib", apply.DependencyInfo.Module)
	require.Equal(t, &graphfrag.ExportExcerpt{StartLine: 22, FocusLine: 25, Lines: []string{
		"",
		"// Apply hashes data with h.",
		"func Apply(h Hasher, data []byte) []byte {",
		"\treturn h.Hash(data)",
		"}",
	}}, apply.Excerpt, "the window stops at the end of lib.go")
	require.NotNil(t, hash.Excerpt)
	require.Equal(t, 35, hash.Excerpt.FocusLine)
	require.Equal(t, "\tsum := sha512.Sum512(data)", hash.Excerpt.Lines[hash.Excerpt.FocusLine-hash.Excerpt.StartLine])
}
