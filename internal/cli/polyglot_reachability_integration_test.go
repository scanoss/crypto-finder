// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// polyglotExport is the slice of a callgraph export these tests read.
type polyglotExport struct {
	SchemaVersion string `json:"schema_version"`
	ScanMetadata  struct {
		Ecosystem  string                      `json:"ecosystem"`
		Ecosystems []graphfrag.ExportEcosystem `json:"ecosystems"`
	} `json:"scan_metadata"`
	FindingGraphs []json.RawMessage                  `json:"finding_graphs"`
	Functions     []graphfrag.ExportInternedFunction `json:"functions"`
}

type polyglotFindingGraph struct {
	FindingID        string    `json:"finding_id"`
	OccurrenceKey    string    `json:"occurrence_key"`
	UnresolvedReason string    `json:"unresolved_reason"`
	Reachability     string    `json:"reachability"`
	CallChainIndexes [][]int   `json:"call_chain_indexes"`
	FindingLocation  *struct{} `json:"finding_location"`
}

// polyglotVerdict is one finding of the fixture as the export reports it.
type polyglotVerdict struct {
	location         string
	occurrenceKey    string
	reachability     string
	unresolvedReason string
	// chains are the sampled routes as function names, entry first.
	chains [][]string
	// raw is the finding graph with its chains hydrated from functions[], so
	// two exports compare regardless of catalog positions.
	raw string
}

// A Java-dominant repository with a TypeScript module used to build one call
// graph, for Java, and look every TypeScript finding up in it. Each came back
// no_containing_function and not_applicable. Each supported ecosystem now has
// its own graph and each finding resolves against its own language's.
//
// The occurrence keys below were produced by the release before this change
// on the same fixture: consumers key finding identity on them, so they must
// not move. The Java verdicts are that release's verdicts too.
func TestPolyglotScanResolvesEachFindingInItsOwnEcosystem(t *testing.T) {
	if testing.Short() {
		t.Skip("black-box CLI test with a real scanner")
	}
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("opengrep not installed")
	}
	root := repositoryRoot(t)
	binary := buildCryptoFinder(t, root)
	rules := filepath.Join(root, "testdata", "rules", "polyglot-reachability.yaml")

	work := t.TempDir()
	target := filepath.Join(work, "repo")
	require.NoError(t, os.CopyFS(target, os.DirFS(filepath.Join(root, "testdata", "projects", "polyglot_reachability"))))

	export, verdicts := runPolyglotScan(t, binary, rules, target, filepath.Join(work, "polyglot"))
	require.Equal(t, graphfrag.CallgraphInternedSchemaVersion, export.SchemaVersion)
	require.Equal(t, "java", export.ScanMetadata.Ecosystem, "the primary ecosystem is still the dominant language")
	require.Len(t, export.ScanMetadata.Ecosystems, 2)
	require.Equal(t, "java", export.ScanMetadata.Ecosystems[0].Ecosystem)
	require.Equal(t, "node", export.ScanMetadata.Ecosystems[1].Ecosystem)
	require.Positive(t, export.ScanMetadata.Ecosystems[1].FunctionCount)

	want := map[string]polyglotVerdict{
		"ledger/src/main/java/com/example/ledger/DigestService.java:8": {
			occurrenceKey: "v1:6b67f0518b5ac6be", reachability: graphfrag.ReachabilityReachable,
			chains: [][]string{{"com.example.ledger.LedgerController.postEntry", "com.example.ledger.DigestService.fingerprint"}},
		},
		"ledger/src/main/java/com/example/ledger/LegacyChecksum.java:7": {
			occurrenceKey: "v1:befe6a26b8f65d5b", reachability: graphfrag.ReachabilityUnreachable,
			chains: [][]string{{"com.example.ledger.LegacyChecksum.checksum"}},
		},
		"web/src/lib/avatarHash.ts:4": {
			occurrenceKey: "v1:45e95fa50f2c1176", reachability: graphfrag.ReachabilityReachable,
			chains: [][]string{{"web/src/lib/avatarHash.avatarUrl", "web/src/lib/avatarHash.avatarCacheKey"}},
		},
		"web/src/lib/avatarHash.ts:12": {
			occurrenceKey: "v1:b0567cb3b88cfb8f", reachability: graphfrag.ReachabilityUnreachable,
			chains: [][]string{{"web/src/lib/avatarHash.legacyEtag"}},
		},
		// Reached only from another module, through a relative import
		// written with the .js extension TypeScript's ESM output uses.
		"web/src/lib/etag.ts:4": {
			occurrenceKey: "v1:7e3249b376533603", reachability: graphfrag.ReachabilityReachable,
			chains: [][]string{{"web/src/routes/profile.renderProfile", "web/src/lib/etag.etag"}},
		},
		// Kotlin has no call graph parser: the finding says so instead of
		// claiming the analyzed code had no function around it.
		"ledger/src/main/kotlin/com/example/ledger/Report.kt:5": {
			occurrenceKey: "v1:1a30b17fb683c5a8", reachability: graphfrag.ReachabilityNotApplicable,
			unresolvedReason: "language_not_analyzed",
		},
	}
	require.Len(t, verdicts, len(want), "one finding per planted call: %v", verdicts)
	for location, expected := range want {
		got, ok := verdicts[location]
		require.Truef(t, ok, "no finding at %s: %v", location, verdicts)
		require.Equalf(t, expected.occurrenceKey, got.occurrenceKey, "%s occurrence key moved", location)
		require.Equalf(t, expected.reachability, got.reachability, "%s reachability", location)
		require.Equalf(t, expected.unresolvedReason, got.unresolvedReason, "%s unresolved_reason", location)
		if expected.chains != nil {
			require.Equalf(t, expected.chains, got.chains, "%s call chains", location)
		}
	}

	// The same Java module scanned without the TypeScript one takes the
	// single-ecosystem path, which this change leaves as it was. Its Java
	// finding graphs are byte-identical to the polyglot run's.
	javaOnly := filepath.Join(work, "java-only")
	require.NoError(t, os.CopyFS(javaOnly, os.DirFS(target)))
	require.NoError(t, os.RemoveAll(filepath.Join(javaOnly, "web")))
	require.NoError(t, os.RemoveAll(filepath.Join(javaOnly, "ledger", "src", "main", "kotlin")))
	javaExport, javaVerdicts := runPolyglotScan(t, binary, rules, javaOnly, filepath.Join(work, "single"))
	require.Empty(t, javaExport.ScanMetadata.Ecosystems, "a single-ecosystem export carries no ecosystems list")
	require.Len(t, javaVerdicts, 2)
	for location, single := range javaVerdicts {
		require.Equalf(t, single.raw, verdicts[location].raw, "%s finding graph differs between the Java-only and polyglot scans", location)
	}
}

func runPolyglotScan(t *testing.T, binary, rules, target, outDir string, extra ...string) (polyglotExport, map[string]polyglotVerdict) {
	t.Helper()
	require.NoError(t, os.MkdirAll(outDir, 0o750))
	findingsPath := filepath.Join(outDir, "findings.json")
	callgraphPath := filepath.Join(outDir, "callgraph.json")
	args := []string{
		"--error-format", "json", "scan", "--scanner", "opengrep", "--no-remote-rules", "--findings-cache", "none",
		"--rules", rules, "--output", findingsPath, "--export-callgraph", callgraphPath,
		"--export-callgraph-project-reachability",
	}
	args = append(append(args, extra...), target)
	cmd := exec.CommandContext(t.Context(), binary, args...)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "crypto-finder output:\n%s", output)

	var report entities.InterimReport
	readJSON(t, findingsPath, &report)
	locations := make(map[string]string)
	for _, finding := range report.Findings {
		rel, relErr := filepath.Rel(target, finding.FilePath)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			rel = finding.FilePath
		}
		for i := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[i]
			locations[asset.FindingID] = filepath.ToSlash(rel) + ":" + strconv.Itoa(asset.StartLine)
		}
	}

	var export polyglotExport
	readJSON(t, callgraphPath, &export)
	verdicts := make(map[string]polyglotVerdict, len(export.FindingGraphs))
	for _, raw := range export.FindingGraphs {
		var fg polyglotFindingGraph
		require.NoError(t, json.Unmarshal(raw, &fg))
		location, ok := locations[fg.FindingID]
		require.Truef(t, ok, "finding graph %s has no interim finding", fg.FindingID)
		verdict := polyglotVerdict{
			location:         location,
			occurrenceKey:    fg.OccurrenceKey,
			reachability:     fg.Reachability,
			unresolvedReason: fg.UnresolvedReason,
		}
		var generic map[string]any
		require.NoError(t, json.Unmarshal(raw, &generic))
		delete(generic, "call_chain_indexes")
		frames := make([][]graphfrag.ExportInternedFunction, 0, len(fg.CallChainIndexes))
		for _, route := range fg.CallChainIndexes {
			names := make([]string, 0, len(route))
			hops := make([]graphfrag.ExportInternedFunction, 0, len(route))
			for _, index := range route {
				require.Less(t, index, len(export.Functions))
				names = append(names, export.Functions[index].FunctionName)
				hops = append(hops, export.Functions[index])
			}
			verdict.chains = append(verdict.chains, names)
			frames = append(frames, hops)
		}
		generic["hydrated_frames"] = frames
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		require.NoError(t, enc.Encode(generic))
		verdict.raw = buf.String()
		verdicts[location] = verdict
	}
	return export, verdicts
}

// A Node package with a package.json and no package-lock.json made
// --scan-dependencies fail the whole scan with dependency_resolution_failed.
// Its dependencies cannot be resolved without the lockfile, so that phase is
// skipped with its own reason, and its first-party code is still analyzed.
func TestNodePackageWithoutLockfileSkipsDependenciesAndKeepsReachability(t *testing.T) {
	if testing.Short() {
		t.Skip("black-box CLI test with a real scanner")
	}
	if _, err := exec.LookPath("opengrep"); err != nil {
		t.Skip("opengrep not installed")
	}
	root := repositoryRoot(t)
	binary := buildCryptoFinder(t, root)
	rules := filepath.Join(root, "testdata", "rules", "polyglot-reachability.yaml")

	work := t.TempDir()
	target := filepath.Join(work, "web")
	require.NoError(t, os.CopyFS(target, os.DirFS(filepath.Join(root, "testdata", "projects", "polyglot_reachability", "web"))))
	_, err := os.Stat(filepath.Join(target, "package-lock.json"))
	require.True(t, os.IsNotExist(err), "the fixture must have no lockfile")

	findingsPath := filepath.Join(work, "findings.json")
	callgraphPath := filepath.Join(work, "callgraph.json")
	cmd := exec.CommandContext(t.Context(), binary,
		"--error-format", "json", "scan", "--progress", "--scanner", "opengrep", "--no-remote-rules", "--findings-cache", "none",
		"--rules", rules, "--scan-dependencies", "--output", findingsPath,
		"--export-callgraph", callgraphPath, "--export-callgraph-project-reachability", target)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoErrorf(t, cmd.Run(), "scan of a Node package without a lockfile failed:\n%s", stderr.String())

	skipped := ""
	for _, line := range strings.Split(stderr.String(), "\n") {
		var event map[string]any
		if json.Unmarshal([]byte(line), &event) != nil || event["event"] != "scan_progress" {
			continue
		}
		if event["phase"] == "dependencies" && event["status"] == "skipped" {
			details, _ := event["details"].(map[string]any)
			skipped, _ = details["reason"].(string)
		}
	}
	require.Equal(t, "lockfile_absent", skipped, "dependencies phase skip reason:\n%s", stderr.String())

	var export polyglotExport
	readJSON(t, callgraphPath, &export)
	require.Equal(t, "node", export.ScanMetadata.Ecosystem)
	reachability := map[string]int{}
	for _, raw := range export.FindingGraphs {
		var fg polyglotFindingGraph
		require.NoError(t, json.Unmarshal(raw, &fg))
		require.Emptyf(t, fg.UnresolvedReason, "finding %s", fg.FindingID)
		reachability[fg.Reachability]++
	}
	require.Equal(t, map[string]int{graphfrag.ReachabilityReachable: 2, graphfrag.ReachabilityUnreachable: 1}, reachability)
}
