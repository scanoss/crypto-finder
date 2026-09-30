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

package scan

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// entryRootsFixture is a small Java service shaped like the reports that
// motivated walking chains back to entry points:
//
//	TransferHandler.handle (HttpHandler) -> TransferService.submit -> IdempotencyKeyHasher.hash
//	ReplayTool.replay (nothing calls it)  -> TransferService.submit -> IdempotencyKeyHasher.hash
//	NightlyJobs.main -> archiveStatement -> StatementExport.encryptForArchive
//	InlineDigestHandler.handle (HttpHandler) hashes inline
//	LegacyChecksum.legacyChecksum (@Deprecated, nothing calls it) hashes inline
//
// submit calls hash on two lines, so every route through it has two call-site
// variants.
type entryRootsFixture struct {
	root   string
	result *engine.DepScanResult
}

// entryRootsFindings names each planted crypto call by its file and the text
// on its line.
var entryRootsFindings = map[string]struct{ file, needle string }{
	"hash":     {"src/main/java/com/app/service/IdempotencyKeyHasher.java", `MessageDigest.getInstance("SHA-256")`},
	"archive":  {"src/main/java/com/app/service/StatementExport.java", `Cipher.getInstance(`},
	"inline":   {"src/main/java/com/app/api/InlineDigestHandler.java", `MessageDigest.getInstance("MD5")`},
	"checksum": {"src/main/java/com/app/util/LegacyChecksum.java", `MessageDigest.getInstance("SHA-1")`},
}

func newEntryRootsFixture(t *testing.T) entryRootsFixture {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(testFile), "testdata", "entry_roots")
	builder := callgraph.NewBuilderForEcosystem("java", callgraph.NewJavaParser())
	graph, err := builder.BuildFromDirectories([]callgraph.PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	report := &entities.InterimReport{Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"}}
	for _, id := range slices.Sorted(func(yield func(string) bool) {
		for id := range entryRootsFindings {
			if !yield(id) {
				return
			}
		}
	}) {
		planted := entryRootsFindings[id]
		line := lineContaining(t, filepath.Join(root, planted.file), planted.needle)
		report.Findings = append(report.Findings, entities.Finding{
			FilePath: planted.file,
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				FindingID: id,
				StartLine: line,
				EndLine:   line,
				Match:     planted.needle,
				Rules:     []entities.RuleInfo{{ID: "java.crypto." + id}},
				Metadata:  map[string]string{"assetType": "algorithm"},
			}},
		})
	}
	return entryRootsFixture{root: root, result: &engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		Ecosystem:   "java",
		ProjectRoot: root,
		RootModule:  "com.app:app",
	}}
}

func lineContaining(t *testing.T, path, needle string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for i, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	t.Fatalf("%s has no line containing %q", path, needle)
	return 0
}

// entryRootsChain is one exported chain as short Type.method names plus its
// root kind.
type entryRootsChain struct {
	frames   []string
	rootKind string
}

func exportEntryRoots(t *testing.T, fixture entryRootsFixture, maxChains int) map[string]callGraphExportFinding {
	t.Helper()
	path := filepath.Join(t.TempDir(), "callgraph.json")
	options := CallGraphExportOptions{ProjectReachability: true, MaxChains: maxChains}
	if err := exportCallGraphWithOptions(path, "json", fixture.result, options); err != nil {
		t.Fatalf("export: %v", err)
	}
	payload := mustDecodeCallGraphExport(t, path)
	out := map[string]callGraphExportFinding{}
	for i := range payload.FindingGraphs {
		out[payload.FindingGraphs[i].FindingID] = payload.FindingGraphs[i]
	}
	for id := range out {
		fg := out[id]
		identities := catalogChains(t, &payload, fg)
		for i := range fg.CallChains {
			for j := range fg.CallChains[i] {
				fg.CallChains[i][j].FunctionName = identities[i][j].FunctionName
			}
		}
		out[id] = fg
	}
	return out
}

func shortChains(fg callGraphExportFinding) []entryRootsChain {
	out := make([]entryRootsChain, 0, len(fg.CallChains))
	for _, chain := range fg.CallChains {
		c := entryRootsChain{rootKind: chain[0].RootKind}
		for i := range chain {
			parts := strings.Split(chain[i].FunctionName, ".")
			c.frames = append(c.frames, strings.Join(parts[max(0, len(parts)-2):], "."))
		}
		out = append(out, c)
	}
	return out
}

func hasChain(chains []entryRootsChain, rootKind string, frames ...string) bool {
	for _, c := range chains {
		if c.rootKind == rootKind && slices.Equal(c.frames, frames) {
			return true
		}
	}
	return false
}

// TestExportCallGraph_ChainsStartAtEntryPoints: a chain walks back through
// application code to where the program starts, instead of stopping at the
// first application frame (TransferService.submit -> hash).
func TestExportCallGraph_ChainsStartAtEntryPoints(t *testing.T) {
	t.Parallel()
	graphs := exportEntryRoots(t, newEntryRootsFixture(t), 0)

	hash := graphs["hash"]
	if hash.Reachability != graphfrag.ReachabilityReachable {
		t.Fatalf("hash reachability = %q, want reachable", hash.Reachability)
	}
	chains := shortChains(hash)
	if !hasChain(chains, string(callgraph.RootKindFrameworkEntry), "TransferHandler.handle", "TransferService.submit", "IdempotencyKeyHasher.hash") {
		t.Errorf("hash chains = %+v, want one from TransferHandler.handle as a framework entry", chains)
	}
	if !hasChain(chains, string(callgraph.RootKindNoCallers), "ReplayTool.replay", "TransferService.submit", "IdempotencyKeyHasher.hash") {
		t.Errorf("hash chains = %+v, want one from ReplayTool.replay, which nothing calls", chains)
	}

	archive := shortChains(graphs["archive"])
	if !hasChain(archive, string(callgraph.RootKindMain), "NightlyJobs.main", "NightlyJobs.archiveStatement", "StatementExport.encryptForArchive") {
		t.Errorf("archive chains = %+v, want one from NightlyJobs.main", archive)
	}
}

// TestExportCallGraph_EntryPointWithInlineCryptoIsReachable: a handler the
// framework calls, doing crypto itself, has no caller in the graph. It is
// reachable from its own entry point, not unreachable.
func TestExportCallGraph_EntryPointWithInlineCryptoIsReachable(t *testing.T) {
	t.Parallel()
	inline := exportEntryRoots(t, newEntryRootsFixture(t), 0)["inline"]

	if inline.Reachability != graphfrag.ReachabilityReachable {
		t.Fatalf("inline reachability = %q, want reachable", inline.Reachability)
	}
	chains := shortChains(inline)
	if len(chains) != 1 || !hasChain(chains, string(callgraph.RootKindFrameworkEntry), "InlineDigestHandler.handle") {
		t.Fatalf("inline chains = %+v, want the handler alone as a framework entry", chains)
	}
}

// TestExportCallGraph_UncalledNonEntryStaysUnreachable: a deprecated helper
// nothing calls is dead code, not an entry point.
func TestExportCallGraph_UncalledNonEntryStaysUnreachable(t *testing.T) {
	t.Parallel()
	checksum := exportEntryRoots(t, newEntryRootsFixture(t), 0)["checksum"]

	if checksum.Reachability != graphfrag.ReachabilityUnreachable {
		t.Fatalf("checksum reachability = %q, want unreachable", checksum.Reachability)
	}
	for _, chain := range checksum.CallChains {
		if chain[0].RootKind != "" {
			t.Fatalf("checksum self-chain carries root_kind %q, want none", chain[0].RootKind)
		}
	}
}
