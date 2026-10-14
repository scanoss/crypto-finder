// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

var exportedAtField = regexp.MustCompile(`"exported_at": ?"[^"]*"`)

// withFragmentEdgeWorkers runs fn with the edge build pinned to n workers.
// Callers must not be parallel tests: the worker count is package state.
func withFragmentEdgeWorkers(t *testing.T, n int, fn func()) {
	t.Helper()
	saved := fragmentEdgeWorkers
	fragmentEdgeWorkers = func() int { return n }
	defer func() { fragmentEdgeWorkers = saved }()
	fn()
}

// parallelEdgeFixtures are real call graphs, large enough to span many work
// items: this repository's own Go packages and the Java test sources.
func parallelEdgeFixtures(t *testing.T) map[string]*engine.DepScanResult {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	internalDir := filepath.Dir(filepath.Dir(testFile))
	packages := []string{"callgraph", "scan", "engine"}
	goDirs := make([]callgraph.PackageDir, 0, len(packages))
	for _, pkg := range packages {
		goDirs = append(goDirs, callgraph.PackageDir{
			Dir:        filepath.Join(internalDir, pkg),
			ImportPath: "github.com/scanoss/crypto-finder/internal/" + pkg,
		})
	}
	goGraph, err := callgraph.NewBuilderForEcosystem("go", callgraph.NewGoParser()).BuildFromDirectories(goDirs, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories(go): %v", err)
	}
	javaRoot := filepath.Join(filepath.Dir(testFile), "testdata")
	javaGraph, err := callgraph.NewBuilderForEcosystem("java", callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: javaRoot}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories(java): %v", err)
	}
	report := func() *entities.InterimReport {
		return &entities.InterimReport{Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"}}
	}
	return map[string]*engine.DepScanResult{
		"go":   {Report: report(), CallGraph: goGraph, ProjectRoot: internalDir, RootModule: "github.com/scanoss/crypto-finder", Ecosystem: "go"},
		"java": {Report: report(), CallGraph: javaGraph, ProjectRoot: javaRoot, RootModule: "org.example:testdata", Ecosystem: "java"},
	}
}

// The parallel edge build must write the fragment a serial build writes, byte
// for byte, whatever the number of workers.
func TestGraphFragmentEdgesParallelMatchesSerial(t *testing.T) {
	for name, result := range parallelEdgeFixtures(t) {
		t.Run(name, func(t *testing.T) {
			if name == "go" {
				requireSplitCallee(t, planFragmentEdgeItems(result.CallGraph, sortedKeys(result.CallGraph.Callers)))
			}
			write := func(workers int) []byte {
				t.Helper()
				var data []byte
				withFragmentEdgeWorkers(t, workers, func() {
					path := filepath.Join(t.TempDir(), "fragment.json")
					if err := exportGraphFragment(path, "json", result); err != nil {
						t.Fatalf("exportGraphFragment(workers=%d): %v", workers, err)
					}
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatalf("ReadFile: %v", err)
					}
					data = exportedAtField.ReplaceAll(raw, []byte(`"exported_at":""`))
				})
				return data
			}
			serial := write(1)
			if !bytes.Contains(serial, []byte(`"internal_edges_compact": [`)) {
				t.Fatalf("serial fragment has no internal edges")
			}
			for _, workers := range []int{2, 3, 8} {
				if parallel := write(workers); !bytes.Equal(serial, parallel) {
					t.Fatalf("workers=%d fragment differs from the serial one (%d vs %d bytes)", workers, len(parallel), len(serial))
				}
			}

			build := func(workers int) graphfrag.GraphFragmentExport {
				var out graphfrag.GraphFragmentExport
				withFragmentEdgeWorkers(t, workers, func() {
					out = buildGraphFragmentProjection(result)
					out.ScanMetadata.ExportedAt = ""
				})
				return out
			}
			if serial, parallel := build(1), build(8); !reflect.DeepEqual(serial, parallel) {
				t.Fatalf("parallel in-memory projection differs from the serial one")
			}
		})
	}
}

// requireSplitCallee fails unless items hold several work items, one of them
// a run of a callee cut into several.
func requireSplitCallee(t *testing.T, items [][]fragmentEdgePiece) {
	t.Helper()
	for _, item := range items {
		if len(items) >= 8 && len(item) == 1 && item[0].callers != nil {
			return
		}
	}
	t.Fatalf("fixture plans %d work items and no split callee, want both", len(items))
}

// The work items cover every callee in order, each exactly once, and cut only
// callees with more callers than one item takes, into runs of their sorted
// callers.
func TestPlanFragmentEdgeItems(t *testing.T) {
	graph := parallelEdgeFixtures(t)["go"].CallGraph
	calleeKeys := sortedKeys(graph.Callers)
	items := planFragmentEdgeItems(graph, calleeKeys)
	requireSplitCallee(t, items)
	var gotCallees []string
	callersOf := make(map[string][]string)
	for _, item := range items {
		pairs := 0
		for _, piece := range item {
			if n := len(gotCallees); n == 0 || gotCallees[n-1] != piece.calleeKey {
				gotCallees = append(gotCallees, piece.calleeKey)
			}
			callers := piece.callers
			if callers == nil {
				callers = sortedFragmentCallers(graph, piece.calleeKey)
			} else if len(item) != 1 {
				t.Fatalf("split callee %s shares a work item", piece.calleeKey)
			}
			callersOf[piece.calleeKey] = append(callersOf[piece.calleeKey], callers...)
			pairs += max(len(callers), 1)
		}
		if limit := 2 * fragmentEdgeItemCallers; pairs > limit {
			t.Fatalf("work item covers %d pairs, want at most %d", pairs, limit)
		}
	}
	if !reflect.DeepEqual(gotCallees, calleeKeys) {
		t.Fatalf("work items cover %d callees out of order or twice, want the %d in order", len(gotCallees), len(calleeKeys))
	}
	for _, calleeKey := range calleeKeys {
		if want := sortedFragmentCallers(graph, calleeKey); len(want) > 0 && !reflect.DeepEqual(callersOf[calleeKey], want) {
			t.Fatalf("callers of %s = %v, want %v", calleeKey, callersOf[calleeKey], want)
		}
	}
}

// A consumer that quits stops the parallel build.
func TestForEachFragmentEdgesStopsWhenConsumerQuits(t *testing.T) {
	result := parallelEdgeFixtures(t)["go"]
	ctx := newExportBuildContext(result)
	keys := sortedKeys(ctx.graph.Callers)
	const quitAt = 100
	consumed := 0
	withFragmentEdgeWorkers(t, 4, func() {
		forEachFragmentEdges(ctx, keys, nil, func(fragmentEdges) bool {
			consumed++
			return consumed < quitAt
		})
	})
	if consumed != quitAt {
		t.Fatalf("consumed %d runs, want %d", consumed, quitAt)
	}
}

// Forks share the memo caches an earlier stage half filled, so they read and
// fill them concurrently: under -race this catches a memo cache shared
// without a guard.
// The result must still be the one a cold serial build gives.
func TestForEachFragmentEdgesWithWarmCaches(t *testing.T) {
	for name, result := range parallelEdgeFixtures(t) {
		t.Run(name, func(t *testing.T) { checkParallelEdgesOverWarmCaches(t, result) })
	}
}

func checkParallelEdgesOverWarmCaches(t *testing.T, result *engine.DepScanResult) {
	t.Helper()
	collect := func(ctx *exportBuildContext, workers int) fragmentEdges {
		var out fragmentEdges
		withFragmentEdgeWorkers(t, workers, func() {
			forEachFragmentEdges(ctx, sortedKeys(ctx.graph.Callers), encodeFragmentEntryCalls, func(edges fragmentEdges) bool {
				out.internal = append(out.internal, edges.internal...)
				out.external = append(out.external, edges.external...)
				out.entryCalls = append(out.entryCalls, edges.entryCalls...)
				return true
			})
		})
		return out
	}
	serial := collect(newExportBuildContext(result), 1)

	warm := newExportBuildContext(result)
	// Half warm: the forks must still fill the other half, which is the write
	// that races on a shared cache.
	for i, key := range sortedKeys(warm.graph.Functions) {
		if i%2 == 1 {
			continue
		}
		fn := warm.graph.Functions[key]
		warm.chainIDForLine(key, fn, fn.StartLine)
		warm.callSignatureIndexForCaller(key, fn)
		calleeSignatureKey(warm, key)
		normalizeExportPath(warm, fn.FilePath)
	}
	warm.returnInlining = map[string]bool{}
	first := sortedKeys(warm.graph.Functions)[0]
	_, warmCalls := warm.callsBySignature.lookup(first)
	_, warmChains := warm.chainIDsByCallerLine.lookup(first)
	_, warmSignatures := warm.calleeSignatureKeys.lookup(first)
	_, warmLocations := warm.exportLocations.lookup(warm.graph.Functions[first].FilePath)
	if !warmCalls || !warmChains || !warmSignatures || !warmLocations {
		t.Fatal("caches not warmed")
	}
	if parallel := collect(warm, 8); !reflect.DeepEqual(serial, parallel) {
		t.Fatal("parallel edges over warm caches differ from the cold serial ones")
	}
}

// writeCompactEdge must write what writeArrayElement writes through
// graphfrag's MarshalJSON: for every edge of the fixtures, and for the edge
// shapes MarshalJSON trims or escapes differently.
func TestAppendCompactFragmentEdgeMatchesMarshalJSON(t *testing.T) {
	escaped := &graphfrag.GraphFragmentCallSite{Line: 7, Parameters: []graphfrag.GraphFragmentParameter{{
		ParameterIndex: 1, Type: "java.util.List<byte[]>", ArgumentExpression: `a < b && c > "d"`,
	}}}
	edges := []graphfrag.GraphFragmentCompactEdge{
		{},
		{Caller: 1},
		{Caller: 1, Callee: 2, Line: 3, ResolvedReceiverType: 4},
		{Caller: 1, Callee: 2, EndCol: 9},
		{EntryCall: &graphfrag.GraphFragmentCallSite{}},
		{Caller: 3, Arity: 2, EntryCall: escaped},
	}
	for _, result := range parallelEdgeFixtures(t) {
		ctx := newExportBuildContext(result)
		interner := newFragmentStringInterner()
		functionIndex := make(map[string]int)
		for i, key := range sortedKeys(ctx.graph.Functions) {
			functionIndex[key] = i
		}
		for _, calleeKey := range sortedKeys(ctx.graph.Callers) {
			for _, edge := range buildResolvedFragmentEdgesFrom(ctx, calleeKey, sortedFragmentCallers(ctx.graph, calleeKey)).internal {
				edges = append(edges, compactGraphFragmentEdge(edge, functionIndex, interner))
			}
		}
	}
	withEntryCall := 0
	for _, edge := range edges {
		var want bytes.Buffer
		if err := writeJSONValue(&want, edge); err != nil {
			t.Fatalf("writeJSONValue: %v", err)
		}
		var entryCall []byte
		if edge.EntryCall != nil {
			withEntryCall++
			fragment := fragmentEdges{internal: []graphfrag.GraphFragmentEdge{{EntryCall: edge.EntryCall}}}
			encodeFragmentEntryCalls(&fragment)
			entryCall = fragment.entryCalls[0]
		}
		if got := appendCompactFragmentEdge(nil, edge, entryCall); !bytes.Equal(got, want.Bytes()) {
			t.Fatalf("appendCompactFragmentEdge = %s, want %s", got, want.Bytes())
		}
	}
	if len(edges) < 1000 || withEntryCall < 100 {
		t.Fatalf("checked %d edges, %d with an entry call: fixtures too small", len(edges), withEntryCall)
	}
}
