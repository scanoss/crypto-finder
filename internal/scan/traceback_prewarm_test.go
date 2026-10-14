// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

const prewarmFindingCount = 400

// withGOMAXPROCS runs fn with GOMAXPROCS set to n, which sizes both the
// traceback prewarm and the edge build. Callers must not be parallel tests.
func withGOMAXPROCS(t *testing.T, n int, fn func()) {
	t.Helper()
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(n))
	fn()
}

// withSyntheticFindings returns the go fixture with one finding in each of
// up to prewarmFindingCount of its project functions, so the export traces
// that many distinct functions.
func withSyntheticFindings(t *testing.T) *engine.DepScanResult {
	t.Helper()
	result := *parallelEdgeFixtures(t)["go"]
	graph := result.CallGraph
	findings := make([]entities.Finding, 0, prewarmFindingCount)
	for _, key := range sortedKeys(graph.Functions) {
		fn := graph.Functions[key]
		rel, err := filepath.Rel(result.ProjectRoot, fn.FilePath)
		if err != nil || strings.HasPrefix(rel, "..") || strings.HasSuffix(rel, "_test.go") || fn.EndLine <= fn.StartLine {
			continue
		}
		findings = append(findings, entities.Finding{FilePath: rel, Language: "go", CryptographicAssets: []entities.CryptographicAsset{{
			FindingID: fmt.Sprintf("prewarm-%d", len(findings)),
			StartLine: fn.StartLine + 1,
			EndLine:   fn.StartLine + 1,
			Match:     "sha256.Sum256(data)",
			Rules:     []entities.RuleInfo{{ID: "go.crypto.sha256"}},
			Metadata:  map[string]string{"assetType": "algorithm"},
		}}})
		if len(findings) == prewarmFindingCount {
			break
		}
	}
	if len(findings) < prewarmFindingCount {
		t.Fatalf("fixture yields %d findings, want %d", len(findings), prewarmFindingCount)
	}
	report := *result.Report
	report.Findings = findings
	result.Report = &report
	return &result
}

// The prewarm traces on forks of the shared tracer, concurrently: under
// -race this catches a fork that shares mutable tracer state. Each pretraced
// trace must be the one the shared tracer gives serially.
func TestPrewarmTracebacksMatchesSharedTracer(t *testing.T) {
	result := withSyntheticFindings(t)
	ctx := newExportBuildContext(result)
	fns := findingContainingFunctions(ctx, result.Report.Findings)
	withGOMAXPROCS(t, 8, func() { prewarmTracebacks(ctx, fns) })

	if len(ctx.pretraced) < prewarmFindingCount/2 {
		t.Fatalf("prewarm traced %d functions, want at least %d", len(ctx.pretraced), prewarmFindingCount/2)
	}
	serial := newExportBuildContext(result).sharedTracer()
	for _, fn := range fns {
		if fn == nil {
			continue
		}
		want := serial.TraceBackCondensed(fn.ID, ctx.userPackages, ctx.maxDepth, ctx.emitMaxChains())
		if got := ctx.pretraced[fn.ID.String()]; !reflect.DeepEqual(got, want) {
			t.Fatalf("pretraced %s differs from the serial trace", fn.ID)
		}
	}
}

// A fragment with findings, whose tracebacks the prewarm runs on several
// workers, must be byte for byte the one a single-threaded export writes.
func TestGraphFragmentWithFindingsParallelMatchesSerial(t *testing.T) {
	result := withSyntheticFindings(t)
	write := func(procs int) []byte {
		t.Helper()
		var data []byte
		withGOMAXPROCS(t, procs, func() {
			path := filepath.Join(t.TempDir(), "fragment.json")
			if err := exportGraphFragment(path, "json", result); err != nil {
				t.Fatalf("exportGraphFragment(GOMAXPROCS=%d): %v", procs, err)
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
	if n := bytes.Count(serial, []byte(`"prewarm-`)); n < prewarmFindingCount {
		t.Fatalf("serial fragment names %d synthetic findings, want at least %d", n, prewarmFindingCount)
	}
	for _, procs := range []int{2, 8} {
		if parallel := write(procs); !bytes.Equal(serial, parallel) {
			t.Fatalf("GOMAXPROCS=%d fragment differs from the serial one (%d vs %d bytes)", procs, len(parallel), len(serial))
		}
	}
}
