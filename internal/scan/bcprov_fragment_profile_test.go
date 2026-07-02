// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package scan

// bcprov_fragment_profile_test.go — a one-off profiling harness isolating
// BuildGraphFragmentExport (the `scan --export-graph-fragment` code path) on
// the bcprov-jdk15on corpus, split out from the `--export-callgraph` timings
// in internal/callgraph/bcprov_profile_test.go because the two export paths
// are backed by different code (pkg/scan/fragment_export.go vs
// internal/scan/export.go's Tracer.TraceBackLimited) and were reported to
// have very different cost profiles on this corpus. Gated on
// CRYPTO_FINDER_BCPROV_SRC and CRYPTO_FINDER_BCPROV_FINDINGS so it never runs
// in CI.
//
// Example:
//
//	CRYPTO_FINDER_BCPROV_SRC=/path/to/bcprov/src \
//	CRYPTO_FINDER_BCPROV_FINDINGS=/path/to/findings.json \
//	  go test -run TestProfileBcprovGraphFragment -cpuprofile cpu.out -memprofile mem.out \
//	  -timeout 15m ./internal/scan/
//	go tool pprof -top -nodecount=20 cpu.out
//	go tool pprof -top -nodecount=20 -alloc_space mem.out

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

func bcprovFragmentSourceDir(t testing.TB) string {
	t.Helper()
	dir := os.Getenv("CRYPTO_FINDER_BCPROV_SRC")
	if dir == "" {
		t.Skip("set CRYPTO_FINDER_BCPROV_SRC to an unpacked bcprov-jdk15on src dir to run this profiling harness")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("bcprov fixture source not available at %s: %v", dir, err)
	}
	return dir
}

// bcprovFragmentFindings loads a previously-captured InterimReport JSON (the
// --output of a prior `scan` run over the same corpus) so this harness can
// isolate BuildGraphFragmentExport's own cost without re-running opengrep
// every time. Falls back to an empty report (findings=[]) when the env var is
// unset, which still exercises the structural/reachability machinery over
// the full call graph but without any crypto annotations.
func bcprovFragmentFindings(t testing.TB) *entities.InterimReport {
	t.Helper()
	path := os.Getenv("CRYPTO_FINDER_BCPROV_FINDINGS")
	if path == "" {
		t.Log("CRYPTO_FINDER_BCPROV_FINDINGS not set; using an empty findings report")
		return &entities.InterimReport{Tool: entities.ToolInfo{Name: "crypto-finder", Version: "dev"}}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	var report entities.InterimReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Unmarshal InterimReport: %v", err)
	}
	return &report
}

// TestProfileBcprovGraphFragment builds the bcprov call graph once, then runs
// BuildGraphFragmentExport over it — the same function `scan
// --export-graph-fragment` calls. Run under `go test -cpuprofile
// -memprofile` to capture where the fragment-export path spends time/memory.
func TestProfileBcprovGraphFragment(t *testing.T) {
	dir := bcprovFragmentSourceDir(t)
	report := bcprovFragmentFindings(t)

	builder := callgraph.NewBuilderForEcosystem("java", callgraph.NewJavaParser())
	graph, err := builder.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "org.bouncycastle"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories(bcprov): %v", err)
	}
	t.Logf("graph: functions=%d callers=%d edgeResolutions=%d", len(graph.Functions), len(graph.Callers), len(graph.EdgeResolutions))

	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	export := BuildGraphFragmentExport(&engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		ProjectRoot: dir,
		RootModule:  "org.bouncycastle:bcprov-jdk15on",
		Ecosystem:   "java",
	})

	t.Logf("fragment: functions=%d internalEdges=%d externalCalls=%d cryptoOps=%d entryPoints=%d supporting=%d",
		len(export.Functions), len(export.InternalEdges), len(export.ExternalCalls),
		len(export.CryptoAnnotations), len(export.CryptoEntryPoints), len(export.SupportingCalls))
}
