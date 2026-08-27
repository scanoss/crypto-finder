// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

// python_perf_test.go — performance guard for the Python parser's
// single-descent architecture (python-parser-parity-2, design.md §3): one
// full-file pythonWalk pass with deferred per-scope call resolution,
// replacing the earlier three-walk pipeline (import prepass + per-function
// walkForCalls + pruned walkPrunedForCalls) this benchmark originally
// guarded (T1-T5, python-parser-java-parity). The corpus is generated on
// demand by testdata/python_perf/generate_fixture.go (not committed); this
// benchmark skips when the generated corpus is absent, mirroring the
// testdata/inference_perf/TestPerformance_InferenceOverhead convention.
// Every row landed on top of this architecture (rows 6-20, C, 14) re-runs
// this benchmark, alongside the deterministic TestPythonParser_NodeVisitBudget
// CI guard, before being considered done — see apply-progress.md for the
// full per-row measurement history.

import (
	"os"
	"path/filepath"
	"testing"
)

// pythonPerfFixtureDir returns the path to the generated python_perf module
// corpus, skipping the test when it has not been generated.
func pythonPerfFixtureDir(t testing.TB) string {
	t.Helper()
	dir := filepath.Join("testdata", "python_perf", "modules")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("performance fixture not found at %s (run: cd testdata/python_perf && go run generate_fixture.go)", dir)
	}
	return dir
}

// BenchmarkPythonParseDirectory_Bindings measures the full Python
// ParseDirectory + BuildFromDirectories pipeline cost — the single-descent
// pythonWalk, its layered binding table, deferred call resolution,
// `<module>`/`<clinit>` synthesis, and import walk — over the generated
// module corpus. The benchmark body itself is unchanged across rows; only
// this doc comment was updated (13.7, python-parser-parity-2 batch 3).
func BenchmarkPythonParseDirectory_Bindings(b *testing.B) {
	dir := pythonPerfFixtureDir(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		builder := NewBuilderForEcosystem("python", NewPythonParser())
		_, err := builder.BuildFromDirectories(
			[]PackageDir{{Dir: dir, ImportPath: "perf"}},
			nil,
		)
		if err != nil {
			b.Fatalf("BuildFromDirectories: %v", err)
		}
	}
}
