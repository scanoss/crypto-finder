// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

// python_perf_test.go — performance guard for T1-T5's added per-file/per-body
// parsing work (binding table, class-attribute walk, synthetic-decl pruning
// walk, recursive import walk). The corpus is generated on demand by
// testdata/python_perf/generate_fixture.go (not committed); this benchmark
// skips when the generated corpus is absent, mirroring the
// testdata/inference_perf/TestPerformance_InferenceOverhead convention.

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
// ParseDirectory + BuildFromDirectories pipeline cost, including this
// change's binding table, class-attribute collection, `<module>`/`<clinit>`
// synthesis, and recursive import walk, over the generated module corpus.
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
