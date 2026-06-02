// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "testing"

// TestDecodeFragment_GraphAlgoVersionAndEndLine asserts that the structural
// graph carries graph_algo_version (the rules-independent cache key for the
// annotate-only reuse path) and that function EndLine survives ingest (needed
// to map a finding to its containing function during annotate-only).
func TestDecodeFragment_GraphAlgoVersionAndEndLine(t *testing.T) {
	if GraphAlgoVersion == "" {
		t.Fatal("GraphAlgoVersion constant must be non-empty")
	}
	raw := []byte(`{
		"schema_version": "graph-fragment-1.2",
		"scan_metadata": {"root_module": "com.acme:app", "graph_algo_version": "graph-algo-1"},
		"functions": [
			{"key": "com.acme.(App).run#0", "function_name": "com.acme.App.run", "file_path": "App.java", "start_line": 5, "end_line": 12}
		]
	}`)
	frag, err := DecodeFragment(ComponentKey{Purl: "pkg:maven/com.acme/app", Version: "1.0"}, raw)
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}
	if frag.GraphAlgoVersion != "graph-algo-1" {
		t.Errorf("Fragment.GraphAlgoVersion = %q, want graph-algo-1", frag.GraphAlgoVersion)
	}
	if len(frag.Functions) != 1 {
		t.Fatalf("functions len = %d, want 1", len(frag.Functions))
	}
	if frag.Functions[0].EndLine != 12 {
		t.Errorf("Function.EndLine = %d, want 12 (not carried through ingest)", frag.Functions[0].EndLine)
	}
}
