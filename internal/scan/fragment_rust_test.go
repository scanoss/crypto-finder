// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/oid"
)

// buildRustProject builds the call graph of a Rust source tree.
func buildRustProject(t *testing.T, files map[string]string) *engine.DepScanResult {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := callgraph.NewBuilderForEcosystem("rust", callgraph.NewParserForEcosystem("rust")).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return &engine.DepScanResult{CallGraph: graph, Ecosystem: "rust", ProjectRoot: root}
}

// A Rust fragment lists each file's use bindings, with their spans and use
// trees, the items the file declares, a fn with its parameters and a type
// alias with its aliased type as written and the column of its `type`
// keyword, and the binary expressions of its function bodies, whichever
// writer produces it.
func TestGraphFragmentImportsAndItems_Rust(t *testing.T) {
	t.Parallel()
	result := buildRustProject(t, map[string]string{
		"src/lib.rs": "use acme::kdf::{Kdf, self};\n\npub fn derive(k: &[u8], n: usize) -> Vec<u8> {\n    Kdf::new().run(k, n * 8)\n}\n\npub type Mode = acme::Mode<acme::Blk128>;\n",
	})
	dir := t.TempDir()
	streamed, raw := filepath.Join(dir, "resolved.json"), filepath.Join(dir, "raw.json")
	if err := ExportResolvedGraphFragment(streamed, "json", result, &oid.ResolvedReport{}); err != nil {
		t.Fatal(err)
	}
	if err := exportGraphFragment(raw, result); err != nil {
		t.Fatal(err)
	}
	wantImports := map[string][]graphfrag.GraphFragmentImport{
		"src/lib.rs": {
			{Line: 1, Module: "acme::kdf", Name: "Kdf", StartCol: 1, EndCol: 28, Text: "acme::kdf::{Kdf, self}"},
			{Line: 1, Module: "acme", Name: "kdf", StartCol: 1, EndCol: 28, Text: "acme::kdf::{Kdf, self}"},
		},
	}
	exports := map[string]graphfrag.GraphFragmentExport{
		"resolved writer":     decodeFragmentFile(t, streamed),
		"raw writer":          decodeFragmentFile(t, raw),
		"resolved projection": BuildGraphFragmentExport(result, &oid.ResolvedReport{}),
		"raw projection":      buildGraphFragmentExport(result),
	}
	for name, export := range exports {
		if !reflect.DeepEqual(export.Imports, wantImports) {
			t.Errorf("%s: imports\n got %+v\nwant %+v", name, export.Imports, wantImports)
		}
		items := export.Items["src/lib.rs"]
		if len(items) != 2 || items[0].Kind != "fn" || items[0].Name != "derive" || items[0].Line != 3 || items[0].EndLine != 5 {
			t.Errorf("%s: items %+v, want a fn derive spanning lines 3-5 and a type alias", name, items)
			continue
		}
		wantAlias := graphfrag.GraphFragmentItem{Line: 7, StartCol: 1, EndCol: 42, Kind: "type", Name: "Mode", Type: "acme::Mode<acme::Blk128>", KeywordCol: 5}
		if !reflect.DeepEqual(items[1], wantAlias) {
			t.Errorf("%s: alias %+v, want %+v", name, items[1], wantAlias)
		}
		wantParams := []graphfrag.GraphFragmentParam{
			{Line: 3, StartCol: 15, EndCol: 23, Pattern: "k", Type: "&[u8]"},
			{Line: 3, StartCol: 25, EndCol: 33, Pattern: "n", Type: "usize"},
		}
		if !reflect.DeepEqual(items[0].Params, wantParams) {
			t.Errorf("%s: derive params %+v, want %+v", name, items[0].Params, wantParams)
		}
		wantExprs := map[string][]graphfrag.GraphFragmentBinaryExpr{
			"src/lib.rs": {{Line: 4, StartCol: 23, EndCol: 28, Op: "*", Left: "n", Right: "8", LeftEndCol: 24, RightStartCol: 27, Function: "derive"}},
		}
		if !reflect.DeepEqual(export.BinaryExprs, wantExprs) {
			t.Errorf("%s: binary exprs\n got %+v\nwant %+v", name, export.BinaryExprs, wantExprs)
		}
		if !reflect.DeepEqual(export.Imports, exports["raw projection"].Imports) || !reflect.DeepEqual(export.Items, exports["raw projection"].Items) ||
			!reflect.DeepEqual(export.BinaryExprs, exports["raw projection"].BinaryExprs) {
			t.Errorf("%s: differs from the raw projection", name)
		}
	}
}
