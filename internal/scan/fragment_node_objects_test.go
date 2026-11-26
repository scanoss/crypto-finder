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

// A Node fragment lists each file's outermost object literals, text and
// position, under the path its functions name the file by, whichever writer
// produces it; end_line only for a literal that spans lines.
func TestGraphFragmentObjectLiterals_Node(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	src := "const acme = require('acme-crypto');\n" +
		"const opts = { mode: 'x1' };\n" +
		"function seal(d) {\n  return acme.seal(d, {\n    mode: 'x2',\n  });\n}\n" +
		"module.exports = { seal };\n"
	path := filepath.Join(root, "src", "seal.js")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem("node", callgraph.NewNodeParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	result := &engine.DepScanResult{CallGraph: graph, Ecosystem: "node", ProjectRoot: root}

	got := BuildGraphFragmentExport(result, &oid.ResolvedReport{}).ObjectLiterals["src/seal.js"]
	if len(got) != 3 {
		t.Fatalf("object literals: got %+v, want 3", got)
	}
	module, inner := got[0].CallerKey, got[1].CallerKey
	want := []graphfrag.GraphFragmentObjectLiteral{
		{Line: 2, StartCol: 14, EndCol: 28, Text: "{ mode: 'x1' }", CallerKey: module, AssignedVar: "opts", AssignStartCol: 7},
		{Line: 4, StartCol: 23, EndLine: 6, EndCol: 4, Text: "{\n    mode: 'x2',\n  }", CallerKey: inner},
		{Line: 8, StartCol: 18, EndCol: 26, Text: "{ seal }", CallerKey: module},
	}
	if module == inner || inner == "" {
		t.Errorf("caller keys: module %q, function %q", module, inner)
	}
	dir := t.TempDir()
	streamed, raw := filepath.Join(dir, "resolved.json"), filepath.Join(dir, "raw.json")
	if err := ExportResolvedGraphFragment(streamed, "json", result, &oid.ResolvedReport{}); err != nil {
		t.Fatal(err)
	}
	if err := exportGraphFragment(raw, result); err != nil {
		t.Fatal(err)
	}
	for name, export := range map[string]graphfrag.GraphFragmentExport{
		"resolved writer":     decodeFragmentFile(t, streamed),
		"raw writer":          decodeFragmentFile(t, raw),
		"resolved projection": BuildGraphFragmentExport(result, &oid.ResolvedReport{}),
		"raw projection":      buildGraphFragmentExport(result),
	} {
		if g := export.ObjectLiterals["src/seal.js"]; !reflect.DeepEqual(g, want) {
			t.Errorf("%s: object literals\n got %+v\nwant %+v", name, g, want)
		}
	}
}
