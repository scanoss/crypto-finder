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

// A Node fragment lists each file's imports, with the form each was written
// in, under the path its functions name the file by, whichever writer
// produces it.
func TestGraphFragmentImports_Node(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	files := map[string]string{
		"src/sign.js": "const acme = require('acme-crypto');\nimport { seal as close } from 'acme-seal';\n\n" +
			"function sign(k, d) {\n  const h = require('node:crypto');\n  return acme.sign(k, close(d), h);\n}\n\nmodule.exports = { sign };\n",
		"src/types.ts": "import type { Key } from 'acme-crypto';\nexport * from './sign';\n",
		"src/empty.js": "module.exports = 1;\n",
	}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := callgraph.NewBuilderForEcosystem("node", callgraph.NewNodeParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	result := &engine.DepScanResult{CallGraph: graph, Ecosystem: "node", ProjectRoot: root}

	want := map[string][]graphfrag.GraphFragmentImport{
		"src/sign.js": {
			{Line: 1, Module: "acme-crypto", Alias: "acme", Kind: "require"},
			{Line: 2, Module: "acme-seal", Name: "seal", Alias: "close"},
			{Line: 5, Module: "node:crypto", Alias: "h", Kind: "require", Local: true},
		},
		"src/types.ts": {
			{Line: 1, Module: "acme-crypto", Name: "Key", Kind: "type"},
			{Line: 2, Module: "./sign", Name: "*", Kind: "export"},
		},
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
		if !reflect.DeepEqual(export.Imports, want) {
			t.Errorf("%s: imports\n got %+v\nwant %+v", name, export.Imports, want)
		}
	}
}
