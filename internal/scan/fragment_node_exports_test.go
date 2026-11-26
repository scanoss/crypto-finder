// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/reach/callgraph"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/oid"
)

// A Node package's fragment lists the keys a caller spells through its
// specifier, mapped to the functions the package declares, whichever writer
// produces it (the package built as a scan builds it), so a stitch joins an application's `require("acme-sign")` call
// into the package.
func TestGraphFragmentExports_Node(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for name, content := range map[string]string{
		"package.json": `{"name": "acme-sign", "version": "1.0.0", "main": "index.js"}` + "\n",
		"index.js":     "exports.sign = function sign(k) { return k; };\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := callgraph.NewBuilderForEcosystem("node", callgraph.NewParserForEcosystem("node")).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: root, ImportPath: DetectRootModule(root, "node")}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	result := &engine.DepScanResult{CallGraph: graph, Ecosystem: "node", ProjectRoot: root}
	if len(graph.NodePackageExports) == 0 {
		t.Fatal("the graph has no node package exports")
	}
	dir := t.TempDir()
	streamed, raw := filepath.Join(dir, "resolved.json"), filepath.Join(dir, "raw.json")
	if err := ExportResolvedGraphFragment(streamed, "json", result, &oid.ResolvedReport{}); err != nil {
		t.Fatal(err)
	}
	if err := exportGraphFragment(raw, result); err != nil {
		t.Fatal(err)
	}
	for name, exports := range map[string]map[string]string{
		"resolved writer":     decodeFragmentFile(t, streamed).Exports,
		"raw writer":          decodeFragmentFile(t, raw).Exports,
		"resolved projection": BuildGraphFragmentExport(result, &oid.ResolvedReport{}).Exports,
		"raw projection":      buildGraphFragmentExport(result).Exports,
	} {
		key, ok := exports["acme-sign.sign"]
		if !ok || key == "acme-sign.sign" {
			t.Errorf("%s: exports %v, want acme-sign.sign mapped to the package's own key", name, exports)
		}
	}
}
