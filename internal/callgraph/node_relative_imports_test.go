// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveNodeRelativeModule(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	for _, rel := range []string{"src/routes/profile.ts", "src/lib/hash.ts", "src/util/index.ts", "src/both.ts", "src/both/index.ts"} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("export {};\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	importer := filepath.Join(root, "src", "routes", "profile.ts")

	cases := []struct {
		name, packagePath, specifier, want string
		resolved                           bool
	}{
		{name: "parent directory", packagePath: "src/routes", specifier: "../lib/hash", want: "src/lib/hash", resolved: true},
		{name: "written js extension names the ts module", packagePath: "src/routes", specifier: "../lib/hash.js", want: "src/lib/hash", resolved: true},
		{name: "directory resolves to its index", packagePath: "src/routes", specifier: "../util", want: "src/util/index", resolved: true},
		{name: "a file wins over a directory of the same name", packagePath: "src/routes", specifier: "../both", want: "src/both", resolved: true},
		{name: "same directory", packagePath: "src/routes", specifier: "./missing", want: "src/routes/missing", resolved: true},
		{name: "bare package keeps its name", packagePath: "src/routes", specifier: "crypto"},
		{name: "scoped package keeps its name", packagePath: "src/routes", specifier: "@noble/hashes/sha256"},
		{name: "above the scanned tree keeps its form", packagePath: "src/routes", specifier: "../../../outside"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := resolveNodeRelativeModule(importer, tc.packagePath, tc.specifier)
			if ok != tc.resolved || got != tc.want {
				t.Fatalf("resolveNodeRelativeModule(%q) = (%q, %v), want (%q, %v)", tc.specifier, got, ok, tc.want, tc.resolved)
			}
		})
	}
}

// A call through a relative import must target the identity the imported file
// declares its export under. The specifier used to be kept verbatim, so the
// callee named a module no file declares and the cross-file edge was lost.
func TestNodeBuilder_RelativeImportLinksToTheDeclaringModule(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	files := map[string]string{
		"src/lib/hash.ts":       "import { createHash } from 'crypto';\nexport function fingerprint(s: string) { return createHash('md5').update(s).digest('hex'); }\n",
		"src/routes/profile.ts": "import { fingerprint } from '../lib/hash';\nexport function render(s: string) { return fingerprint(s); }\n",
	}
	for rel, content := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	builder := NewBuilderForEcosystem("node", NewNodeParser())
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	callers := graph.Callers["src/lib/hash.fingerprint"]
	if len(callers) != 1 || callers[0] != "src/routes/profile.render" {
		t.Fatalf("callers of src/lib/hash.fingerprint = %v, want [src/routes/profile.render]", callers)
	}
}
