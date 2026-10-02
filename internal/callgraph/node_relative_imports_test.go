// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path"
	"path/filepath"
	"testing"
)

func TestResolveNodeRelativeModule(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	for _, rel := range []string{"src/routes/profile.ts", "src/lib/hash.ts", "src/util/index.ts", "src/both.ts", "src/both/index.ts"} {
		target := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("export {};\n"), 0o600); err != nil {
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
		target := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
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

// A specifier written with an extension names a file in whatever directory it
// points at, and the module it resolves to is keyed by that file's own package
// path, as nodeModulePath keys it when the parser declares the file.
func TestResolveNodeRelativeModule_WrittenExtensionKeepsTheTargetDirectory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, rel := range []string{
		"app/main.mjs", "app/a.mjs", "app/lib/a.js", "app/lib/b.ts", "app/lib/b.mjs",
		"x/a.ts", "a.mjs", "app/deep/er/main.js",
	} {
		writeNodeFixtureFile(t, filepath.Join(root, filepath.FromSlash(rel)), "x()\n")
	}
	cases := []struct {
		name, importer, packagePath, specifier, want string
		file                                         string
	}{
		{"same directory", "app/main.mjs", "app", "./a.mjs", "app/a", "app/a.mjs"},
		{"subdirectory", "app/main.mjs", "app", "./lib/a.js", "app/lib/a", "app/lib/a.js"},
		{"subdirectory ts", "app/main.mjs", "app", "./lib/b.ts", "app/lib/b", "app/lib/b.ts"},
		{"same-stem sibling in a subdirectory", "app/main.mjs", "app", "./lib/b.mjs", "app/lib/b.mjs", "app/lib/b.mjs"},
		{"parent directory", "app/main.mjs", "app", "../x/a.ts", "x/a", "x/a.ts"},
		{"two levels up into the root", "app/deep/er/main.js", "app/deep/er", "../../../a.mjs", "a", "a.mjs"},
		{"nested depth", "app/deep/er/main.js", "app/deep/er", "../../lib/a.js", "app/lib/a", "app/lib/a.js"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			importer := filepath.Join(root, filepath.FromSlash(tc.importer))
			got, ok := resolveNodeRelativeModule(importer, tc.packagePath, tc.specifier)
			if !ok || got != tc.want {
				t.Fatalf("resolveNodeRelativeModule(%q) = (%q, %v), want %q", tc.specifier, got, ok, tc.want)
			}
			dir := path.Dir(tc.file)
			if dir == "." {
				dir = ""
			}
			if declared := nodeModulePath(dir, filepath.Join(root, filepath.FromSlash(tc.file))); declared != got {
				t.Fatalf("resolved %q, but the parser keys %s as %q", got, tc.file, declared)
			}
		})
	}
}

// An import written with an extension into another directory must link the
// caller to the function the file there declares.
func TestNodeBuilder_ExplicitExtensionImportReachesAnotherDirectory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeNodeFixtureFile(t, filepath.Join(root, "server.js"), "import { applyDeferred } from './lib/svelte.js';\nexport function startup() { return applyDeferred('x'); }\n")
	writeNodeFixtureFile(t, filepath.Join(root, "lib", "svelte.js"), "import { createHash } from 'crypto';\nexport function applyDeferred(s) { return createHash('md5').update(s); }\n")
	writeNodeFixtureFile(t, filepath.Join(root, "sub", "run.ts"), "import { boot } from '../bootstrap.ts';\nexport function run() { return boot(); }\n")
	writeNodeFixtureFile(t, filepath.Join(root, "bootstrap.ts"), "export function boot() { return 1; }\n")
	graph, err := NewBuilderForEcosystem("node", NewNodeParser()).BuildFromDirectories([]PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for callee, caller := range map[string]string{
		"lib/svelte.applyDeferred": "server.startup",
		"bootstrap.boot":           "sub/run.run",
	} {
		callers := graph.Callers[callee]
		if len(callers) != 1 || callers[0] != caller {
			t.Errorf("callers of %s = %v, want [%s]", callee, callers, caller)
		}
	}
}
