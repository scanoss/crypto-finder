// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package callgraph

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestNodeHasScriptShebang(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, file, src string
		want            bool
	}{
		{"env node", "a.js", "#!/usr/bin/env node\nx()\n", true},
		{"env bun ts", "a.ts", "#!/usr/bin/env bun\nx()\n", true},
		{"env -S deno", "a.mjs", "#!/usr/bin/env -S deno run --allow-read\nx()\n", true},
		{"env -S node flags", "a.cjs", "#!/usr/bin/env -S node --no-warnings\n", true},
		{"direct path", "a.mts", "#!/usr/local/bin/tsx\n", true},
		{"ts-node", "a.cts", "#!/usr/bin/env ts-node\n", true},
		{"windows line ending", "a.js", "#!/usr/bin/env node\r\nx()\n", true},
		{"python", "a.js", "#!/usr/bin/env python3\n", false},
		{"sh", "a.js", "#!/bin/sh\n", false},
		{"no shebang", "a.js", "const x = 1\n", false},
		{"shebang not first line", "a.js", "\n#!/usr/bin/env node\n", false},
		{"other extension", "a.json", "#!/usr/bin/env node\n", false},
		{"bare shebang", "a.js", "#!\n", false},
		{"env -u value", "a.js", "#!/usr/bin/env -u FOO node\n", true},
		{"env --unset value", "a.js", "#!/usr/bin/env --unset FOO node\n", true},
		{"env -u value then python", "a.js", "#!/usr/bin/env -u node python3\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := nodeHasScriptShebang(c.file, []byte(c.src)); got != c.want {
				t.Fatalf("nodeHasScriptShebang(%q, %q) = %v, want %v", c.file, c.src, got, c.want)
			}
		})
	}
}

func TestNodeScriptTargets(t *testing.T) {
	t.Parallel()
	cases := []struct {
		script string
		want   []string
	}{
		{"tsx scripts/baseline-drizzle.ts", []string{"scripts/baseline-drizzle.ts"}},
		{"node scripts/run.js", []string{"scripts/run.js"}},
		{"node ./dist/cli.js --flag", []string{"./dist/cli.js"}},
		{"ts-node -r dotenv/config src/seed.ts", []string{"src/seed.ts"}},
		{"bun run scripts/a.ts", []string{"scripts/a.ts"}},
		{"deno run --allow-net scripts/a.ts", []string{"scripts/a.ts"}},
		{"NODE_ENV=test cross-env X=1 node build.cjs", []string{"build.cjs"}},
		{"npx tsx tools/gen.mts", []string{"tools/gen.mts"}},
		{"tsc && node scripts/a.js && tsx scripts/b.ts", []string{"scripts/a.js", "scripts/b.ts"}},
		{"echo hi; node scripts/a.js | tee out.log", []string{"scripts/a.js"}},
		{`node "scripts/quoted.js"`, []string{"scripts/quoted.js"}},
		{"node --require ./setup.js scripts/a.js", []string{"scripts/a.js"}},
		{"node --max-old-space-size 4096 scripts/a.js", []string{"scripts/a.js"}},
		{"tsx watch scripts/a.ts", []string{"scripts/a.ts"}},
		{"dotenv -e .env -- node scripts/a.js", []string{"scripts/a.js"}},
		{"npx -y tsx scripts/a.ts", []string{"scripts/a.ts"}},
		{"env -u FOO node scripts/a.js", []string{"scripts/a.js"}},
		{"eslint scripts/a.js", nil},
		{"jest scripts/a.test.js", nil},
		{"bun run build", nil},
		{"node -e 'console.log(1)'", nil},
		{"node", nil},
		{"node $FILE", nil},
		{"node scripts/*.js", nil},
		{"npm run other", nil},
		{"", nil},
	}
	for _, c := range cases {
		if got := nodeScriptTargets(c.script); !slices.Equal(got, c.want) {
			t.Errorf("nodeScriptTargets(%q) = %v, want %v", c.script, got, c.want)
		}
	}
}

func TestParseNodeManifest_ScriptsBecomeProgramEntries(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifest := parseNodeManifest(dir, []byte(`{
		"main": "dist/index.js",
		"bin": {"tool": "bin/tool.js"},
		"scripts": {
			"db:baseline": "tsx scripts/baseline-drizzle.ts",
			"build": "tsc && node dist/tasks/build.js",
			"lint": "eslint scripts/linted.js",
			"count": 3
		}
	}`))
	for rel, want := range map[string]bool{
		"scripts/baseline-drizzle": true,
		"dist/tasks/build":         true,
		"src/tasks/build":          true,
		"scripts/linted":           false,
		"lib/plain":                false,
	} {
		if got := manifest.scripts[rel]; got != want {
			t.Errorf("scripts[%q] = %v, want %v", rel, got, want)
		}
	}
	if !manifest.mains["dist/index"] || !manifest.bins["bin/tool"] {
		t.Errorf("main and bin lost: mains=%v bins=%v", manifest.mains, manifest.bins)
	}
}

func TestNodePackageEntryRole_Scripts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeNodeFixtureFile(t, filepath.Join(dir, "package.json"), `{"main":"index.js","bin":"bin/cli.js","scripts":{"seed":"tsx scripts/seed.ts"}}`)
	cases := map[string]nodeEntryRole{
		"index.js":         nodeLibraryEntry,
		"bin/cli.js":       nodeProgramEntry,
		"scripts/seed.ts":  nodeProgramEntry,
		"scripts/other.ts": nodeNotAnEntry,
		"lib/plain.js":     nodeNotAnEntry,
	}
	for rel, want := range cases {
		if got := nodePackageEntryRole(filepath.Join(dir, filepath.FromSlash(rel))); got != want {
			t.Errorf("nodePackageEntryRole(%s) = %v, want %v", rel, got, want)
		}
	}
}

func TestNodeModulePath_SameStemSiblingsKeepSeparateIdentities(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, name := range []string{"a.ts", "a.mjs", "b.js", "c.js", "c.cjs"} {
		writeNodeFixtureFile(t, filepath.Join(dir, name), "x()\n")
	}
	cases := map[string]string{
		"a.ts":  "pkg/a",
		"a.mjs": "pkg/a.mjs",
		"b.js":  "pkg/b",
		"c.js":  "pkg/c",
		"c.cjs": "pkg/c.cjs",
	}
	for name, want := range cases {
		if got := nodeModulePath("pkg", filepath.Join(dir, name)); got != want {
			t.Errorf("nodeModulePath(%s) = %q, want %q", name, got, want)
		}
	}
}

func TestNodeParser_ShebangImportModuleKeepsTopLevelBesideSameStemFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeNodeFixtureFile(t, filepath.Join(dir, "run.mjs"), "#!/usr/bin/env node\nimport crypto from 'crypto'\ncrypto.createHash('md5')\n")
	writeNodeFixtureFile(t, filepath.Join(dir, "run.ts"), "import crypto from 'crypto'\ncrypto.createHash('sha1')\n")
	p := NewNodeParser()
	mjs, err := p.ParseFile(filepath.Join(dir, "run.mjs"), "pkg")
	if err != nil {
		t.Fatal(err)
	}
	ts, err := p.ParseFile(filepath.Join(dir, "run.ts"), "pkg")
	if err != nil {
		t.Fatal(err)
	}
	if mjs.Functions[0].ID == ts.Functions[0].ID {
		t.Fatalf("both files declare %v", mjs.Functions[0].ID)
	}
	var rooted []EntryRef
	for _, ref := range mjs.EntryRefs {
		if ref.Function.Name == moduleInitMethodName {
			rooted = append(rooted, ref)
		}
	}
	if len(rooted) != 1 || rooted[0].Function != mjs.Functions[0].ID || rooted[0].Kind != RootKindMain {
		t.Fatalf("shebang module entry refs = %v, want main for %v", mjs.EntryRefs, mjs.Functions[0].ID)
	}
	for _, ref := range ts.EntryRefs {
		if ref.Function.Name == moduleInitMethodName {
			t.Fatalf("plain run.ts rooted: %v", ref)
		}
	}
}

func TestNodePackageEntryRole_ExplicitExtensionRootsOnlyThatFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeNodeFixtureFile(t, filepath.Join(dir, "package.json"), `{"bin":"bin/tool.mjs","scripts":{"cli":"node scripts/cli.mjs","gone":"node dist/gone.js","bare":"node run.js"}}`)
	for _, rel := range []string{"scripts/cli.mjs", "scripts/cli.ts", "bin/tool.mjs", "bin/tool.ts", "src/gone.ts", "run.js", "src/run.ts", "run/index.ts"} {
		writeNodeFixtureFile(t, filepath.Join(dir, rel), "x()\n")
	}
	cases := map[string]nodeEntryRole{
		"scripts/cli.mjs": nodeProgramEntry,
		"scripts/cli.ts":  nodeNotAnEntry,
		"bin/tool.mjs":    nodeProgramEntry,
		"bin/tool.ts":     nodeNotAnEntry,
		"src/gone.ts":     nodeProgramEntry,
		"run.js":          nodeProgramEntry,
		"src/run.ts":      nodeNotAnEntry,
		"run/index.ts":    nodeNotAnEntry,
	}
	for rel, want := range cases {
		if got := nodePackageEntryRole(filepath.Join(dir, filepath.FromSlash(rel))); got != want {
			t.Errorf("nodePackageEntryRole(%s) = %v, want %v", rel, got, want)
		}
	}
}

func TestResolveNodeRelativeModule_WrittenExtensionOfAnExistingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, name := range []string{"main.mjs", "run.ts", "run.mjs", "a.ts"} {
		writeNodeFixtureFile(t, filepath.Join(dir, name), "x()\n")
	}
	importer := filepath.Join(dir, "main.mjs")
	for specifier, want := range map[string]string{
		"./run.mjs": "pkg/run.mjs",
		"./run.ts":  "pkg/run",
		"./a.js":    "pkg/a",
	} {
		if got, ok := resolveNodeRelativeModule(importer, "pkg", specifier); !ok || got != want {
			t.Errorf("resolveNodeRelativeModule(%q) = (%q, %v), want %q", specifier, got, ok, want)
		}
	}
}

func TestNodeBuilder_ExplicitExtensionImportReachesTheShadowedSibling(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeNodeFixtureFile(t, filepath.Join(root, "pkg", "main.mjs"), "import { go } from './run.mjs';\nexport function start() { return go(); }\n")
	writeNodeFixtureFile(t, filepath.Join(root, "pkg", "run.mjs"), "import { createHash } from 'crypto';\nexport function go() { return createHash('md5'); }\n")
	writeNodeFixtureFile(t, filepath.Join(root, "pkg", "run.ts"), "export function go() { return 1; }\n")
	graph, err := NewBuilderForEcosystem("node", NewNodeParser()).BuildFromDirectories([]PackageDir{{Dir: filepath.Join(root, "pkg")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for key, callers := range graph.Callers {
		if strings.HasSuffix(key, "run.mjs.go") && len(callers) == 1 && strings.HasSuffix(callers[0], "main.start") {
			found = true
		}
	}
	if !found {
		t.Fatalf("run.mjs go has no caller main.start: %v", graph.Callers)
	}
}

func writeNodeFixtureFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
