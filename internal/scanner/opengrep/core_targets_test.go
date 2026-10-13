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

package opengrep

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The expectations below were taken from `opengrep scan -d` (opengrep
// 1.30.2), which prints the targets file the CLI hands opengrep-core.

func TestExcludeMatcherFollowsWcmatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"test/", "/tmp/og2/t/a/test/x.go", true},
		{"docs", "/tmp/og2/t/b/docs/x/z.go", true},
		{"docs", "/tmp/og2/t/b/docsx/z.go", false},
		// An ancestor of an absolute target matches too.
		{"og2", "/tmp/og2/t/c/w.go", true},
		{"**/zz_generated*.go", "t/c/zz_generated_x.go", true},
		{"**/zz_generated*.go", "t/c/w.go", false},
		{".hid", "t/.hid/h.go", true},
		{"*.min.js", "t/c/x.min.js", true},
		{"src/test/", "repo/src/test/A.java", true},
		{"src/test/", "repo/src/testing/A.java", false},
		{"**/*Test.java", "repo/src/main/FooTest.java", true},
		// Absolute anchored patterns with a trailing slash match below them.
		{"/abs/dep/node_modules/", "/abs/dep/node_modules/x/index.js", true},
		{"/abs/dep/node_modules/", "/abs/dep/index.js", false},
		{"[ab]*.go", "t/a.go", true},
		{"[!ab]*.go", "t/a.go", false},
		{"?.go", "t/ab.go", false},
		{".git", "t/.git/config", true},
	}
	for _, c := range cases {
		if got := newExcludeMatcher([]string{c.pattern}).matches(c.path); got != c.want {
			t.Errorf("exclude %q on %q = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestPyPath(t *testing.T) {
	cases := map[string]string{
		"":            ".",
		".":           ".",
		"./a/b/":      "a/b",
		"a//b/./c":    "a/b/c",
		"/tmp//x/":    "/tmp/x",
		"../rules":    "../rules",
		"/":           "/",
		"a/../b":      "a/../b",
		"./../x/./y/": "../x/y",
	}
	for in, want := range cases {
		if got := pyPath(in); got != want {
			t.Errorf("pyPath(%q) = %q, want %q", in, got, want)
		}
	}
	if got := pyJoin(".", "x/y.go"); got != "x/y.go" {
		t.Errorf("pyJoin(., x/y.go) = %q", got)
	}
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func langs(t *testing.T, keys ...string) []*language {
	t.Helper()
	out := make([]*language, 0, len(keys))
	for _, key := range keys {
		lang := languageByKey[key]
		if lang == nil {
			t.Fatalf("unknown language %s", key)
		}
		out = append(out, lang)
	}
	return out
}

func targetPairs(plan *targetPlan, root string) []string {
	pairs := make([]string, 0, len(plan.targets))
	for _, target := range plan.targets {
		rel, _ := filepath.Rel(root, target.path)
		pairs = append(pairs, filepath.ToSlash(rel)+":"+target.analyzer)
	}
	sort.Strings(pairs)
	return pairs
}

func TestEnumerateTargetsMatchesCLISelection(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"top.go":                 "package x",
		"a/test/x.go":            "package x",
		"b/docs/x/z.go":          "package x",
		".hid/h.go":              "package x",
		"c/w.go":                 "package x",
		"c/zz_generated_x.go":    "package x",
		"c/x.min.js":             "x",
		"c/a.js":                 "x",
		"c/b.d.ts":               "x",
		"c/c.ts":                 "x",
		"c/h.h":                  "x",
		"c/script2":              "#!/usr/bin/env python\nimport os\n",
		"c/big.go":               strings.Repeat("a", defaultMaxTargetBytes+1),
		"c/exact.go":             strings.Repeat("a", defaultMaxTargetBytes),
		".git/hooks/pre-push.go": "package x",
	})
	script := filepath.Join(root, "c", "script")
	if err := os.WriteFile(script, []byte("#!/usr/bin/env python\nimport os\n"), 0o700); err != nil { // An executable fixture.
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "c", "w.go"), filepath.Join(root, "c", "link.go")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	all := langs(t, "go", "python", "javascript", "typescript", "c", "cpp")

	plan, err := enumerateTargets(ctx, targetOptions{targets: []string{root}, includeGitIgnored: true, maxTargetBytes: defaultMaxTargetBytes}, all)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		".hid/h.go:go", "a/test/x.go:go", "b/docs/x/z.go:go", "c/a.js:js", "c/b.d.ts:ts", "c/c.ts:ts",
		"c/exact.go:go", "c/h.h:c", "c/h.h:cpp", "c/script:python", "c/w.go:go", "c/x.min.js:js",
		"c/zz_generated_x.go:go", "top.go:go",
	}
	if got := targetPairs(plan, root); !reflect.DeepEqual(got, want) {
		t.Errorf("targets =\n%v\nwant\n%v", got, want)
	}

	plan, err = enumerateTargets(ctx, targetOptions{targets: []string{root}, skipPatterns: []string{"test/", "docs", "**/zz_generated*.go", ".hid"}, includeGitIgnored: true, maxTargetBytes: defaultMaxTargetBytes}, langs(t, "go"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := targetPairs(plan, root), []string{"c/exact.go:go", "c/w.go:go", "top.go:go"}; !reflect.DeepEqual(got, want) {
		t.Errorf("excluded targets = %v, want %v", got, want)
	}
}

func TestEnumerateTargetsExplicitFiles(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"c/w.go": "package x", "top.go": "package x", "c/notes.txt": "x"})
	files := []string{filepath.Join(root, "c", "w.go"), filepath.Join(root, "top.go"), filepath.Join(root, "c", "notes.txt")}
	ctx := context.Background()

	// Without --force-exclude a named file bypasses --exclude.
	plan, err := enumerateTargets(ctx, targetOptions{targets: files, skipPatterns: []string{"c"}, maxTargetBytes: defaultMaxTargetBytes}, langs(t, "go"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := targetPairs(plan, root), []string{"c/w.go:go", "top.go:go"}; !reflect.DeepEqual(got, want) {
		t.Errorf("named files = %v, want %v", got, want)
	}
	// With --force-exclude (detection scopes) the exclude applies.
	plan, err = enumerateTargets(ctx, targetOptions{targets: files, skipPatterns: []string{"c"}, forceExclude: true, maxTargetBytes: defaultMaxTargetBytes}, langs(t, "go"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := targetPairs(plan, root), []string{"top.go:go"}; !reflect.DeepEqual(got, want) {
		t.Errorf("force-excluded named files = %v, want %v", got, want)
	}
	// A missing named file makes the CLI fail, so core mode defers to it.
	_, err = enumerateTargets(ctx, targetOptions{targets: []string{filepath.Join(root, "gone.go")}}, langs(t, "go"))
	if !errors.Is(err, errTargetsUnsupported) {
		t.Errorf("missing target error = %v, want errTargetsUnsupported", err)
	}
}

func TestEnumerateTargetsRespectsGitIgnore(t *testing.T) {
	if _, err := os.Stat("/usr/bin/git"); err != nil {
		if _, err := os.Stat("/bin/git"); err != nil {
			t.Skip("git unavailable")
		}
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{".gitignore": "ignored/\n", "kept.go": "package x", "ignored/skip.go": "package x", "untracked.go": "package x"})
	ctx := context.Background()
	gitInit := func(args ...string) {
		t.Helper()
		cmd := execCommand(ctx, root, "git", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	gitInit("init", "-q")
	gitInit("add", "kept.go", ".gitignore")
	plan, err := enumerateTargets(ctx, targetOptions{targets: []string{root}, maxTargetBytes: defaultMaxTargetBytes, env: os.Environ()}, langs(t, "go"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := targetPairs(plan, root), []string{"kept.go:go", "untracked.go:go"}; !reflect.DeepEqual(got, want) {
		t.Errorf("git-aware targets = %v, want %v", got, want)
	}
	plan, err = enumerateTargets(ctx, targetOptions{targets: []string{root}, includeGitIgnored: true, maxTargetBytes: defaultMaxTargetBytes}, langs(t, "go"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := targetPairs(plan, root), []string{"ignored/skip.go:go", "kept.go:go", "untracked.go:go"}; !reflect.DeepEqual(got, want) {
		t.Errorf("--no-git-ignore targets = %v, want %v", got, want)
	}
}

func TestTargetsDocumentShape(t *testing.T) {
	data, err := targetsDocument([]coreTarget{{path: "one/a.go", analyzer: "go"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `[["CodeTarget",{"path":"one/a.go","analyzer":"go","products":["sast"]}]]`; string(data) != want {
		t.Errorf("targets document = %s, want %s", data, want)
	}
}
