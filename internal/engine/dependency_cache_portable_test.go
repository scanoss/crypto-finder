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

package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
	"github.com/scanoss/crypto-finder/internal/scanner/opengrep"
)

// rootRelativeScanner is a fingerprinted mockScanner that scans roots
// through relative paths.
type rootRelativeScanner struct {
	*fingerprintedScanner
	relative bool
}

func (s *rootRelativeScanner) ScansRootRelative() bool { return s.relative }

// portableFixture is a dependency scan whose scanner reports, like the
// opengrep adapter, paths relative to the scanned root, and records the
// roots it scanned.
type portableFixture struct {
	t        *testing.T
	rule     string
	cache    FindingsCache
	scanned  []string
	relative bool
	// absolute makes the scanner report absolute paths.
	absolute bool
}

func newPortableFixture(t *testing.T) *portableFixture {
	t.Helper()
	dir := t.TempDir()
	rule := filepath.Join(dir, "rules", "rule.yaml")
	if err := os.MkdirAll(filepath.Dir(rule), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rule, []byte("rules:\n- id: fixture\n  languages: [java]\n  pattern: $X\n  message: fixture\n  severity: WARNING\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cache, err := NewDiskFindingsCacheWithDir(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	return &portableFixture{t: t, rule: rule, cache: cache, relative: true}
}

// run scans deps for the project at target and returns the report's JSON.
func (f *portableFixture) run(target string, cache FindingsCache, deps ...dependency.Dependency) string {
	f.t.Helper()
	registry := scanner.NewRegistry()
	registry.RegisterFactory("fixture", func() scanner.Scanner {
		return &rootRelativeScanner{relative: f.relative, fingerprintedScanner: &fingerprintedScanner{
			fingerprint: func() (string, error) { return "build-1", nil },
			mockScanner: &mockScanner{
				getInfoFunc: func() scanner.Info { return scanner.Info{Name: opengrep.ScannerName, Version: "1"} },
				scanFunc: func(_ context.Context, root string, _ []string, info entities.ToolInfo) (*entities.InterimReport, error) {
					f.scanned = append(f.scanned, root)
					path := filepath.Join("org", "example", "Kdf.java")
					if f.absolute {
						path = filepath.Join(root, path)
					}
					return &entities.InterimReport{Version: "1.0", Tool: info, Findings: []entities.Finding{{
						FilePath:            path,
						Language:            "java",
						CryptographicAssets: []entities.CryptographicAsset{{StartLine: 124, Metadata: map[string]string{"assetType": "algorithm", "algorithmFamily": "PBKDF2"}}},
					}}}, nil
				},
			},
		}}
	})
	orchestrator := NewOrchestrator(&mockDetector{}, rules.NewManager(&mockRuleSource{loadFunc: func() ([]string, error) { return []string{f.rule}, nil }}), registry)
	resolver := &fakeResolver{ecosystem: "maven", resolveFn: func(context.Context, string) (*dependency.ResolveResult, error) {
		return &dependency.ResolveResult{RootModule: "app", Dependencies: deps}, nil
	}}
	consumer := NewDependencyScanner(orchestrator, resolver, callgraph.NewBuilder(noopCallgraphParser{}), cache)
	result, err := consumer.ScanWithDependencies(f.t.Context(), &entities.InterimReport{}, DepScanOptions{Workers: 1, ScanOptions: ScanOptions{Target: target, ScannerName: "fixture"}})
	if err != nil {
		f.t.Fatal(err)
	}
	data, err := json.Marshal(result.Report)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(data)
}

// home makes a home directory at path and a project in it, points HOME
// there and returns the project and a dependency extracted into the home's
// source cache.
func portableHome(t *testing.T, path string) (project string, dep dependency.Dependency) {
	t.Helper()
	t.Setenv("HOME", path)
	sources, err := dependency.SourceCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sources, path) {
		t.Fatalf("source cache %s is not under HOME %s", sources, path)
	}
	dir := filepath.Join(sources, "org.example-lib", "1.0")
	project = filepath.Join(path, "work", "app")
	for _, d := range []string{filepath.Join(dir, "org", "example"), project} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	return project, dependency.Dependency{Module: "org.example:lib", Version: "1.0", Dir: dir}
}

// A dependency extracted into another home's source cache, at another name
// and depth, and scanned from another working directory, is served the
// first home's entry: the same key, no rescan, and a report byte-identical
// to the first home's and to a cache-disabled scan in the second home.
func TestDependencyCacheEntryPortableAcrossHomes(t *testing.T) {
	f := newPortableFixture(t)
	base := t.TempDir()
	projectA, depA := portableHome(t, filepath.Join(base, "homeA"))
	t.Chdir(projectA)
	cold := f.run(projectA, f.cache, depA)
	if len(f.scanned) != 1 || f.scanned[0] != depA.Dir {
		t.Fatalf("cold run scanned %v, want %s", f.scanned, depA.Dir)
	}

	projectB, depB := portableHome(t, filepath.Join(base, "x", "y", "other-home-B"))
	t.Chdir(projectB)
	if warm := f.run(projectB, f.cache, depB); warm != cold || len(f.scanned) != 1 {
		t.Fatalf("another home must reuse the entry byte-identically: rescans=%d identical=%v\ncold=%s\nwarm=%s", len(f.scanned)-1, warm == cold, cold, warm)
	}
	if uncached := f.run(projectB, nil, depB); uncached != cold {
		t.Fatalf("the cached report must equal a cache-disabled scan in the other home:\ncached=%s\nfresh=%s", cold, uncached)
	}
	if strings.Contains(cold, base) {
		t.Fatalf("the report must not name the home: %s", cold)
	}
}

// Where the root-relative scan does not apply, or the dependency is a local
// directory rather than a published version, where it lies stays keyed.
func TestDependencyCacheKeepsRootWhereItMatters(t *testing.T) {
	base := t.TempDir()
	t.Run("not root-relative", func(t *testing.T) {
		f := newPortableFixture(t)
		f.relative = false
		projectA, depA := portableHome(t, filepath.Join(base, "n", "homeA"))
		f.run(projectA, f.cache, depA)
		projectB, depB := portableHome(t, filepath.Join(base, "n", "homeB"))
		f.run(projectB, f.cache, depB)
		if len(f.scanned) != 2 {
			t.Fatalf("a scan through absolute paths must not share entries across roots: scans=%v", f.scanned)
		}
	})
	t.Run("local directory", func(t *testing.T) {
		f := newPortableFixture(t)
		project, _ := portableHome(t, filepath.Join(base, "l", "home"))
		for _, name := range []string{"lib-a", "lib-b"} {
			dir := filepath.Join(base, "l", name)
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			f.run(project, f.cache, dependency.Dependency{Module: "org.example:lib", Version: "1.0", Dir: dir})
		}
		if len(f.scanned) != 2 {
			t.Fatalf("two local directories standing for one version must not share an entry: scans=%v", f.scanned)
		}
	})
	t.Run("unportable report", func(t *testing.T) {
		f := newPortableFixture(t)
		f.absolute = true
		project, dep := portableHome(t, filepath.Join(base, "u", "home"))
		f.run(project, f.cache, dep)
		f.run(project, f.cache, dep)
		if len(f.scanned) != 2 {
			t.Fatalf("a report naming files by absolute path must not be stored under a portable key: scans=%v", f.scanned)
		}
	})
}

// Two installs of one version in stores that do not verify their content
// never share an entry, while the same content installed elsewhere does.
func TestDependencyCacheKeysSourceContentOfUnverifiedStores(t *testing.T) {
	f := newPortableFixture(t)
	base := t.TempDir()
	projectA, depA := portableHome(t, filepath.Join(base, "homeA"))
	writeTree(t, depA.Dir, map[string]string{"org/example/Kdf.java": "class Kdf { PBKDF2 }"})
	t.Chdir(projectA)
	cold := f.run(projectA, f.cache, depA)

	projectB, depB := portableHome(t, filepath.Join(base, "homeB"))
	writeTree(t, depB.Dir, map[string]string{"org/example/Kdf.java": "class Kdf { PBKDF2; scrypt }"})
	t.Chdir(projectB)
	f.run(projectB, f.cache, depB)
	if len(f.scanned) != 2 || f.scanned[1] != depB.Dir {
		t.Fatalf("other content at the same version and place must be scanned, not served another install's findings: scans=%v", f.scanned)
	}

	projectC, depC := portableHome(t, filepath.Join(base, "x", "homeC"))
	writeTree(t, depC.Dir, map[string]string{"org/example/Kdf.java": "class Kdf { PBKDF2 }"})
	t.Chdir(projectC)
	if warm := f.run(projectC, f.cache, depC); len(f.scanned) != 2 || warm != cold {
		t.Fatalf("the first install's content elsewhere must reuse its entry: scans=%v identical=%v", f.scanned, warm == cold)
	}
}

// A store that verifies each version's content keys module@version alone:
// what it holds under that name is that content.
func TestDependencyCacheTrustsVerifiedStores(t *testing.T) {
	f := newPortableFixture(t)
	base := t.TempDir()
	project, _ := portableHome(t, filepath.Join(base, "home"))
	t.Chdir(project)
	for i, content := range []string{"package x // one", "package x // two"} {
		t.Setenv("GOMODCACHE", filepath.Join(base, "gomod", string(rune('a'+i))))
		dir := filepath.Join(os.Getenv("GOMODCACHE"), "example.com", "x@v1.0.0")
		writeTree(t, dir, map[string]string{"x.go": content})
		f.run(project, f.cache, dependency.Dependency{Module: "example.com/x", Version: "v1.0.0", Dir: dir})
	}
	if len(f.scanned) != 1 {
		t.Fatalf("a module cache entry is keyed by module@version, whatever its files hold: scans=%v", f.scanned)
	}
}

// A dependency whose content cannot be read is scanned every time rather
// than keyed on what could be read.
func TestDependencyCacheNotKeyedOnUnreadableSource(t *testing.T) {
	base := t.TempDir()
	t.Run("listed file missing", func(t *testing.T) {
		f := newPortableFixture(t)
		project, dep := portableHome(t, filepath.Join(base, "m", "home"))
		t.Chdir(project)
		dep.Files = []string{filepath.Join(dep.Dir, "org", "example", "Kdf.java")}
		f.run(project, f.cache, dep)
		f.run(project, f.cache, dep)
		if len(f.scanned) != 2 {
			t.Fatalf("an unreadable source must not be cached: scans=%v", f.scanned)
		}
	})
	t.Run("unreadable file", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads every file")
		}
		f := newPortableFixture(t)
		project, dep := portableHome(t, filepath.Join(base, "u", "home"))
		t.Chdir(project)
		writeTree(t, dep.Dir, map[string]string{"org/example/Kdf.java": "class Kdf {}"})
		if err := os.Chmod(filepath.Join(dep.Dir, "org", "example", "Kdf.java"), 0); err != nil {
			t.Fatal(err)
		}
		f.run(project, f.cache, dep)
		f.run(project, f.cache, dep)
		if len(f.scanned) != 2 {
			t.Fatalf("an unreadable source must not be cached: scans=%v", f.scanned)
		}
	})
}

func TestStorePlace(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HOME", filepath.Join(base, "home"))
	t.Setenv("GOMODCACHE", filepath.Join(base, "gomod"))
	t.Setenv("CARGO_HOME", filepath.Join(base, "cargo"))
	sources, err := dependency.SourceCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	registry := filepath.Join(base, "cargo", "registry", "src")
	cases := []struct{ dir, place, base string }{
		{filepath.Join(sources, "io.jsonwebtoken-jjwt-impl", "0.12.6"), "sources:io.jsonwebtoken-jjwt-impl/0.12.6", sources},
		{filepath.Join(base, "gomod", "golang.org", "x", "crypto@v0.17.0"), "gomodcache:golang.org/x/crypto@v0.17.0", filepath.Join(base, "gomod")},
		{filepath.Join(registry, "index.crates.io-1", "ring-0.17"), "cargo-registry:index.crates.io-1/ring-0.17", registry},
		{filepath.Join(base, "cargo", "git", "checkouts", "x-1", "abc"), "cargo-git:x-1/abc", filepath.Join(base, "cargo", "git", "checkouts")},
		{filepath.Join(base, "proj", "node_modules", "a", "node_modules", "b"), "node_modules/a/node_modules/b", filepath.Join(base, "proj")},
		{filepath.Join(base, "venv", "lib", "python3.12", "site-packages"), "site-packages", filepath.Join(base, "venv", "lib", "python3.12")},
		{filepath.Join(base, "local", "lib"), "", ""},
		{filepath.Join(base, "gomod"), "", ""},
		{"relative/node_modules/x", "", ""},
	}
	for _, c := range cases {
		place, ok := storePlace(c.dir)
		if place != c.place || ok != (c.place != "") {
			t.Errorf("storePlace(%s) = %q %v, want %q", c.dir, place, ok, c.place)
		}
		if got := storeBase(c.dir); got != c.base {
			t.Errorf("storeBase(%s) = %q, want %q", c.dir, got, c.base)
		}
	}
	// The scan of a dependency is named from its store, alone or batched.
	item := depWork{dep: dependency.Dependency{Dir: cases[0].dir}, base: storeBase(cases[0].dir)}
	if root := item.root(); root.Base != sources || root.Dir != cases[0].dir {
		t.Errorf("root = %+v, want %s named from the source cache %s", root, cases[0].dir, sources)
	}
}

func TestCacheCWDOnlyWhenRuleIDsDependOnIt(t *testing.T) {
	base := t.TempDir()
	ruleDir := filepath.Join(base, "rules")
	relative := &rootRelativeScanner{relative: true, fingerprintedScanner: &fingerprintedScanner{mockScanner: &mockScanner{}}}
	absolute := &rootRelativeScanner{relative: false, fingerprintedScanner: &fingerprintedScanner{mockScanner: &mockScanner{}}}
	cases := []struct {
		name string
		s    scanner.Scanner
		cwd  string
		want bool
	}{
		{"rules elsewhere", relative, filepath.Join(base, "project"), false},
		{"rules below cwd", relative, base, true},
		{"cwd in rules", relative, filepath.Join(ruleDir, "java"), true},
		{"cwd is rules", relative, ruleDir, true},
		{"not root-relative", absolute, filepath.Join(base, "project"), true},
	}
	for _, c := range cases {
		got := cacheCWD(c.s, c.cwd, []string{ruleDir})
		if (got == c.cwd) != c.want || (got != "" && got != c.cwd) {
			t.Errorf("%s: cacheCWD = %q, want keyed=%v", c.name, got, c.want)
		}
	}
}

func TestRootAnchoredPatterns(t *testing.T) {
	got := rootAnchoredPatterns([]string{"test/", "/deps/a/node_modules/", "/deps/ab/x", "**/*Test.java"}, "/deps/a")
	if want := []string{"test/", "$ROOT/node_modules/", "/deps/ab/x", "**/*Test.java"}; !reflect.DeepEqual(got, want) {
		t.Errorf("rootAnchoredPatterns = %v, want %v", got, want)
	}
}

func TestRootRelativeReport(t *testing.T) {
	report := func(paths ...string) *entities.InterimReport {
		r := &entities.InterimReport{}
		for _, p := range paths {
			r.Findings = append(r.Findings, entities.Finding{FilePath: p})
		}
		return r
	}
	for paths, want := range map[string]bool{
		"a/b.java":         true,
		"a/b.java|c.go":    true,
		"/abs/a.java":      false,
		"../out.java":      false,
		"a/b.java|..":      false,
		"":                 false,
		"a/../../x.java":   false,
		"lib/..x/file.js":  true,
		"lib/x..y/file.js": true,
	} {
		if got := rootRelativeReport(report(strings.Split(paths, "|")...)); got != want {
			t.Errorf("rootRelativeReport(%q) = %v, want %v", paths, got, want)
		}
	}
	if !rootRelativeReport(nil) {
		t.Error("a nil report holds no paths")
	}
}
