// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const npmAppManifest = `{"name":"app","dependencies":{"left":"^1.0.0","@noble/hashes":"^1.3.0"},"devDependencies":{"jest":"^29.0.0"}}`

// moduleVersions lists a closure's dependencies as module@version.
func moduleVersions(r *ResolveResult) []string {
	out := make([]string, 0, len(r.Dependencies))
	for _, d := range r.Dependencies {
		out = append(out, Ref{Module: d.Module, Version: d.Version}.Key())
	}
	return out
}

// TestNpmResolverFormats: each lock format gives the runtime closure of the
// same small project: left and @noble/hashes are declared, shared is left's
// (and dev jest's) and stays, jest and its own package are dev and go.
func TestNpmResolverFormats(t *testing.T) {
	t.Parallel()
	want := []string{"@noble/hashes@1.3.2", "left@1.0.0", "shared@1.0.0"}
	cases := map[string]map[string]string{
		"package-lock.json": {"package-lock.json": `{"name":"app","lockfileVersion":3,"packages":{
"":{"name":"app","dependencies":{"left":"^1.0.0","@noble/hashes":"^1.3.0"},"devDependencies":{"jest":"^29.0.0"}},
"node_modules/left":{"version":"1.0.0","dependencies":{"shared":"^1.0.0"}},
"node_modules/@noble/hashes":{"version":"1.3.2"},
"node_modules/shared":{"version":"1.0.0"},
"node_modules/jest":{"version":"29.0.0","dev":true,"dependencies":{"shared":"^1.0.0","jest-core":"^29.0.0"}},
"node_modules/jest-core":{"version":"29.0.0","dev":true}}}`},
		"npm-shrinkwrap.json": {"npm-shrinkwrap.json": `{"name":"app","lockfileVersion":2,"packages":{
"":{"name":"app","dependencies":{"left":"^1.0.0","@noble/hashes":"^1.3.0"},"devDependencies":{"jest":"^29.0.0"}},
"node_modules/left":{"version":"1.0.0","dependencies":{"shared":"^1.0.0"}},
"node_modules/@noble/hashes":{"version":"1.3.2"},
"node_modules/shared":{"version":"1.0.0"},
"node_modules/jest":{"version":"29.0.0","dev":true,"dependencies":{"shared":"^1.0.0"}}}}`},
		"yarn.lock": {"yarn.lock": `# yarn lockfile v1

"@noble/hashes@^1.3.0":
  version "1.3.2"

jest@^29.0.0:
  version "29.0.0"
  dependencies:
    shared "^1.0.0"

left@^1.0.0:
  version "1.0.0"
  dependencies:
    shared "^1.0.0"

shared@^1.0.0:
  version "1.0.0"
`},
		"pnpm-lock.yaml": {"pnpm-lock.yaml": `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      '@noble/hashes':
        specifier: ^1.3.0
        version: 1.3.2
      left:
        specifier: ^1.0.0
        version: 1.0.0
    devDependencies:
      jest:
        specifier: ^29.0.0
        version: 29.0.0

packages:

  '@noble/hashes@1.3.2':
    resolution: {integrity: sha512-aaa}

  jest@29.0.0:
    resolution: {integrity: sha512-bbb}

  left@1.0.0:
    resolution: {integrity: sha512-ccc}

  shared@1.0.0:
    resolution: {integrity: sha512-ddd}

snapshots:

  '@noble/hashes@1.3.2': {}

  jest@29.0.0:
    dependencies:
      shared: 1.0.0

  left@1.0.0:
    dependencies:
      shared: 1.0.0

  shared@1.0.0: {}
`},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			target := writeTree(t, files)
			if err := os.WriteFile(filepath.Join(target, "package.json"), []byte(npmAppManifest), 0o600); err != nil {
				t.Fatal(err)
			}
			r := NewNpmResolver()
			if !r.CanResolve(target) || r.Ecosystem() != "node" {
				t.Fatal("CanResolve: want the lock file")
			}
			got, err := r.Resolve(t.Context(), target)
			if err != nil {
				t.Fatal(err)
			}
			if mv := moduleVersions(got); !reflect.DeepEqual(mv, want) {
				t.Errorf("dependencies = %v, want %v (dev packages excluded)", mv, want)
			}
			if !reflect.DeepEqual(got.DirectDependencies, []string{"@noble/hashes", "left"}) {
				t.Errorf("direct = %v", got.DirectDependencies)
			}
			if kids := got.VersionedGraph["left@1.0.0"]; !reflect.DeepEqual(kids, []Ref{{Module: "shared", Version: "1.0.0"}}) {
				t.Errorf("left's children = %v", kids)
			}
			if got.Source != name || got.RootModule != "app" {
				t.Errorf("source %q, root module %q", got.Source, got.RootModule)
			}
		})
	}
}

// TestNpmResolverWorkspace: a workspace member is the project's own package,
// not a dependency; what it declares joins the closure.
func TestNpmResolverWorkspace(t *testing.T) {
	t.Parallel()
	target := writeTree(t, map[string]string{
		"package.json":               `{"name":"mono","workspaces":["packages/*"],"dependencies":{"left":"^1.0.0"}}`,
		"packages/core/package.json": `{"name":"@mono/core","version":"0.1.0","dependencies":{"@noble/hashes":"^1.3.0"},"devDependencies":{"jest":"^29.0.0"}}`,
		"packages/web/package.json":  `{"name":"@mono/web","version":"0.1.0","dependencies":{"@mono/core":"*"}}`,
		"package-lock.json": `{"name":"mono","lockfileVersion":3,"packages":{
"":{"name":"mono","workspaces":["packages/*"],"dependencies":{"left":"^1.0.0"}},
"node_modules/@mono/core":{"resolved":"packages/core","link":true},
"node_modules/@mono/web":{"resolved":"packages/web","link":true},
"node_modules/left":{"version":"1.0.0"},
"node_modules/@noble/hashes":{"version":"1.3.2"},
"node_modules/jest":{"version":"29.0.0","dev":true},
"packages/core":{"name":"@mono/core","version":"0.1.0","dependencies":{"@noble/hashes":"^1.3.0"},"devDependencies":{"jest":"^29.0.0"}},
"packages/web":{"name":"@mono/web","version":"0.1.0","dependencies":{"@mono/core":"*"}}}}`,
	})
	got, err := NewNpmResolver().Resolve(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"@noble/hashes@1.3.2", "left@1.0.0"}
	if mv := moduleVersions(got); !reflect.DeepEqual(mv, want) {
		t.Errorf("dependencies = %v, want %v", mv, want)
	}
}

// TestNpmResolverUnsupportedLockfile: a lock the shared parser cannot read
// (an npm 6 package-lock.json, lockfileVersion 1) fails the resolution and
// names why, rather than yielding an empty closure.
func TestNpmResolverUnsupportedLockfile(t *testing.T) {
	t.Parallel()
	target := writeTree(t, map[string]string{
		"package-lock.json": `{"lockfileVersion":1,"dependencies":{"left":{"version":"1.0.0"}}}`,
	})
	_, err := NewNpmResolver().Resolve(t.Context(), target)
	if err == nil || !strings.Contains(err.Error(), "unsupported_version") {
		t.Fatalf("err = %v, want unsupported_version", err)
	}
}

// TestNpmResolverNoLock: a project with only a package.json has no closure.
func TestNpmResolverNoLock(t *testing.T) {
	t.Parallel()
	target := writeTree(t, map[string]string{"package.json": npmAppManifest})
	r := NewNpmResolver()
	if r.CanResolve(target) {
		t.Error("CanResolve: package.json alone has no pins")
	}
	if _, err := r.Resolve(t.Context(), target); err == nil {
		t.Error("Resolve without a lock: want an error")
	}
}

// TestNpmResolverInstalledDirs: a dependency installed under node_modules
// carries its directory: hoisted, scoped, nested under another package, or a
// pnpm symbolic link into the virtual store; one at another version, or not
// installed, has none.
func TestNpmResolverInstalledDirs(t *testing.T) {
	t.Parallel()
	pkg := func(name, version string) string { return `{"name":"` + name + `","version":"` + version + `"}` }
	target := writeTree(t, map[string]string{
		"package-lock.json": `{"lockfileVersion":3,"packages":{
"":{"name":"app","dependencies":{"left":"^1.0.0","@noble/hashes":"^1.3.0","nested":"^2.0.0","linked":"^1.0.0","absent":"^1.0.0","stale":"^1.0.0"}},
"node_modules/left":{"version":"1.0.0"},
"node_modules/@noble/hashes":{"version":"1.3.2"},
"node_modules/nested":{"version":"2.0.0"},
"node_modules/linked":{"version":"1.0.0"},
"node_modules/absent":{"version":"1.0.0"},
"node_modules/stale":{"version":"1.0.0"}}}`,
		"node_modules/left/package.json":                                   pkg("left", "1.0.0"),
		"node_modules/@noble/hashes/package.json":                          pkg("@noble/hashes", "1.3.2"),
		"node_modules/other/node_modules/nested/package.json":              pkg("nested", "2.0.0"),
		"node_modules/other/package.json":                                  pkg("other", "3.0.0"),
		"node_modules/.pnpm/linked@1.0.0/node_modules/linked/package.json": pkg("linked", "1.0.0"),
		"node_modules/stale/package.json":                                  pkg("stale", "0.9.0"),
	})
	if err := os.Symlink(filepath.Join(".pnpm", "linked@1.0.0", "node_modules", "linked"), filepath.Join(target, "node_modules", "linked")); err != nil {
		t.Skip("symbolic links unavailable:", err)
	}
	got, err := NewNpmResolver().Resolve(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	dirs := map[string]string{}
	for _, d := range got.Dependencies {
		dirs[d.Module] = d.Dir
	}
	want := map[string]string{
		"left":          filepath.Join(resolvedTarget, "node_modules", "left"),
		"@noble/hashes": filepath.Join(resolvedTarget, "node_modules", "@noble", "hashes"),
		"nested":        filepath.Join(resolvedTarget, "node_modules", "other", "node_modules", "nested"),
		"linked":        filepath.Join(resolvedTarget, "node_modules", ".pnpm", "linked@1.0.0", "node_modules", "linked"),
		"absent":        "",
		"stale":         "",
	}
	if !reflect.DeepEqual(dirs, want) {
		t.Errorf("dirs = %v, want %v", dirs, want)
	}
}

// TestNpmResolverOneVersionPerPackage: a package the lock holds at several
// versions keeps the one the project loads, and the others are listed.
func TestNpmResolverOneVersionPerPackage(t *testing.T) {
	t.Parallel()
	t.Run("hoisted wins over a higher nested copy", func(t *testing.T) {
		t.Parallel()
		target := writeTree(t, map[string]string{"package-lock.json": `{"lockfileVersion":3,"packages":{
"":{"name":"app","dependencies":{"elliptic":"^6.5.0","bn.js":"^4.0.0"}},
"node_modules/bn.js":{"version":"4.12.0"},
"node_modules/elliptic":{"version":"6.5.4","dependencies":{"bn.js":"^5.0.0"}},
"node_modules/elliptic/node_modules/bn.js":{"version":"5.2.1"}}}`})
		got, err := NewNpmResolver().Resolve(t.Context(), target)
		if err != nil {
			t.Fatal(err)
		}
		if mv := moduleVersions(got); !reflect.DeepEqual(mv, []string{"bn.js@4.12.0", "elliptic@6.5.4"}) {
			t.Errorf("dependencies = %v, want the hoisted bn.js 4.12.0", mv)
		}
		if len(got.OtherVersions) != 1 || got.OtherVersions[0].Module != "bn.js" || got.OtherVersions[0].Version != "5.2.1" {
			t.Errorf("other versions = %+v, want bn.js 5.2.1", got.OtherVersions)
		}
		if kids := got.VersionedGraph["elliptic@6.5.4"]; !reflect.DeepEqual(kids, []Ref{{Module: "bn.js", Version: "4.12.0"}}) {
			t.Errorf("elliptic's children = %v, want the edge to the kept version", kids)
		}
	})
	t.Run("semver, not text, when nothing is hoisted or direct", func(t *testing.T) {
		t.Parallel()
		target := writeTree(t, map[string]string{"package-lock.json": `{"lockfileVersion":3,"packages":{
"":{"name":"app","dependencies":{"a":"^1.0.0","b":"^1.0.0"}},
"node_modules/a":{"version":"1.0.0","dependencies":{"semi":"^9.0.0"}},
"node_modules/a/node_modules/semi":{"version":"9.0.0"},
"node_modules/b":{"version":"1.0.0","dependencies":{"semi":"^10.0.0"}},
"node_modules/b/node_modules/semi":{"version":"10.0.0"}}}`})
		got, err := NewNpmResolver().Resolve(t.Context(), target)
		if err != nil {
			t.Fatal(err)
		}
		if mv := moduleVersions(got); !reflect.DeepEqual(mv, []string{"a@1.0.0", "b@1.0.0", "semi@10.0.0"}) {
			t.Errorf("dependencies = %v, want semi 10.0.0", mv)
		}
		if len(got.OtherVersions) != 1 || got.OtherVersions[0].Version != "9.0.0" {
			t.Errorf("other versions = %+v", got.OtherVersions)
		}
	})
	t.Run("yarn: the most depended on version", func(t *testing.T) {
		t.Parallel()
		target := writeTree(t, map[string]string{
			"package.json": `{"name":"app","dependencies":{"a":"^1.0.0","b":"^1.0.0","c":"^1.0.0"}}`,
			"yarn.lock": `# yarn lockfile v1

a@^1.0.0:
  version "1.0.0"
  dependencies:
    shared "^1.0.0"

b@^1.0.0:
  version "1.0.0"
  dependencies:
    shared "^1.0.0"

c@^1.0.0:
  version "1.0.0"
  dependencies:
    shared "^2.0.0"

shared@^1.0.0:
  version "1.5.0"

shared@^2.0.0:
  version "2.0.0"
`,
		})
		got, err := NewNpmResolver().Resolve(t.Context(), target)
		if err != nil {
			t.Fatal(err)
		}
		if mv := moduleVersions(got); !reflect.DeepEqual(mv, []string{"a@1.0.0", "b@1.0.0", "c@1.0.0", "shared@1.5.0"}) {
			t.Errorf("dependencies = %v, want shared 1.5.0 (two dependents)", mv)
		}
		if len(got.OtherVersions) != 1 || got.OtherVersions[0].Version != "2.0.0" {
			t.Errorf("other versions = %+v", got.OtherVersions)
		}
	})
	t.Run("a package only a dropped version requires is listed, not requested", func(t *testing.T) {
		t.Parallel()
		// bar -> foo 1.0.0 (nested, dropped for the hoisted foo 2.0.0) -> x;
		// nothing else requires x, and x requires y.
		target := writeTree(t, map[string]string{"package-lock.json": `{"lockfileVersion":3,"packages":{
"":{"name":"app","dependencies":{"bar":"^1.0.0","foo":"^2.0.0"}},
"node_modules/foo":{"version":"2.0.0"},
"node_modules/bar":{"version":"1.0.0","dependencies":{"foo":"^1.0.0"}},
"node_modules/bar/node_modules/foo":{"version":"1.0.0","dependencies":{"x":"^1.0.0"}},
"node_modules/x":{"version":"1.0.0","dependencies":{"y":"^1.0.0"}},
"node_modules/y":{"version":"1.0.0"}}}`})
		got, err := NewNpmResolver().Resolve(t.Context(), target)
		if err != nil {
			t.Fatal(err)
		}
		if mv := moduleVersions(got); !reflect.DeepEqual(mv, []string{"bar@1.0.0", "foo@2.0.0"}) {
			t.Errorf("dependencies = %v, want bar and the hoisted foo only", mv)
		}
		want := []Dependency{{Module: "x", Version: "1.0.0"}, {Module: "y", Version: "1.0.0"}}
		if !reflect.DeepEqual(got.UnderOtherVersions, want) {
			t.Errorf("under other versions = %+v, want %+v", got.UnderOtherVersions, want)
		}
	})
}

// Two locks of one monorepo that pin a package at different versions request
// one of them, the highest, and list the other, as one lock does.
func TestKeepOneNpmVersionAcrossRoots(t *testing.T) {
	a := &ResolveResult{
		Dependencies:   []Dependency{{Module: "x", Version: "10.0.0"}, {Module: "app-a", Version: "1.0.0"}},
		VersionedGraph: map[string][]Ref{"app-a@1.0.0": {{Module: "x", Version: "10.0.0"}}},
	}
	b := &ResolveResult{
		Dependencies:   []Dependency{{Module: "x", Version: "9.0.0"}, {Module: "app-b", Version: "1.0.0"}},
		VersionedGraph: map[string][]Ref{"app-b@1.0.0": {{Module: "x", Version: "9.0.0"}}, "x@9.0.0": {{Module: "y", Version: "1.0.0"}}},
	}
	merged := MergeRootResolutions([]RootResolution{
		{Root: discoveredRoot{Dir: "/r/services/a", Rel: "services/a", Depth: 2}, Result: a},
		{Root: discoveredRoot{Dir: "/r/services/b", Rel: "services/b", Depth: 2}, Result: b},
	})
	KeepOneNpmVersionAcrossRoots(merged)
	var xs []string
	for _, dep := range merged.Dependencies {
		if dep.Module == "x" {
			xs = append(xs, dep.Version)
		}
	}
	if !slices.Equal(xs, []string{"10.0.0"}) {
		t.Errorf("x requested at %v, want [10.0.0]", xs)
	}
	if want := []Dependency{{Module: "x", Version: "9.0.0"}}; !reflect.DeepEqual(merged.OtherVersions, want) {
		t.Errorf("other versions %v, want %v", merged.OtherVersions, want)
	}
	if got, want := merged.VersionedGraph["app-b@1.0.0"], []Ref{{Module: "x", Version: "10.0.0"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("app-b edges %v, want %v", got, want)
	}
	if _, ok := merged.VersionedGraph["x@9.0.0"]; ok {
		t.Error("the dropped version keeps its edges")
	}
}

// The versions each root's lock lists as other are listed once across roots,
// and never one the merged request names.
func TestKeepOneNpmVersionAcrossRootsOtherVersions(t *testing.T) {
	root := func(rel string, r *ResolveResult) RootResolution {
		return RootResolution{Root: discoveredRoot{Dir: "/r/" + rel, Rel: rel, Depth: 2}, Result: r}
	}
	// Both services hoist bn.js 5.2.1 and nest 4.12.0: 4.12.0 is listed once.
	shared := MergeRootResolutions([]RootResolution{
		root("services/a", &ResolveResult{Dependencies: []Dependency{{Module: "bn.js", Version: "5.2.1"}}, OtherVersions: []Dependency{{Module: "bn.js", Version: "4.12.0"}}}),
		root("services/b", &ResolveResult{Dependencies: []Dependency{{Module: "bn.js", Version: "5.2.1"}}, OtherVersions: []Dependency{{Module: "bn.js", Version: "4.12.0"}}}),
	})
	KeepOneNpmVersionAcrossRoots(shared)
	if want := []Dependency{{Module: "bn.js", Version: "4.12.0"}}; !reflect.DeepEqual(shared.OtherVersions, want) {
		t.Errorf("shared nested version: other versions %v, want %v", shared.OtherVersions, want)
	}
	// Service a keeps 4.12.0 and lists 5.2.1; service b has 5.2.1 only. The
	// request names 5.2.1, so only 4.12.0 is listed as other.
	crossed := MergeRootResolutions([]RootResolution{
		root("services/a", &ResolveResult{Dependencies: []Dependency{{Module: "bn.js", Version: "4.12.0"}}, OtherVersions: []Dependency{{Module: "bn.js", Version: "5.2.1"}}}),
		root("services/b", &ResolveResult{Dependencies: []Dependency{{Module: "bn.js", Version: "5.2.1"}}}),
	})
	KeepOneNpmVersionAcrossRoots(crossed)
	if want := []Dependency{{Module: "bn.js", Version: "5.2.1"}}; !reflect.DeepEqual(crossed.Dependencies, want) {
		t.Errorf("crossed: requested %v, want %v", crossed.Dependencies, want)
	}
	if want := []Dependency{{Module: "bn.js", Version: "4.12.0"}}; !reflect.DeepEqual(crossed.OtherVersions, want) {
		t.Errorf("crossed: other versions %v, want %v", crossed.OtherVersions, want)
	}
}

// Two roots that lock the same version keep the copy one of them installed,
// whichever root comes first, so an offline scan mines it.
func TestKeepOneNpmVersionAcrossRootsKeepsTheInstalledCopy(t *testing.T) {
	merged := MergeRootResolutions([]RootResolution{
		{Root: discoveredRoot{Dir: "/r/services/a", Rel: "services/a", Depth: 2}, Result: &ResolveResult{Dependencies: []Dependency{{Module: "bcryptjs", Version: "2.4.3"}}}},
		{Root: discoveredRoot{Dir: "/r/services/b", Rel: "services/b", Depth: 2}, Result: &ResolveResult{Dependencies: []Dependency{{Module: "bcryptjs", Version: "2.4.3", Dir: "/r/services/b/node_modules/bcryptjs"}}}},
	})
	KeepOneNpmVersionAcrossRoots(merged)
	if want := []Dependency{{Module: "bcryptjs", Version: "2.4.3", Dir: "/r/services/b/node_modules/bcryptjs"}}; !reflect.DeepEqual(merged.Dependencies, want) {
		t.Errorf("requested %v, want %v", merged.Dependencies, want)
	}
}

// Across roots, a version some root installed is requested over a higher one
// no root installed.
func TestKeepOneNpmVersionAcrossRootsPrefersAnInstalledVersion(t *testing.T) {
	merged := MergeRootResolutions([]RootResolution{
		{Root: discoveredRoot{Dir: "/r/services/a", Rel: "services/a", Depth: 2}, Result: &ResolveResult{Dependencies: []Dependency{{Module: "x", Version: "10.0.0"}}}},
		{Root: discoveredRoot{Dir: "/r/services/b", Rel: "services/b", Depth: 2}, Result: &ResolveResult{Dependencies: []Dependency{{Module: "x", Version: "9.0.0", Dir: "/r/services/b/node_modules/x"}}}},
	})
	KeepOneNpmVersionAcrossRoots(merged)
	if len(merged.Dependencies) != 1 || merged.Dependencies[0].Version != "9.0.0" {
		t.Errorf("requested %v, want x@9.0.0", merged.Dependencies)
	}
	if want := []Dependency{{Module: "x", Version: "10.0.0"}}; !reflect.DeepEqual(merged.OtherVersions, want) {
		t.Errorf("other versions %v, want %v", merged.OtherVersions, want)
	}
}

// Across roots, a package each root lists under a dropped version is listed
// once, and not at all when another root's lock requests it.
func TestKeepOneNpmVersionAcrossRootsUnderOtherVersions(t *testing.T) {
	root := func(rel string, r *ResolveResult) RootResolution {
		return RootResolution{Root: discoveredRoot{Dir: "/r/" + rel, Rel: rel, Depth: 2}, Result: r}
	}
	merged := MergeRootResolutions([]RootResolution{
		root("services/a", &ResolveResult{Dependencies: []Dependency{{Module: "foo", Version: "2.0.0"}}, UnderOtherVersions: []Dependency{{Module: "x", Version: "1.0.0"}, {Module: "z", Version: "1.0.0"}}}),
		root("services/b", &ResolveResult{Dependencies: []Dependency{{Module: "foo", Version: "2.0.0"}}, UnderOtherVersions: []Dependency{{Module: "x", Version: "1.0.0"}}}),
		root("services/c", &ResolveResult{Dependencies: []Dependency{{Module: "z", Version: "1.0.0"}}}),
	})
	KeepOneNpmVersionAcrossRoots(merged)
	if want := []Dependency{{Module: "x", Version: "1.0.0"}}; !reflect.DeepEqual(merged.UnderOtherVersions, want) {
		t.Errorf("under other versions = %+v, want %+v", merged.UnderOtherVersions, want)
	}
}
