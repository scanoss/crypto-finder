// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

const (
	registrySource = "registry+https://github.com/rust-lang/crates.io-index"
	appID          = "path+file:///w/app#app@0.1.0"
	coreID         = "path+file:///w/core#my-core@0.1.0"
	pathLibID      = "path+file:///w/app/crates/pathlib#pathlib@0.1.0"
)

func cargoID(name, version string) string {
	return registrySource + "#" + name + "@" + version
}

func registryPkg(name, version, dir string) map[string]any {
	return map[string]any{
		"id": cargoID(name, version), "name": name, "version": version, "source": registrySource,
		"manifest_path": filepath.Join(dir, name+"-"+version, "Cargo.toml"),
		"targets":       []any{map[string]any{"name": underscore(name), "kind": []string{"lib"}}},
	}
}

func underscore(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c == '-' {
			out[i] = '_'
		}
	}
	return string(out)
}

func normalDep(id string) map[string]any {
	return map[string]any{"pkg": id, "dep_kinds": []any{map[string]any{"kind": nil, "target": nil}}}
}

func kindDep(id, kind string) map[string]any {
	return map[string]any{"pkg": id, "dep_kinds": []any{map[string]any{"kind": kind, "target": nil}}}
}

// metadataFixture is a workspace of app and my-core: app depends on aes-gcm
// (normal), my-core (a member) and tempfile (dev); aes-gcm on aes and
// cpufeatures (a build-only edge); aes only on subtle; tempfile (dev only)
// on fastrand; a git crate (with a registry child gitchild) is a normal
// dependency of my-core; a path crate outside the workspace (pathlib, with a
// registry child extra) is a normal dependency of app.
func metadataFixture(t *testing.T, cache string) *cargoMetadata {
	t.Helper()
	doc := map[string]any{
		"workspace_members": []string{appID, coreID},
		"packages": []any{
			map[string]any{
				"id": appID, "name": "app", "version": "0.1.0", "source": nil, "manifest_path": "/w/app/Cargo.toml",
				"targets": []any{map[string]any{"name": "app", "kind": []string{"bin"}}},
			},
			map[string]any{
				"id": coreID, "name": "my-core", "version": "0.1.0", "source": nil, "manifest_path": "/w/core/Cargo.toml",
				"targets": []any{map[string]any{"name": "my_core", "kind": []string{"lib"}}},
			},
			registryPkg("aes-gcm", "0.10.3", cache),
			registryPkg("aes", "0.8.4", cache),
			registryPkg("subtle", "2.6.1", cache),
			registryPkg("cpufeatures", "0.2.9", cache),
			registryPkg("tempfile", "3.10.0", cache),
			registryPkg("fastrand", "2.0.0", cache),
			registryPkg("extra", "1.0.0", cache),
			registryPkg("gitchild", "4.0.0", cache),
			map[string]any{
				"id": pathLibID, "name": "pathlib", "version": "0.1.0", "source": nil, "manifest_path": "/w/app/crates/pathlib/Cargo.toml",
				"targets": []any{map[string]any{"name": "pathlib", "kind": []string{"lib"}}},
			},
			map[string]any{
				"id": "git+https://example.test/x/gitcrate#0.3.0", "name": "gitcrate", "version": "0.3.0",
				"source": "git+https://example.test/x/gitcrate", "manifest_path": "/g/Cargo.toml", "targets": []any{},
			},
		},
		"resolve": map[string]any{"root": nil, "nodes": []any{
			map[string]any{"id": appID, "deps": []any{normalDep(cargoID("aes-gcm", "0.10.3")), normalDep(coreID), normalDep(pathLibID), kindDep(cargoID("tempfile", "3.10.0"), "dev")}},
			map[string]any{"id": pathLibID, "deps": []any{normalDep(cargoID("extra", "1.0.0"))}},
			map[string]any{"id": "git+https://example.test/x/gitcrate#0.3.0", "deps": []any{normalDep(cargoID("gitchild", "4.0.0"))}},
			map[string]any{"id": coreID, "deps": []any{normalDep("git+https://example.test/x/gitcrate#0.3.0")}},
			map[string]any{"id": cargoID("aes-gcm", "0.10.3"), "deps": []any{normalDep(cargoID("aes", "0.8.4")), kindDep(cargoID("cpufeatures", "0.2.9"), "build")}},
			map[string]any{"id": cargoID("aes", "0.8.4"), "deps": []any{normalDep(cargoID("subtle", "2.6.1"))}},
			map[string]any{"id": cargoID("tempfile", "3.10.0"), "deps": []any{normalDep(cargoID("fastrand", "2.0.0"))}},
		}},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var meta cargoMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	return &meta
}

// TestCargoClosureIsProduction: members are the application, dev and build
// edges (and what only they reach) are left out, a git crate is unpinned,
// and the graph carries the versioned normal edges.
func TestCargoClosureIsProduction(t *testing.T) {
	t.Parallel()
	cache := t.TempDir()
	result := (&CargoResolver{}).closure("/w", metadataFixture(t, cache))

	if got, want := moduleVersions(result), []string{"aes@0.8.4", "aes-gcm@0.10.3", "extra@1.0.0", "gitchild@4.0.0", "subtle@2.6.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("closure = %v, want %v", got, want)
	}
	wantMembers := []WorkspaceMember{
		{Name: "app", ImportPath: "", Dir: "/w/app"},
		{Name: "my-core", ImportPath: "my_core", Dir: "/w/core"},
		{Name: "pathlib", ImportPath: "", Dir: "/w/app/crates/pathlib"},
	}
	if !reflect.DeepEqual(result.WorkspaceMembers, wantMembers) {
		t.Errorf("members = %+v, want %+v", result.WorkspaceMembers, wantMembers)
	}
	if want := []string{"aes-gcm", "extra"}; !reflect.DeepEqual(result.DirectDependencies, want) {
		t.Errorf("direct = %v, want %v", result.DirectDependencies, want)
	}
	wantGraph := map[string][]Ref{
		"aes-gcm@0.10.3": {{Module: "aes", Version: "0.8.4"}},
		"aes@0.8.4":      {{Module: "subtle", Version: "2.6.1"}},
		"gitcrate@0.3.0": {{Module: "gitchild", Version: "4.0.0"}},
	}
	if !reflect.DeepEqual(result.VersionedGraph, wantGraph) {
		t.Errorf("versioned graph = %v, want %v", result.VersionedGraph, wantGraph)
	}
	if want := []string{"aes-gcm"}; !reflect.DeepEqual(result.Graph["app"], want) {
		t.Errorf("app children = %v, want %v", result.Graph["app"], want)
	}
	if want := []string{"gitcrate"}; !reflect.DeepEqual(result.Graph["my-core"], want) {
		t.Errorf("my-core children = %v, want %v", result.Graph["my-core"], want)
	}
	if want := []UnpinnedDependency{{Module: "gitcrate", Manifest: "Cargo.toml"}}; !reflect.DeepEqual(result.Unpinned, want) {
		t.Errorf("unpinned = %v, want %v", result.Unpinned, want)
	}
	if result.Source != "Cargo.lock" || result.RootModule != "app" {
		t.Errorf("source/root = %q/%q", result.Source, result.RootModule)
	}
	for _, dep := range result.Dependencies {
		if dep.ImportPath != "" && dep.ImportPath != underscore(dep.Module) {
			t.Errorf("%s import path = %q", dep.Module, dep.ImportPath)
		}
	}
}

// TestCargoClosureLocalPathCrate: a path crate outside the resolved
// directory is a local dependency analyzed from its own directory, as is a
// path crate it depends on; their registry dependencies are transitive. A
// path crate inside the directory stays the project's own code.
func TestCargoClosureLocalPathCrate(t *testing.T) {
	t.Parallel()
	result := (&CargoResolver{}).closure("/w/app", localPathMetadata(t))

	want := []Dependency{
		{Module: "demo-liba", ImportPath: "demo_liba", Version: "1.0.0", Dir: "/w/liba", Local: true},
		{Module: "libb", Version: "2.0.0", Dir: "/w/libb", Local: true},
		{Module: "sha2", Version: "0.10.8"},
	}
	if !reflect.DeepEqual(result.Dependencies, want) {
		t.Errorf("dependencies = %+v, want %+v", result.Dependencies, want)
	}
	if want := []WorkspaceMember{{Name: "app", Dir: "/w/app"}, {Name: "inner", Dir: "/w/app/crates/inner"}}; !reflect.DeepEqual(result.WorkspaceMembers, want) {
		t.Errorf("members = %+v, want %+v", result.WorkspaceMembers, want)
	}
	if want := []string{"demo-liba"}; !reflect.DeepEqual(result.DirectDependencies, want) {
		t.Errorf("direct = %v, want %v", result.DirectDependencies, want)
	}
	wantGraph := map[string][]Ref{"demo-liba@1.0.0": {{Module: "libb", Version: "2.0.0"}, {Module: "sha2", Version: "0.10.8"}}}
	if !reflect.DeepEqual(result.VersionedGraph, wantGraph) {
		t.Errorf("versioned graph = %v, want %v", result.VersionedGraph, wantGraph)
	}
	if len(result.Unpinned) != 0 {
		t.Errorf("unpinned = %v, want none", result.Unpinned)
	}
}

// TestCargoClosurePathCrateInsideTheScanRoot: a path crate outside the
// resolved directory but inside the scan root is a member, the project's own
// code, as a scan root without Cargo.toml resolves each crate root below it.
func TestCargoClosurePathCrateInsideTheScanRoot(t *testing.T) {
	t.Parallel()
	result := (&CargoResolver{scanRoot: "/w"}).closure("/w/app", localPathMetadata(t))

	if want := []Dependency{{Module: "sha2", Version: "0.10.8"}}; !reflect.DeepEqual(result.Dependencies, want) {
		t.Errorf("dependencies = %+v, want %+v", result.Dependencies, want)
	}
	members := make([]string, 0, len(result.WorkspaceMembers))
	for _, m := range result.WorkspaceMembers {
		members = append(members, m.Name)
	}
	if want := []string{"app", "demo-liba", "inner", "libb"}; !reflect.DeepEqual(sorted(members), want) {
		t.Errorf("members = %v, want %v", members, want)
	}
}

func sorted(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// localPathMetadata is an app at /w/app with a path crate inside it
// (crates/inner) and two outside it (/w/liba, which needs /w/libb and sha2).
func localPathMetadata(t *testing.T) *cargoMetadata {
	t.Helper()
	const (
		app   = "path+file:///w/app#app@0.1.0"
		inner = "path+file:///w/app/crates/inner#inner@0.1.0"
		liba  = "path+file:///w/liba#demo-liba@1.0.0"
		libb  = "path+file:///w/libb#libb@2.0.0"
	)
	pathPkg := func(id, name, version, dir string) map[string]any {
		return map[string]any{
			"id": id, "name": name, "version": version, "source": nil, "manifest_path": dir + "/Cargo.toml",
			"targets": []any{map[string]any{"name": underscore(name), "kind": []string{"lib"}}},
		}
	}
	cache := t.TempDir()
	raw, err := json.Marshal(map[string]any{
		"workspace_members": []string{app},
		"packages": []any{
			pathPkg(app, "app", "0.1.0", "/w/app"),
			pathPkg(inner, "inner", "0.1.0", "/w/app/crates/inner"),
			pathPkg(liba, "demo-liba", "1.0.0", "/w/liba"),
			pathPkg(libb, "libb", "2.0.0", "/w/libb"),
			registryPkg("sha2", "0.10.8", cache),
		},
		"resolve": map[string]any{"root": app, "nodes": []any{
			map[string]any{"id": app, "deps": []any{normalDep(liba), normalDep(inner)}},
			map[string]any{"id": liba, "deps": []any{normalDep(libb), normalDep(cargoID("sha2", "0.10.8"))}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var meta cargoMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	return &meta
}

// TestCargoLibraryName: the source namespace is the library target's name.
func TestCargoLibraryName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pkg  cargoPackage
		lib  string
		path string
	}{
		{cargoPackage{Name: "aes-gcm", Targets: []cargoTarget{{Name: "aes_gcm", Kind: []string{"lib"}}}}, "aes_gcm", "aes_gcm"},
		{cargoPackage{Name: "ring", Targets: []cargoTarget{{Name: "ring", Kind: []string{"lib"}}}}, "ring", ""},
		{cargoPackage{Name: "renamed", Targets: []cargoTarget{{Name: "other", Kind: []string{"proc-macro"}}}}, "other", "other"},
		{cargoPackage{Name: "tool", Targets: []cargoTarget{{Name: "tool", Kind: []string{"bin"}}}}, "", ""},
		{cargoPackage{Name: "no-targets"}, "no_targets", "no_targets"},
	}
	for _, c := range cases {
		if got := c.pkg.libraryName(); got != c.lib {
			t.Errorf("%s: library = %q, want %q", c.pkg.Name, got, c.lib)
		}
		if got := c.pkg.importPath(); got != c.path {
			t.Errorf("%s: import path = %q, want %q", c.pkg.Name, got, c.path)
		}
	}
}

// TestCargoSourceDir: the registry cache, a versioned vendor directory and a
// vendor directory of another version.
func TestCargoSourceDir(t *testing.T) {
	t.Parallel()
	home, project := t.TempDir(), t.TempDir()
	write := func(dir, version string) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		manifest := "[package]\nname = \"x\"\nversion = \"" + version + "\"\n"
		if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cached := filepath.Join(home, "registry", "src", "index.crates.io-abc", "aes-0.8.4")
	write(cached, "0.8.4")
	write(filepath.Join(project, "vendor", "subtle"), "2.5.0")
	write(filepath.Join(project, "vendor", "cpufeatures-0.2.9"), "0.2.9")
	r := &CargoResolver{cargoHome: home}
	pkg := func(name, version string) cargoPackage {
		return cargoPackage{Name: name, Version: version, ManifestPath: "/gone/" + name + "/Cargo.toml"}
	}
	if got := r.sourceDir(project, pkg("aes", "0.8.4")); got != cached {
		t.Errorf("registry cache = %q, want %q", got, cached)
	}
	if got := r.sourceDir(project, pkg("cpufeatures", "0.2.9")); got != filepath.Join(project, "vendor", "cpufeatures-0.2.9") {
		t.Errorf("versioned vendor dir = %q", got)
	}
	if got := r.sourceDir(project, pkg("subtle", "2.6.1")); got != "" {
		t.Errorf("a vendor dir of another version must not match, got %q", got)
	}
}

// TestCargoResolverReadsALockedProject runs the real cargo on a project of
// path dependencies (no network): the lock is read as it is, a dev-only crate
// is left out and a project without Cargo.lock fails without writing one.
func TestCargoResolverReadsALockedProject(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo is not installed")
	}
	root := writeTree(t, map[string]string{
		"Cargo.toml":         "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nhelper = { path = \"helper\" }\n[dev-dependencies]\ndevonly = { path = \"devonly\" }\n",
		"src/lib.rs":         "",
		"helper/Cargo.toml":  "[package]\nname = \"helper\"\nversion = \"0.2.0\"\nedition = \"2021\"\n",
		"helper/src/lib.rs":  "",
		"devonly/Cargo.toml": "[package]\nname = \"devonly\"\nversion = \"0.3.0\"\nedition = \"2021\"\n",
		"devonly/src/lib.rs": "",
	})
	r := NewCargoResolver()
	_, err := r.Resolve(context.Background(), root)
	if !errors.Is(err, ErrCargoLockMissing) {
		t.Fatalf("no Cargo.lock: err = %v, want ErrCargoLockMissing", err)
	}
	if fileExists(filepath.Join(root, "Cargo.lock")) {
		t.Fatal("the resolver wrote a Cargo.lock")
	}
	lock := `# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "devonly",
 "helper",
]

[[package]]
name = "devonly"
version = "0.3.0"

[[package]]
name = "helper"
version = "0.2.0"
`
	if err := os.WriteFile(filepath.Join(root, "Cargo.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(filepath.Dir(root))
	result, err := r.Resolve(context.Background(), filepath.Base(root)) // a relative target, as the CLI is given
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(result.Dependencies) != 0 || result.RootModule != "app" {
		t.Errorf("path dependencies are the project's own code: deps = %v root = %q", result.Dependencies, result.RootModule)
	}
	if len(result.Unpinned) != 0 || len(result.WorkspaceMembers) != 2 || result.WorkspaceMembers[1].Name != "helper" {
		t.Errorf("unpinned = %v, members = %v, want helper a member and devonly left out", result.Unpinned, result.WorkspaceMembers)
	}
}

// TestCargoCrateAtTwoVersions: the app declares rand 0.8.5 and a transitive
// crate (old) needs rand 0.7.3, which alone needs ppv. The request names the
// version the app declares; 0.7.3 is left out (OtherVersions), ppv is only
// required by it (UnderOtherVersions), and old's edge points at 0.8.5.
func TestCargoCrateAtTwoVersions(t *testing.T) {
	t.Parallel()
	cache := t.TempDir()
	doc := map[string]any{
		"workspace_members": []string{appID},
		"packages": []any{
			map[string]any{
				"id": appID, "name": "app", "version": "0.1.0", "source": nil, "manifest_path": "/w/app/Cargo.toml",
				"targets": []any{map[string]any{"name": "app", "kind": []string{"bin"}}},
			},
			registryPkg("rand", "0.8.5", cache), registryPkg("rand", "0.7.3", cache),
			registryPkg("old", "1.0.0", cache), registryPkg("ppv", "1.0.0", cache),
		},
		"resolve": map[string]any{"root": appID, "nodes": []any{
			map[string]any{"id": appID, "deps": []any{normalDep(cargoID("rand", "0.8.5")), normalDep(cargoID("old", "1.0.0"))}},
			map[string]any{"id": cargoID("old", "1.0.0"), "deps": []any{normalDep(cargoID("rand", "0.7.3"))}},
			map[string]any{"id": cargoID("rand", "0.7.3"), "deps": []any{normalDep(cargoID("ppv", "1.0.0"))}},
		}},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var meta cargoMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	result := (&CargoResolver{}).closure(t.TempDir(), &meta)
	if got, want := moduleVersions(result), []string{"old@1.0.0", "rand@0.8.5"}; !reflect.DeepEqual(got, want) {
		t.Errorf("closure = %v, want %v", got, want)
	}
	if got := moduleVersions(&ResolveResult{Dependencies: result.OtherVersions}); !reflect.DeepEqual(got, []string{"rand@0.7.3"}) {
		t.Errorf("other versions = %v", got)
	}
	if got := moduleVersions(&ResolveResult{Dependencies: result.UnderOtherVersions}); !reflect.DeepEqual(got, []string{"ppv@1.0.0"}) {
		t.Errorf("under other versions = %v", got)
	}
	if want := map[string][]Ref{"old@1.0.0": {{Module: "rand", Version: "0.8.5"}}}; !reflect.DeepEqual(result.VersionedGraph, want) {
		t.Errorf("versioned graph = %v, want %v", result.VersionedGraph, want)
	}
}

func TestVersionLess(t *testing.T) {
	t.Parallel()
	for _, c := range [][2]string{{"0.7.3", "0.8.5"}, {"0.9.0", "0.10.0"}, {"1.0.0-rc.1", "1.0.0"}, {"1.2", "1.2.1"}} {
		if !versionLess(c[0], c[1]) || versionLess(c[1], c[0]) {
			t.Errorf("%s must sort below %s", c[0], c[1])
		}
	}
}
