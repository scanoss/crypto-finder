// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const goResolverMod = `module example.com/app

go 1.22

require (
	example.com/Signer v1.2.0
	example.com/codec v0.3.1 // indirect
	example.com/old v1.0.0
	example.com/local v0.0.0
)

require example.com/single v2.0.0+incompatible // indirect

replace example.com/old v1.0.0 => example.com/new v1.1.0

replace example.com/local => ../local
`

// TestGoResolver: the closure is go.mod's requirements at their versions,
// direct unless `// indirect`, after replace directives; a local replacement
// is unpinned; a module's own edges come from the cached go.mod, upper-case
// paths escaped as the module cache stores them.
func TestGoResolver(t *testing.T) {
	t.Parallel()
	target, cache := t.TempDir(), t.TempDir()
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(target, "go.mod"), goResolverMod)
	write(filepath.Join(cache, "cache", "download", "example.com", "!signer", "@v", "v1.2.0.mod"),
		"module example.com/Signer\n\nrequire example.com/codec v0.3.0\n")
	if err := os.MkdirAll(filepath.Join(cache, "example.com", "!signer@v1.2.0"), 0o755); err != nil {
		t.Fatal(err)
	}

	r := &GoResolver{modCache: cache}
	if !r.CanResolve(target) || r.CanResolve(cache) {
		t.Fatal("CanResolve: want a go.mod")
	}
	got, err := r.Resolve(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	if got.RootModule != "example.com/app" || got.Source != "go.mod" {
		t.Errorf("root %q source %q", got.RootModule, got.Source)
	}
	versions := map[string]string{}
	for _, d := range got.Dependencies {
		versions[d.Module] = d.Version
	}
	wantVersions := map[string]string{
		"example.com/Signer": "v1.2.0", "example.com/codec": "v0.3.1",
		"example.com/new": "v1.1.0", "example.com/single": "v2.0.0+incompatible",
	}
	if !reflect.DeepEqual(versions, wantVersions) {
		t.Errorf("dependencies %v, want %v", versions, wantVersions)
	}
	if want := []string{"example.com/Signer", "example.com/new"}; !reflect.DeepEqual(got.DirectDependencies, want) {
		t.Errorf("direct %v, want %v", got.DirectDependencies, want)
	}
	if want := []string{"example.com/codec"}; !reflect.DeepEqual(got.Graph["example.com/Signer"], want) {
		t.Errorf("Signer requires %v, want %v (the selected version's module)", got.Graph["example.com/Signer"], want)
	}
	if want := []Ref{{Module: "example.com/codec", Version: "v0.3.1"}}; !reflect.DeepEqual(got.VersionedGraph["example.com/Signer@v1.2.0"], want) {
		t.Errorf("versioned edges %v, want %v", got.VersionedGraph, want)
	}
	if len(got.Unpinned) != 1 || got.Unpinned[0].Module != "example.com/local" {
		t.Errorf("unpinned %v, want the local replacement", got.Unpinned)
	}
	for _, d := range got.Dependencies {
		if (d.Dir != "") != (d.Module == "example.com/Signer") {
			t.Errorf("%s dir %q: only the cached module has one", d.Module, d.Dir)
		}
		if d.Local {
			t.Errorf("%s: a module version is not a local source", d.Module)
		}
	}
}

// TestGoResolverLocalReplacement: a module replaced by a directory outside
// the module is a local dependency at its required version, analyzed from
// that directory, its edges read from the directory's go.mod. A replacement
// inside the module is the project's own code and stays unpinned, as does
// one whose directory does not exist.
func TestGoResolverLocalReplacement(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"app/go.mod": `module example.com/app

go 1.22

require (
	example.com/liba v1.0.0
	example.com/libb v1.0.0 // indirect
	example.com/inner v0.0.0
	example.com/gone v0.0.0
)

replace example.com/liba => ../liba

replace example.com/libb v1.0.0 => ../libb

replace example.com/inner => ./inner

replace example.com/gone => ../gone
`,
		"app/inner/go.mod": "module example.com/inner\n",
		"liba/go.mod":      "module example.com/liba\n\nrequire example.com/libb v1.0.0\n",
		"liba/liba.go":     "package liba\n",
		"libb/go.mod":      "module example.com/libb\n",
	})
	r := &GoResolver{}
	got, err := r.Resolve(t.Context(), filepath.Join(root, "app"))
	if err != nil {
		t.Fatal(err)
	}
	want := []Dependency{
		{Module: "example.com/liba", Version: "v1.0.0", Dir: filepath.Join(root, "liba"), Local: true},
		{Module: "example.com/libb", Version: "v1.0.0", Dir: filepath.Join(root, "libb"), Local: true},
	}
	if !reflect.DeepEqual(got.Dependencies, want) {
		t.Errorf("dependencies %+v, want %+v", got.Dependencies, want)
	}
	if want := []string{"example.com/liba"}; !reflect.DeepEqual(got.DirectDependencies, want) {
		t.Errorf("direct %v, want %v", got.DirectDependencies, want)
	}
	if want := []Ref{{Module: "example.com/libb", Version: "v1.0.0"}}; !reflect.DeepEqual(got.VersionedGraph["example.com/liba@v1.0.0"], want) {
		t.Errorf("liba's edges %v, want %v (from its own go.mod)", got.VersionedGraph, want)
	}
	unpinned := make([]string, 0, len(got.Unpinned))
	for _, u := range got.Unpinned {
		unpinned = append(unpinned, u.Module)
	}
	if want := []string{"example.com/inner", "example.com/gone"}; !reflect.DeepEqual(unpinned, want) {
		t.Errorf("unpinned %v, want %v", unpinned, want)
	}
}
