// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// linearDependencyForPath is dependencyForPath before the ancestor walk: the
// first root, longest first, that the path is relative to.
func linearDependencyForPath(dependencies []exportDependencyRoot, path string) *exportDependencyRoot {
	for i := range dependencies {
		if _, ok := relativeToRoot(dependencies[i].Dir, path); ok {
			return &dependencies[i]
		}
	}
	return nil
}

// The ancestor walk must answer what trying every root answered, for nested
// roots, two dependencies sharing a directory, a root that is the path
// itself, and relative paths, so export locations stay byte-identical.
func TestDependencyForPath_AgreesWithTryingEveryRoot(t *testing.T) {
	artifacts := newExportArtifacts(&engine.DepScanResult{
		ProjectRoot: "/work",
		Dependencies: []dependency.Dependency{
			{Module: "outer", Version: "1", Dir: "/mod/outer@1"},
			{Module: "inner", Version: "1", Dir: "/mod/outer@1/vendor/inner"},
			{Module: "twin-a", Version: "1", Dir: "/mod/twin@1"},
			{Module: "twin-b", Version: "1", Dir: "/mod/twin@1/"},
			{Module: "vendored", Version: "1", Dir: "/work/vendor/lib"},
			{Module: "relative", Version: "1", Dir: "deps/rel"},
			{Module: "no-dir", Version: "1"},
		},
	})
	for _, path := range []string{
		"/mod/outer@1/a.go",
		"/mod/outer@1",
		"/mod/outer@1/vendor/inner/b.go",
		"/mod/outer@1/vendor/innerx/b.go",
		"/mod/twin@1/c.go",
		"/work/vendor/lib/d.go",
		"/work/e.go",
		"/elsewhere/f.go",
		"/",
		"deps/rel/g.go",
		"deps/relx/g.go",
		"../deps/rel/h.go",
		"i.go",
		".",
	} {
		want := linearDependencyForPath(artifacts.dependencies, path)
		if got := artifacts.dependencyForPath(path); got != want {
			t.Errorf("dependencyForPath(%q) = %+v, want %+v", path, got, want)
		}
	}
}

// Python distributions installed into one namespace directory share it as
// their Dir; a file there belongs to the one whose Files list it, so each
// exported function and call site names the distribution that installed it.
func TestDependencyForPath_NamespaceSiblingsOwnTheirFiles(t *testing.T) {
	ns := filepath.FromSlash("/sp/google")
	auth, proto := filepath.Join(ns, "auth", "creds.py"), filepath.Join(ns, "protobuf", "msg.py")
	artifacts := newExportArtifacts(&engine.DepScanResult{
		ProjectRoot: "/work",
		Dependencies: []dependency.Dependency{
			{Module: "protobuf", Version: "7", Dir: ns, Files: []string{proto}},
			{Module: "google-auth", Version: "2", Dir: ns, Files: []string{auth}},
		},
	})
	for path, want := range map[string]string{auth: "google-auth", proto: "protobuf", filepath.Join(ns, "other.py"): ""} {
		got := ""
		if dep := artifacts.dependencyForPath(path); dep != nil {
			got = dep.Module
		}
		if got != want {
			t.Errorf("dependencyForPath(%q) = %q, want %q", path, got, want)
		}
	}
}

// A project given as a relative target still binds to a graph whose files
// were recorded with absolute paths, and the other way round.
func TestFindContainingFunctionByFinding_ResolvesRelativeRoots(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, projectRoot, functionFile string
	}{
		{name: "relative root, absolute graph", projectRoot: ".", functionFile: filepath.Join(cwd, "src", "seal.go")},
		{name: "absolute root, relative graph", projectRoot: cwd, functionFile: filepath.Join("src", "seal.go")},
		{name: "no root, relative graph", projectRoot: "", functionFile: filepath.Join("src", "seal.go")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fn := anchorScopeFunction("app/src", tc.functionFile, 100)
			ctx := newExportPathContext(&engine.DepScanResult{
				ProjectRoot: tc.projectRoot,
				CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{fn.ID.String(): fn}},
			})
			if got := ctx.findContainingFunctionByFinding("src/seal.go", nil, 10, 0); got != fn {
				t.Fatalf("findContainingFunctionByFinding = %v, want %s", got, fn.FilePath)
			}
		})
	}
}

// A dependency the scan has no source directory for owns no files, so its
// findings bind to nothing rather than to a file elsewhere.
func TestFindContainingFunctionByFinding_DependencyWithoutSourceBindsNothing(t *testing.T) {
	fn := anchorScopeFunction("example.com/app/util", "/work/util/seal.go", 100)
	ctx := newExportPathContext(&engine.DepScanResult{
		ProjectRoot: "/work",
		CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{fn.ID.String(): fn}},
	})
	dep := &entities.DependencyInfo{Module: "example.com/unscanned", Version: "v1.0.0"}
	if got := ctx.findContainingFunctionByFinding("util/seal.go", dep, 10, 0); got != nil {
		t.Fatalf("finding of an unscanned dependency bound to %s", got.FilePath)
	}
}

// BenchmarkDependencyForPath compares trying every root with walking the
// path's ancestors, at a dependency scan's size: 200 dependency roots.
func BenchmarkDependencyForPath(b *testing.B) {
	deps := make([]dependency.Dependency, 200)
	for i := range deps {
		deps[i] = dependency.Dependency{Module: fmt.Sprintf("m%d", i), Version: "1", Dir: fmt.Sprintf("/home/u/go/pkg/mod/example.com/m%d@v1.0.0", i)}
	}
	artifacts := newExportArtifacts(&engine.DepScanResult{ProjectRoot: "/work", Dependencies: deps})
	path := "/home/u/go/pkg/mod/example.com/m7@v1.0.0/internal/pkg/file.go"
	b.Run("every-root", func(b *testing.B) {
		for range b.N {
			_ = linearDependencyForPath(artifacts.dependencies, path)
		}
	})
	b.Run("ancestors", func(b *testing.B) {
		for range b.N {
			_ = artifacts.dependencyForPath(path)
		}
	})
}
