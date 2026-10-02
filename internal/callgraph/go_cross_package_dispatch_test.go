// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeGoTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func buildGoTree(t *testing.T, files map[string]string) *CallGraph {
	t.Helper()
	root := t.TempDir()
	writeGoTree(t, root, files)
	g, err := NewBuilderForEcosystem("go", NewGoParser()).
		BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "example.com/m"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return g
}

func assertGoDispatch(t *testing.T, g *CallGraph, caller, callee string) {
	t.Helper()
	if !goHasCaller(g, callee, caller) {
		t.Fatalf("%s has no caller %s; callers=%v", callee, caller, g.Callers[callee])
	}
	if kind, ok := goEdgeKind(g, caller, callee); !ok || kind != EdgeKindInterfaceDispatch {
		t.Errorf("edge %s -> %s = %q (found %v), want interface_dispatch", caller, callee, kind, ok)
	}
}

const crossPkgLic = `package lic

type Signer interface{ Sign(data string) string }

type Direct struct{}

func (d *Direct) Sign(data string) string { return data }
`

const crossPkgImpl = `package impl

type Provider struct{}

func (p *Provider) Sign(data string) string { return data }

type Unrelated struct{}

func (u *Unrelated) Sign(data string, extra string) string { return data }

type Verifier struct{}

func (v *Verifier) Verify(data string) bool { return true }
`

func TestGoBuilder_InterfaceDispatchAcrossPackages(t *testing.T) {
	g := buildGoTree(t, map[string]string{
		"lic/lic.go":   crossPkgLic,
		"impl/impl.go": crossPkgImpl,
		"app/app.go": `package app

import "example.com/m/lic"

type Service struct{ signer lic.Signer }

func (s *Service) FromField(d string) string { return s.signer.Sign(d) }

func FromParam(s lic.Signer, d string) string { return s.Sign(d) }

func FromLocal(d string) string {
	var s lic.Signer
	return s.Sign(d)
}
`,
	})

	provider := "example.com/m/impl.(*Provider).Sign"
	for _, caller := range []string{
		"example.com/m/app.(*Service).FromField",
		"example.com/m/app.FromParam",
		"example.com/m/app.FromLocal",
	} {
		assertGoDispatch(t, g, caller, provider)
		assertGoDispatch(t, g, caller, "example.com/m/lic.(*Direct).Sign")
		for _, no := range []string{
			"example.com/m/impl.(*Unrelated).Sign",
			"example.com/m/impl.(*Verifier).Verify",
		} {
			if goHasCaller(g, no, caller) {
				t.Errorf("%s must not be linked from %s: not an implementer", no, caller)
			}
		}
	}
}

func TestGoBuilder_NonImplementerWithSameMethodNameGetsNoEdge(t *testing.T) {
	g := buildGoTree(t, map[string]string{
		"lic/lic.go": "package lic\n\ntype Pair interface {\n\tSign(data string) string\n\tVerify(data string) bool\n}\n",
		"impl/impl.go": `package impl

type Full struct{}

func (f *Full) Sign(data string) string { return data }
func (f *Full) Verify(data string) bool { return true }

type SignOnly struct{}

func (s *SignOnly) Sign(data string) string { return data }
`,
		"app/app.go": "package app\n\nimport \"example.com/m/lic\"\n\nfunc Use(p lic.Pair) string { return p.Sign(\"x\") }\n",
	})
	caller := "example.com/m/app.Use"
	assertGoDispatch(t, g, caller, "example.com/m/impl.(*Full).Sign")
	if goHasCaller(g, "example.com/m/impl.(*SignOnly).Sign", caller) {
		t.Errorf("SignOnly lacks Verify and must not be linked")
	}
}

func TestGoBuilder_InterfaceDispatchToImplementerInNestedModule(t *testing.T) {
	g := buildGoTree(t, map[string]string{
		"lic/lic.go":                    crossPkgLic,
		"third_party/ext@v1.0.0/go.mod": "module example.org/ext\n\ngo 1.21\n",
		"third_party/ext@v1.0.0/ext.go": "package ext\n\ntype Remote struct{}\n\nfunc (r *Remote) Sign(data string) string { return data }\n",
		"app/app.go":                    "package app\n\nimport \"example.com/m/lic\"\n\nfunc Use(s lic.Signer) string { return s.Sign(\"x\") }\n",
	})
	assertGoDispatch(t, g, "example.com/m/app.Use", "example.org/ext.(*Remote).Sign")
}

// A tiny interface such as Close() error matches every type that has a Close
// method, so the fan-out is bounded to artifacts that can use the interface:
// a dependency type never implements a project interface, while a project
// type does implement a dependency's.
func TestGoBuilder_DispatchFanOutIsBoundedByArtifact(t *testing.T) {
	projectDir, depDir := t.TempDir(), t.TempDir()
	writeGoTree(t, projectDir, map[string]string{
		"closer/closer.go": "package closer\n\ntype Closer interface{ Close() error }\n",
		"mine/mine.go":     "package mine\n\ntype File struct{}\n\nfunc (f *File) Close() error { return nil }\n",
		"app/app.go": `package app

import (
	"fmt"
	"example.com/m/closer"
	"example.org/dep"
)

func UseProject(c closer.Closer) error { return c.Close() }

func UseDep(c dep.Stream) error { return c.Close() }
`,
	})
	writeGoTree(t, depDir, map[string]string{
		"dep.go":      "package dep\n\ntype Stream interface{ Close() error }\n\ntype Conn struct{}\n\nfunc (c *Conn) Close() error { return nil }\n",
		"other/o.go":  "package other\n\ntype Handle struct{}\n\nfunc (h *Handle) Close() error { return nil }\n",
		"other2/o.go": "package other2\n\ntype Pipe struct{}\n\nfunc (p *Pipe) Close() error { return nil }\n",
	})
	g, err := NewBuilderForEcosystem("go", NewGoParser()).BuildFromDirectories([]PackageDir{
		{Dir: projectDir, ImportPath: "example.com/m"},
		{Dir: depDir, ImportPath: "example.org/dep", Version: "1.0.0"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	useProject := "example.com/m/app.UseProject"
	assertGoDispatch(t, g, useProject, "example.com/m/mine.(*File).Close")
	for _, depType := range []string{"example.org/dep.(*Conn).Close", "example.org/dep/other.(*Handle).Close", "example.org/dep/other2.(*Pipe).Close"} {
		if goHasCaller(g, depType, useProject) {
			t.Errorf("dependency type %s must not implement a project interface", depType)
		}
	}

	useDep := "example.com/m/app.UseDep"
	assertGoDispatch(t, g, useDep, "example.com/m/mine.(*File).Close")
	assertGoDispatch(t, g, useDep, "example.org/dep.(*Conn).Close")
}

// Another dotted-name ecosystem keeps its namespace-root bound: a Java class
// outside the interface's root is not linked, one inside is.
func TestJavaBuilder_InterfaceDispatchStaysInNamespaceRoot(t *testing.T) {
	dir := t.TempDir()
	writeGoTree(t, dir, map[string]string{
		"com/acme/api/Signer.java": "package com.acme.api;\n\npublic interface Signer { String sign(String d); }\n",
		"com/acme/impl/Near.java":  "package com.acme.impl;\n\nimport com.acme.api.Signer;\n\npublic class Near implements Signer { public String sign(String d) { return d; } }\n",
		"org/other/Far.java":       "package org.other;\n\nimport com.acme.api.Signer;\n\npublic class Far implements Signer { public String sign(String d) { return d; } }\n",
		"com/acme/app/App.java":    "package com.acme.app;\n\nimport com.acme.api.Signer;\n\npublic class App { public String run(Signer s) { return s.sign(\"x\"); } }\n",
	})
	g, err := NewBuilderForEcosystem(ecosystemJava, NewJavaParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var run, near, far string
	for key, fn := range g.Functions {
		switch {
		case fn.ID.Type == "App" && BaseFunctionName(fn.ID.Name) == "run":
			run = key
		case fn.ID.Type == "Near" && BaseFunctionName(fn.ID.Name) == "sign":
			near = key
		case fn.ID.Type == "Far" && BaseFunctionName(fn.ID.Name) == "sign":
			far = key
		}
	}
	if run == "" || near == "" || far == "" {
		t.Skipf("java fixture not parsed: run=%q near=%q far=%q", run, near, far)
	}
	if !goHasCaller(g, near, run) {
		t.Errorf("in-root implementer has no caller; callers=%v", g.Callers[near])
	}
	if goHasCaller(g, far, run) {
		t.Errorf("cross-root implementer must stay unlinked")
	}
}

func closerTree(n int, samePackage bool) map[string]string {
	files := map[string]string{
		"closer/closer.go": "package closer\n\ntype Closer interface{ Close() error }\n",
		"app/app.go":       "package app\n\nimport \"example.com/m/closer\"\n\nfunc Use(c closer.Closer) error { return c.Close() }\n",
	}
	for i := range n {
		pkg := fmt.Sprintf("p%02d", i)
		files[pkg+"/"+pkg+".go"] = fmt.Sprintf("package %s\n\ntype T struct{}\n\nfunc (t *T) Close() error { return nil }\n", pkg)
	}
	if samePackage {
		files["closer/own.go"] = "package closer\n\ntype Own struct{}\n\nfunc (o *Own) Close() error { return nil }\n"
	}
	return files
}

func TestGoBuilder_CrossPackageDispatchOverCapIsNameOnly(t *testing.T) {
	const caller = "example.com/m/app.Use"

	few := buildGoTree(t, closerTree(goCrossPackageDispatchCap, false))
	for i := range goCrossPackageDispatchCap {
		assertGoDispatch(t, few, caller, fmt.Sprintf("example.com/m/p%02d.(*T).Close", i))
	}

	many := buildGoTree(t, closerTree(20, true))
	for i := range 20 {
		callee := fmt.Sprintf("example.com/m/p%02d.(*T).Close", i)
		if !goHasCaller(many, callee, caller) {
			t.Fatalf("%s lost its edge; callers=%v", callee, many.Callers[callee])
		}
		if kind, _ := goEdgeKind(many, caller, callee); kind != EdgeKindNameOnly {
			t.Errorf("%s edge = %q, want name_only past the cap", callee, kind)
		}
	}
	assertGoDispatch(t, many, caller, "example.com/m/closer.(*Own).Close")
}

func TestGoBuilder_UnexportedMethodInterfaceStaysInItsPackage(t *testing.T) {
	g := buildGoTree(t, map[string]string{
		"lic/lic.go": `package lic

type Sealed interface {
	Sign(data string) string
	seal()
}

type Own struct{}

func (o *Own) Sign(data string) string { return data }
func (o *Own) seal()                   {}
`,
		"impl/impl.go": `package impl

type Outside struct{}

func (o *Outside) Sign(data string) string { return data }
func (o *Outside) seal()                   {}
`,
		"app/app.go": "package app\n\nimport \"example.com/m/lic\"\n\nfunc Use(s lic.Sealed) string { return s.Sign(\"x\") }\n",
	})
	caller := "example.com/m/app.Use"
	assertGoDispatch(t, g, caller, "example.com/m/lic.(*Own).Sign")
	if goHasCaller(g, "example.com/m/impl.(*Outside).Sign", caller) {
		t.Errorf("a type outside the package cannot implement an interface with an unexported method")
	}
}

func TestGoBuilder_DependencyImplementerOfAnotherDependencyInterface(t *testing.T) {
	build := func(requires map[string][]string) *CallGraph {
		projectDir, aDir, bDir := t.TempDir(), t.TempDir(), t.TempDir()
		writeGoTree(t, projectDir, map[string]string{
			"app/app.go": "package app\n\nimport \"example.org/a\"\n\nfunc Use(s a.Signer) string { return s.Sign(\"x\") }\n",
		})
		writeGoTree(t, aDir, map[string]string{"a.go": "package a\n\ntype Signer interface{ Sign(d string) string }\n"})
		writeGoTree(t, bDir, map[string]string{"b.go": "package b\n\ntype Impl struct{}\n\nfunc (i *Impl) Sign(d string) string { return d }\n"})
		b := NewBuilderForEcosystem("go", NewGoParser())
		if requires != nil {
			b.SetArtifactDependencies(requires)
		}
		g, err := b.BuildFromDirectories([]PackageDir{
			{Dir: projectDir, ImportPath: "example.com/m"},
			{Dir: aDir, ImportPath: "example.org/a", Version: "1.0.0"},
			{Dir: bDir, ImportPath: "example.org/b", Version: "1.0.0"},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	const caller, impl = "example.com/m/app.Use", "example.org/b.(*Impl).Sign"

	if g := build(nil); goHasCaller(g, impl, caller) {
		t.Errorf("without a resolved dependency graph a dependency type is not linked to another dependency's interface")
	}
	if g := build(map[string][]string{"example.org/b": {"example.org/a"}}); !goHasCaller(g, impl, caller) {
		t.Errorf("b requires a, so b's type can implement a's interface; callers=%v", g.Callers[impl])
	}
	if g := build(map[string][]string{"example.org/a": {"example.org/b"}}); goHasCaller(g, impl, caller) {
		t.Errorf("a requiring b does not let b's type implement a's interface")
	}
}
