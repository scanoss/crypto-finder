// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/oid"
)

const goResolutionSource = `package app

import (
	"crypto/sha256"

	"example.com/dep"
)

type Local struct{}

func (Local) Run() {}

func use(s *dep.Signer, fn func(int)) {
	sha256.Sum256(nil)
	s.Sign(nil)
	fn(1)
	x := dep.Open()
	x.Do(2)
	dep.Open().Close()
	Local{}.Run()
	(&Local{}).Run()
	new(Local).Run()
	dep.Config{}.Apply()
}
`

func exportGoSource(t *testing.T, source string) graphfrag.GraphFragmentExport {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	builder := callgraph.NewBuilderForEcosystem("go", callgraph.NewParserForEcosystem("go"))
	graph, err := builder.BuildFromDirectories([]callgraph.PackageDir{{Dir: root, ImportPath: "example.com/app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	export := BuildGraphFragmentExport(&engine.DepScanResult{CallGraph: graph, Ecosystem: "go", ProjectRoot: root}, &oid.ResolvedReport{})
	export.RestoreElided()
	return export
}

// A Go call nothing typed is exported name_only with its method name and
// argument count, so a stitcher matches it by name and reads what it reaches
// as unknown: a method on an untyped local or on a call's result, a call of a
// func value. Calls through an import or on a typed receiver stay exact.
func TestExportGraphFragment_GoUntypedCallsAreNameOnly(t *testing.T) {
	t.Parallel()
	export := exportGoSource(t, goResolutionSource)
	type want struct {
		resolution string
		method     string
		arity      int
	}
	wants := map[string]want{
		"x.Do":             {string(callgraph.EdgeKindNameOnly), "Do", 1},
		"dep.Open().Close": {string(callgraph.EdgeKindNameOnly), "Close", 0},
		"fn":               {string(callgraph.EdgeKindNameOnly), "fn", 1},
		"sha256.Sum256":    {string(callgraph.EdgeKindExact), "", -1},
		"s.Sign":           {string(callgraph.EdgeKindExact), "", -1},
		"dep.Open":         {string(callgraph.EdgeKindExact), "", -1},
	}
	seen := map[string]bool{}
	for _, e := range export.ExternalCalls {
		w, ok := wants[e.Raw]
		if !ok {
			continue
		}
		seen[e.Raw] = true
		if e.Resolution != w.resolution {
			t.Errorf("%s -> %s resolution %q, want %q", e.Raw, e.TargetKey, e.Resolution, w.resolution)
		}
		if w.arity >= 0 && (e.MethodName != w.method || e.Arity != w.arity) {
			t.Errorf("%s method %q arity %d, want %q %d", e.Raw, e.MethodName, e.Arity, w.method, w.arity)
		}
	}
	for raw := range wants {
		if !seen[raw] {
			t.Errorf("no external call %s", raw)
		}
	}
}

// A method called on a value the expression constructs (`T{}`, `&T{}`,
// `new(T)`) links to its declaration: an exact internal edge for a type of
// the component, an exact call of the type's method for an imported one.
func TestExportGraphFragment_GoConstructedReceivers(t *testing.T) {
	t.Parallel()
	export := exportGoSource(t, goResolutionSource)
	lines := map[int]bool{}
	for _, e := range export.InternalEdges {
		if e.CallerKey == "example.com/app.use" && e.CalleeKey == "example.com/app.(Local).Run" {
			if e.Resolution != string(callgraph.EdgeKindExact) {
				t.Errorf("line %d: use -> (Local).Run resolution %q, want exact", e.Line, e.Resolution)
			}
			lines[e.Line] = true
		}
	}
	if len(lines) != 3 {
		t.Errorf("use -> (Local).Run on lines %v, want the 3 constructed receivers", lines)
	}
	for _, e := range export.ExternalCalls {
		if e.Raw == "dep.Config{}.Apply" && (e.TargetKey != "example.com/dep.(Config).Apply" || e.Resolution != string(callgraph.EdgeKindExact)) {
			t.Errorf("dep.Config{}.Apply -> %s %s, want example.com/dep.(Config).Apply exact", e.TargetKey, e.Resolution)
		}
	}
}

// A Go fragment lists the values its code reads through an import
// (constant_refs) with the function that holds them, a package-level data
// var's in the file's <varinit> even when that holds no call.
func TestExportGraphFragment_GoConstantRefs(t *testing.T) {
	t.Parallel()
	export := exportGoSource(t, `package app

import "example.com/conf"

var Suites = []int{conf.Level0}

func use(v int) bool {
	return v == conf.Level1
}
`)
	want := map[string]string{
		"example.com/conf.Level0": "example.com/app.<varinit:app>|array",
		"example.com/conf.Level1": "example.com/app.use|compare",
	}
	got := map[string]string{}
	for _, r := range export.ConstantRefs {
		if r.Function < 0 || r.Function >= len(export.Functions) {
			t.Fatalf("%s: function index %d out of range", r.Text, r.Function)
		}
		got[r.Text] = export.Functions[r.Function].Key + "|" + r.Context
	}
	for text, w := range want {
		if got[text] != w {
			t.Errorf("%s at %q, want %q (all: %v)", text, got[text], w, got)
		}
	}
}

// A Go fragment lists the var declarations of an imported type with the type
// written through its import path.
func TestExportGraphFragment_GoDeclarations(t *testing.T) {
	t.Parallel()
	export := exportGoSource(t, `package app

import "example.com/keys"

func use() {
	var params keys.Params
	_ = params
}
`)
	for _, d := range export.Declarations {
		if d.Name == "params" {
			if d.Type != "example.com/keys.Params" || export.Functions[d.Function].Key != "example.com/app.use" {
				t.Errorf("params declared %q in %s, want example.com/keys.Params in example.com/app.use", d.Type, export.Functions[d.Function].Key)
			}
			return
		}
	}
	t.Errorf("no declaration of params: %+v", export.Declarations)
}

// A call a builder pass retypes leaves no site behind under the callee it had
// before: an untyped `key.PublicKey.Bytes()` above a `key.Bytes()` retyped
// from key's producer is exported once, on its own line.
func TestExportGraphFragment_GoRetypedCallLeavesNoPhantomSite(t *testing.T) {
	t.Parallel()
	export := exportGoSource(t, `package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func f() ([]byte, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	point, _ := key.PublicKey.Bytes()
	scalar, _ := key.Bytes()
	return point, scalar
}
`)
	seen := map[string]int{}
	for _, e := range export.ExternalCalls {
		if e.EntryCall != nil && e.EntryCall.Line != 0 && e.EntryCall.Line != e.Line {
			t.Errorf("%s at line %d carries the call of line %d", e.Raw, e.Line, e.EntryCall.Line)
		}
		seen[e.Raw]++
	}
	if seen["key.PublicKey.Bytes"] != 1 || seen["key.Bytes"] != 1 {
		t.Errorf("sites per call %v, want one each", seen)
	}
}

// TestExportGraphFragment_GoUnreadTypeCallsAreNameOnly: a call on a type of a
// module the source roots lack may be an interface call, so it is name_only;
// a method of a read struct type stays exact.
func TestExportGraphFragment_GoUnreadTypeCallsAreNameOnly(t *testing.T) {
	t.Parallel()
	root, depDir := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(depDir, "dep.go"), []byte("package dep\n\ntype Key struct{}\n\nfunc (k *Key) Use() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const source = `package app

import (
	"example.com/dep"
	"example.com/missing"
)

func use() {
	var k *dep.Key
	k.Use()
	var h missing.Hasher
	h.Sum(nil)
}
`
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	builder := callgraph.NewBuilderForEcosystem("go", callgraph.NewParserForEcosystem("go"))
	builder.SetTypeResolver(callgraph.NewGoSourceTypeResolver([]callgraph.GoSourceRoot{{Dir: depDir, Module: "example.com/dep"}}))
	graph, err := builder.BuildFromDirectories([]callgraph.PackageDir{{Dir: root, ImportPath: "example.com/app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	export := BuildGraphFragmentExport(&engine.DepScanResult{CallGraph: graph, Ecosystem: "go", ProjectRoot: root}, &oid.ResolvedReport{})
	export.RestoreElided()
	got := map[string]string{}
	for _, e := range export.ExternalCalls {
		got[e.Raw] = e.Resolution
	}
	if got["k.Use"] != string(callgraph.EdgeKindExact) || got["h.Sum"] != string(callgraph.EdgeKindNameOnly) {
		t.Errorf("resolutions %v, want k.Use exact and h.Sum name_only", got)
	}
}
