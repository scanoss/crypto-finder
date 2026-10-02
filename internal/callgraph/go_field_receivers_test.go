// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func goEdgeKind(g *CallGraph, callerKey, calleeKey string) (EdgeKind, bool) {
	prefix := EdgeResolutionKeyPrefix(callerKey, calleeKey)
	for k := range g.EdgeResolutions {
		if strings.HasPrefix(k, prefix) {
			return g.EdgeResolutions[k].Kind, true
		}
	}
	return "", false
}

func goHasCaller(g *CallGraph, calleeKey, callerKey string) bool {
	for _, c := range g.Callers[calleeKey] {
		if c == callerKey {
			return true
		}
	}
	return false
}

func TestGoParser_RecordsStructFieldTypes(t *testing.T) {
	dir := t.TempDir()
	src := `package app

import (
	"example.com/cache"
	"sync"
)

type Repo struct {
	cm      *cache.Manager
	local   Store
	val     Store2
	a, b    *Store
	mu      sync.Mutex
	hooks   func()
	items   []Store
	generic Box[int]
	Store
}
`
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewGoParser().ParseDirectory(dir, "app")
	if err != nil || len(analyses) != 1 {
		t.Fatalf("ParseDirectory: %v (%d analyses)", err, len(analyses))
	}
	fields := analyses[0].GoStructFields["Repo"]
	want := map[string]GoFieldType{
		"cm":    {Package: "example.com/cache", Type: "*Manager"},
		"local": {Package: "app", Type: "Store"},
		"val":   {Package: "app", Type: "Store2"},
		"a":     {Package: "app", Type: "*Store"},
		"b":     {Package: "app", Type: "*Store"},
		"mu":    {Package: "sync", Type: "Mutex"},
	}
	for name, ft := range want {
		if fields[name] != ft {
			t.Errorf("field %s = %+v, want %+v", name, fields[name], ft)
		}
	}
	if got, want := fields["items"], (GoFieldType{ElemPackage: "app", ElemType: "Store"}); got != want {
		t.Errorf("field items = %+v, want %+v", got, want)
	}
	for _, name := range []string{"hooks", "generic", "Store"} {
		if _, ok := fields[name]; ok {
			t.Errorf("field %s must not be typed, got %+v", name, fields[name])
		}
	}
}

func TestGoParser_FieldReceiverCallShape(t *testing.T) {
	dir := t.TempDir()
	src := `package app

type Repo struct{ cm *Cm }
type Cm struct{}

func (c *Cm) Get() {}

func mk() int { return 0 }

func (r *Repo) Use(o *Repo) {
	u := mk()
	r.cm.Get()
	o.cm.Get()
	u.cm.Get()
	r.cm.deep.Get()
	pkg.Var.cm.Get()
}
`
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewGoParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	var use *FunctionDecl
	for i := range analyses[0].Functions {
		if analyses[0].Functions[i].ID.Name == "Use" {
			use = &analyses[0].Functions[i]
		}
	}
	if use == nil {
		t.Fatal("Use not parsed")
	}
	var typed []string
	for _, c := range use.Calls {
		if c.FieldReceiver != nil {
			typed = append(typed, c.FieldReceiver.Owner.Package+"."+c.FieldReceiver.Owner.Type+"/"+c.FieldReceiver.Name+"/"+c.Callee.Name)
		}
	}
	want := []string{"app.*Repo/cm/Get", "app.*Repo/cm/Get"}
	if strings.Join(typed, ",") != strings.Join(want, ",") {
		t.Errorf("field-receiver calls = %v, want %v (receiver and typed param only; untyped local, longer chain, package root excluded)", typed, want)
	}
}

func TestGoBuilder_FieldReceiverResolvesConcrete(t *testing.T) {
	g := buildGoGraph(t, `package app

type Cm struct{}

func (c *Cm) Get() {}

type ValStore struct{}

func (v *ValStore) Put() {}

type Repo struct {
	cm  *Cm
	val ValStore
}

func (r *Repo) Load() {
	r.cm.Get()
	r.val.Put()
}
`)
	for _, callee := range []string{"app.(*Cm).Get", "app.(*ValStore).Put"} {
		if !goHasCaller(g, callee, "app.(*Repo).Load") {
			t.Errorf("%s has no caller Load; callers=%v", callee, g.Callers[callee])
		}
		kind, ok := goEdgeKind(g, "app.(*Repo).Load", callee)
		if !ok || kind != EdgeKindExact {
			t.Errorf("edge to %s kind = %q (found %v), want exact", callee, kind, ok)
		}
	}
}

func TestGoBuilder_FieldReceiverTypedLocalRoot(t *testing.T) {
	g := buildGoGraph(t, `package app

type Cm struct{}

func (c *Cm) Get() {}

type Repo struct{ cm *Cm }

func Load(r *Repo) {
	r.cm.Get()
}
`)
	if !goHasCaller(g, "app.(*Cm).Get", "app.Load") {
		t.Errorf("Get has no caller Load; callers=%v", g.Callers["app.(*Cm).Get"])
	}
}

func TestGoBuilder_FieldInterfaceFansOutToImplementers(t *testing.T) {
	g := buildGoGraph(t, `package app

type Cache interface{ Get() }

type memCache struct{}

func (m *memCache) Get() {}

type Repo struct{ cache Cache }

func (r *Repo) Load() {
	r.cache.Get()
}
`)
	caller := "app.(*Repo).Load"
	if kind, ok := goEdgeKind(g, caller, "app.(Cache).Get"); !ok || kind != EdgeKindExact {
		t.Errorf("direct interface edge = %q (found %v), want exact", kind, ok)
	}
	impl := "app.(*memCache).Get"
	if !goHasCaller(g, impl, caller) {
		t.Fatalf("implementer has no caller Load; callers=%v", g.Callers[impl])
	}
	if kind, ok := goEdgeKind(g, caller, impl); !ok || kind != EdgeKindInterfaceDispatch {
		t.Errorf("implementer edge = %q (found %v), want interface_dispatch", kind, ok)
	}
}

func TestGoBuilder_FieldReceiverUnresolvedShapesStayUntyped(t *testing.T) {
	g := buildGoGraph(t, `package app

type Cm struct{}

func (c *Cm) Get() {}

type Inner struct{ cm *Cm }

type Embedded struct{ Inner }

type Repo struct {
	inner Inner
	hook  func()
}

func (r *Repo) Load(e *Embedded, x unknown) {
	r.inner.cm.Get()
	e.cm.Get()
	x.cm.Get()
	r.missing.Get()
}
`)
	if got := g.Callers["app.(*Cm).Get"]; len(got) != 0 {
		t.Errorf("untypable field calls must not reach Cm.Get, callers=%v", got)
	}
	for _, k := range goCalleeKeys(g) {
		if k == "app.(Cm).Get" || k == "app.(*Cm).Get" {
			t.Errorf("unexpected typed callee %q", k)
		}
	}
}

func TestGoBuilder_FieldReceiverDisagreeingDeclarationsStayUntyped(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"a.go": "package app\n\ntype A struct{}\n\nfunc (a *A) Get() {}\n\ntype B struct{}\n\nfunc (b *B) Get() {}\n\ntype Repo struct{ x *A }\n\nfunc (r *Repo) Load() { r.x.Get() }\n",
		"b.go": "package app\n\ntype Repo2 struct{ x *B }\n",
		"c.go": "package app\n\ntype Repo struct{ x *B }\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	g, err := NewBuilderForEcosystem("go", NewGoParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, callee := range []string{"app.(*A).Get", "app.(*B).Get"} {
		if goHasCaller(g, callee, "app.(*Repo).Load") {
			t.Errorf("a field two declarations disagree on must not resolve to %s", callee)
		}
	}
}

func TestGoBuilder_FieldReceiverCrossPackage(t *testing.T) {
	root := t.TempDir()
	cacheDir := filepath.Join(root, "cache")
	appDir := filepath.Join(root, "app")
	for _, d := range []string{cacheDir, appDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(cacheDir, "cache.go"): `package cache

type Manager struct{}

func (m *Manager) Get() {}

type Store interface{ Fetch() }

type disk struct{}

func (d *disk) Fetch() {}
`,
		filepath.Join(appDir, "app.go"): `package app

import "example.com/m/cache"

type Repo struct {
	cm    *cache.Manager
	store cache.Store
}

func (r *Repo) Load() {
	r.cm.Get()
	r.store.Fetch()
}
`,
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	g, err := NewBuilderForEcosystem("go", NewGoParser()).BuildFromDirectories([]PackageDir{
		{Dir: cacheDir, ImportPath: "example.com/m/cache"},
		{Dir: appDir, ImportPath: "example.com/m/app"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	caller := "example.com/m/app.(*Repo).Load"
	for _, callee := range []string{
		"example.com/m/cache.(*Manager).Get",
		"example.com/m/cache.(Store).Fetch",
		"example.com/m/cache.(*disk).Fetch",
	} {
		if !goHasCaller(g, callee, caller) {
			t.Errorf("%s has no caller Load; callers=%v", callee, g.Callers[callee])
		}
	}
}

func TestGoBuilder_FieldTypedByTypeParameterStaysUntyped(t *testing.T) {
	g := buildGoGraph(t, `package app

type Getter interface{ Get() }

type T struct{}

func (t *T) Get() {}

type Foo[T Getter] struct{ c T }

func (f *Foo[T]) Use() {
	f.c.Get()
}
`)
	if goHasCaller(g, "app.(*T).Get", "app.(*Foo).Use") || goHasCaller(g, "app.(T).Get", "app.(*Foo).Use") {
		t.Errorf("a field typed by a type parameter must not resolve to the package's type T; callers=%v", g.Callers["app.(*T).Get"])
	}
}

func TestGoBuilder_FieldReceiverAliasedImport(t *testing.T) {
	root := t.TempDir()
	cacheDir := filepath.Join(root, "cache")
	appDir := filepath.Join(root, "app")
	for _, d := range []string{cacheDir, appDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(cacheDir, "cache.go"): "package cache\n\ntype Manager struct{}\n\nfunc (m *Manager) Get() {}\n",
		filepath.Join(appDir, "app.go"): `package app

import c "example.com/m/cache"

type Repo struct{ cm *c.Manager }

func (r *Repo) Load() {
	r.cm.Get()
}
`,
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	g, err := NewBuilderForEcosystem("go", NewGoParser()).BuildFromDirectories([]PackageDir{
		{Dir: cacheDir, ImportPath: "example.com/m/cache"},
		{Dir: appDir, ImportPath: "example.com/m/app"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	callee := "example.com/m/cache.(*Manager).Get"
	if !goHasCaller(g, callee, "example.com/m/app.(*Repo).Load") {
		t.Errorf("aliased import field has no caller; callers=%v", g.Callers[callee])
	}
}

func TestGoBuilder_FieldReceiverTypedLocalNamedLikeReceiverRoot(t *testing.T) {
	g := buildGoGraph(t, `package app

type Cm struct{}

func (c *Cm) Get() {}

type Repo struct{ cm *Cm }

func (c *Cm) Self(r *Repo) {
	r.cm.Get()
}

func Local() {
	var r *Repo
	r.cm.Get()
}
`)
	for _, caller := range []string{"app.Local", "app.(*Cm).Self"} {
		if !goHasCaller(g, "app.(*Cm).Get", caller) {
			t.Errorf("no caller %s; callers=%v", caller, g.Callers["app.(*Cm).Get"])
		}
		if kind, ok := goEdgeKind(g, caller, "app.(*Cm).Get"); !ok || kind != EdgeKindExact {
			t.Errorf("edge from %s kind = %q (found %v), want exact", caller, kind, ok)
		}
	}
}

func TestGoBuilder_FieldReceiverPointerAndValueMethodSets(t *testing.T) {
	g := buildGoGraph(t, `package app

type PtrM struct{}

func (p *PtrM) Put() {}

type ValM struct{}

func (v ValM) Get() {}

type Repo struct {
	val PtrM
	ptr *ValM
}

func (r *Repo) Load() {
	r.val.Put()
	r.ptr.Get()
}
`)
	for _, callee := range []string{"app.(*PtrM).Put", "app.(ValM).Get"} {
		if !goHasCaller(g, callee, "app.(*Repo).Load") {
			t.Errorf("%s has no caller Load; callers=%v", callee, g.Callers[callee])
			continue
		}
		if kind, ok := goEdgeKind(g, "app.(*Repo).Load", callee); ok && kind != EdgeKindExact {
			t.Errorf("edge to %s kind = %q, want exact", callee, kind)
		}
	}
}

func TestGoBuilder_FieldReceiverThreeWayBuildTagMergeStaysUntyped(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"a.go": "package app\n\ntype A struct{}\n\nfunc (a *A) Get() {}\n\ntype B struct{}\n\nfunc (b *B) Get() {}\n\ntype Repo struct{ x *A }\n\nfunc (r *Repo) Load() { r.x.Get() }\n",
		"b.go": "package app\n\ntype Repo struct{ x *B }\n",
		"c.go": "package app\n\ntype Repo struct{ x *A }\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	g, err := NewBuilderForEcosystem("go", NewGoParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, callee := range []string{"app.(*A).Get", "app.(*B).Get"} {
		if goHasCaller(g, callee, "app.(*Repo).Load") {
			t.Errorf("A,B,A declarations must stay untyped, got edge to %s", callee)
		}
	}
}

func TestGoBuilder_FieldOfExternalOrUndeclaredTypeAddsNoFallbackEdge(t *testing.T) {
	g := buildGoGraph(t, `package app

import (
	"sync"
	. "example.com/dot"
)

type Other struct{}

func (o *Other) Lock()  {}
func (o *Other) Error() string { return "" }
func (o *Other) Run()   {}

func Lock()  {}
func Error() {}
func Run()   {}

type Repo struct {
	mu  sync.Mutex
	err error
	dot Widget
}

func (r *Repo) Load() {
	r.mu.Lock()
	r.err.Error()
	r.dot.Run()
}
`)
	caller := "app.(*Repo).Load"
	for _, declared := range []string{
		"app.(*Other).Lock", "app.(*Other).Error", "app.(*Other).Run",
		"app.Lock", "app.Error", "app.Run",
	} {
		if goHasCaller(g, declared, caller) {
			t.Errorf("name-based fallback edge from Load to %s", declared)
		}
		if _, ok := goEdgeKind(g, caller, declared); ok {
			t.Errorf("EdgeResolution recorded from Load to declared function %s", declared)
		}
	}
	allowed := map[string]bool{"sync.(Mutex).Lock": true, "app.(Widget).Run": true, "Error": true}
	for key := range g.EdgeResolutions {
		if !strings.HasPrefix(key, caller+"\x00") {
			continue
		}
		callee := strings.SplitN(key, "\x00", 3)[1]
		if !allowed[callee] {
			t.Errorf("EdgeResolution from Load to unexpected target %q", callee)
		}
	}
}
