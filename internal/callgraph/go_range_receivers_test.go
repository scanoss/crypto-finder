// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

const goRangeDecls = `package app

type Source interface{ Load() }

type remote struct{}

func (r *remote) Load() {}

type local struct{}

func (l local) Load() {}

type Cm struct{}

func (c *Cm) Get() {}
`

func goRangeExpectEdge(t *testing.T, g *CallGraph, caller, callee string, kind EdgeKind) {
	t.Helper()
	if !goHasCaller(g, callee, caller) {
		t.Fatalf("%s has no caller %s; callers=%v", callee, caller, g.Callers[callee])
	}
	if got, _ := goEdgeKind(g, caller, callee); got != kind {
		t.Errorf("edge %s -> %s kind = %q, want %q", caller, callee, got, kind)
	}
}

func goRangeExpectNoCaller(t *testing.T, g *CallGraph, callee, caller string) {
	t.Helper()
	if goHasCaller(g, callee, caller) {
		t.Errorf("%s must not be called by %s", callee, caller)
	}
}

func TestGoBuilder_RangeOverInterfaceSliceField(t *testing.T) {
	g := buildGoGraph(t, goRangeDecls+`
type Manager struct{ sources []Source }

func (m *Manager) LoadAll() {
	for _, source := range m.sources {
		source.Load()
	}
}
`)
	caller := "app.(*Manager).LoadAll"
	goRangeExpectEdge(t, g, caller, "app.(Source).Load", EdgeKindExact)
	goRangeExpectEdge(t, g, caller, "app.(*remote).Load", EdgeKindInterfaceDispatch)
}

func TestGoBuilder_RangeOverPointerSliceAndArrayFields(t *testing.T) {
	g := buildGoGraph(t, goRangeDecls+`
type Holder struct {
	cms  []*Cm
	arr  [4]*Cm
	lits [...]local
}

func (h *Holder) Each() {
	for _, c := range h.cms {
		c.Get()
	}
	for _, c := range h.arr {
		c.Get()
	}
	for _, l := range h.lits {
		l.Load()
	}
}
`)
	caller := "app.(*Holder).Each"
	goRangeExpectEdge(t, g, caller, "app.(*Cm).Get", EdgeKindExact)
	goRangeExpectEdge(t, g, caller, "app.(local).Load", EdgeKindExact)
}

func TestGoBuilder_RangeOverMapField(t *testing.T) {
	g := buildGoGraph(t, goRangeDecls+`
type Keyed struct{ id string }

func (k Keyed) Name() {}

type Registry struct {
	byName map[string]*Cm
	byKey  map[Keyed]Source
}

func (r *Registry) Each() {
	for _, c := range r.byName {
		c.Get()
	}
	for k, s := range r.byKey {
		k.Name()
		s.Load()
	}
}
`)
	caller := "app.(*Registry).Each"
	goRangeExpectEdge(t, g, caller, "app.(*Cm).Get", EdgeKindExact)
	goRangeExpectEdge(t, g, caller, "app.(Keyed).Name", EdgeKindExact)
	goRangeExpectEdge(t, g, caller, "app.(Source).Load", EdgeKindExact)
}

func TestGoBuilder_RangeOverTypedLocalAndParam(t *testing.T) {
	g := buildGoGraph(t, goRangeDecls+`
func FromVar() {
	var xs []*Cm
	for _, c := range xs {
		c.Get()
	}
}

func FromLiteral() {
	ys := []Source{&remote{}}
	for _, s := range ys {
		s.Load()
	}
}

func FromParam(zs map[string]*Cm) {
	for _, c := range zs {
		c.Get()
	}
}

func FromComposite() {
	for _, c := range []*Cm{{}} {
		c.Get()
	}
}
`)
	goRangeExpectEdge(t, g, "app.FromVar", "app.(*Cm).Get", EdgeKindExact)
	goRangeExpectEdge(t, g, "app.FromLiteral", "app.(Source).Load", EdgeKindExact)
	goRangeExpectEdge(t, g, "app.FromLiteral", "app.(*remote).Load", EdgeKindInterfaceDispatch)
	goRangeExpectEdge(t, g, "app.FromParam", "app.(*Cm).Get", EdgeKindExact)
	goRangeExpectEdge(t, g, "app.FromComposite", "app.(*Cm).Get", EdgeKindExact)
}

func TestGoBuilder_RangeOverTypedLocalsField(t *testing.T) {
	g := buildGoGraph(t, goRangeDecls+`
type Manager struct{ sources []Source }

func Run(m *Manager) {
	for _, s := range m.sources {
		s.Load()
	}
}

func RunLocal() {
	m := &Manager{}
	for _, s := range m.sources {
		s.Load()
	}
}
`)
	goRangeExpectEdge(t, g, "app.Run", "app.(Source).Load", EdgeKindExact)
	goRangeExpectEdge(t, g, "app.RunLocal", "app.(Source).Load", EdgeKindExact)
}

func TestGoBuilder_IndexedCollectionReceivers(t *testing.T) {
	g := buildGoGraph(t, goRangeDecls+`
type Manager struct {
	sources []Source
	byName  map[string]*Cm
}

func (m *Manager) First() {
	m.sources[0].Load()
	m.byName["a"].Get()
}

func Local(xs []*Cm) {
	xs[0].Get()
	for i := range xs {
		xs[i].Get()
	}
}
`)
	goRangeExpectEdge(t, g, "app.(*Manager).First", "app.(Source).Load", EdgeKindExact)
	goRangeExpectEdge(t, g, "app.(*Manager).First", "app.(*Cm).Get", EdgeKindExact)
	goRangeExpectEdge(t, g, "app.Local", "app.(*Cm).Get", EdgeKindExact)
}

func TestGoBuilder_RangeElementCrossPackage(t *testing.T) {
	root := t.TempDir()
	srcDir := filepath.Join(root, "rules")
	appDir := filepath.Join(root, "app")
	for _, d := range []string{srcDir, appDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(srcDir, "rules.go"): `package rules

type Remote struct{}

func (r *Remote) Load() {}
`,
		filepath.Join(appDir, "app.go"): `package app

import r "example.com/m/rules"

type Manager struct{ sources []*r.Remote }

func (m *Manager) LoadAll() {
	for _, s := range m.sources {
		s.Load()
	}
}
`,
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	g, err := NewBuilderForEcosystem("go", NewGoParser()).BuildFromDirectories([]PackageDir{
		{Dir: srcDir, ImportPath: "example.com/m/rules"},
		{Dir: appDir, ImportPath: "example.com/m/app"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	goRangeExpectEdge(t, g, "example.com/m/app.(*Manager).LoadAll", "example.com/m/rules.(*Remote).Load", EdgeKindExact)
}

func TestGoBuilder_RangeUntypedCollectionsStayUnresolved(t *testing.T) {
	g := buildGoGraph(t, goRangeDecls+`
type Manager struct {
	chans  chan *Cm
	anys   []any
	empty  []interface{}
	named  Cms
	funcs  []func()
}

type Cms []*Cm

func untyped() []*Cm { return nil }

func (m *Manager) Run(ch chan *Cm, cms Cms) {
	for c := range ch {
		c.Get()
	}
	for c := range m.chans {
		c.Get()
	}
	for _, a := range m.anys {
		a.Get()
	}
	for _, a := range m.empty {
		a.Get()
	}
	for _, c := range m.named {
		c.Get()
	}
	for _, c := range cms {
		c.Get()
	}
	for _, c := range untyped() {
		c.Get()
	}
	for _, c := range unknown {
		c.Get()
	}
	for i := range 3 {
		i.Get()
	}
	for i, c := range []*Cm{} {
		i.Get()
		_ = c
	}
}
`)
	goRangeExpectNoCaller(t, g, "app.(*Cm).Get", "app.(*Manager).Run")
}

func TestGoBuilder_RangeIndexVariableIsNotTheElement(t *testing.T) {
	g := buildGoGraph(t, goRangeDecls+`
type Manager struct{ cms []*Cm }

func (m *Manager) Run() {
	for i := range m.cms {
		i.Get()
	}
}
`)
	goRangeExpectNoCaller(t, g, "app.(*Cm).Get", "app.(*Manager).Run")
}

func TestGoBuilder_ShadowedRangeVariableStaysUnresolved(t *testing.T) {
	g := buildGoGraph(t, goRangeDecls+`
type Manager struct{ cms []*Cm }

type Other struct{}

func (o *Other) Get() {}

func mk() *Other { return nil }

func (m *Manager) Redeclared() {
	for _, c := range m.cms {
		c := mk()
		c.Get()
	}
}

func (m *Manager) Param() {
	for _, c := range m.cms {
		func(c *Other) { c.Get() }(nil)
	}
}

func (m *Manager) AfterLoop() {
	for _, c := range m.cms {
		_ = c
	}
	c := mk()
	c.Get()
}
`)
	goRangeExpectNoCaller(t, g, "app.(*Cm).Get", "app.(*Manager).Redeclared")
	goRangeExpectNoCaller(t, g, "app.(*Cm).Get", "app.(*Manager).Param")
	goRangeExpectNoCaller(t, g, "app.(*Cm).Get", "app.(*Manager).AfterLoop")
}

func TestGoBuilder_RangeFieldTwoDeclarationsDisagreeStayUnresolved(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"a.go": "package app\n\ntype A struct{}\n\nfunc (a *A) Get() {}\n\ntype B struct{}\n\nfunc (b *B) Get() {}\n\ntype M struct{ xs []*A }\n\nfunc (m *M) Run() {\n\tfor _, x := range m.xs {\n\t\tx.Get()\n\t}\n}\n",
		"c.go": "package app\n\ntype M struct{ xs []*B }\n",
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
		goRangeExpectNoCaller(t, g, callee, "app.(*M).Run")
	}
}

func TestGoBuilder_RangeInterfaceElementCrossPackage(t *testing.T) {
	g := buildGoTree(t, map[string]string{
		"rules/rules.go": "package rules\n\ntype Source interface{ Load() }\n",
		"impl/impl.go":   "package impl\n\ntype Remote struct{}\n\nfunc (r *Remote) Load() {}\n",
		"app/app.go":     "package app\n\nimport \"example.com/m/rules\"\n\ntype Manager struct{ sources []rules.Source }\n\nfunc (m *Manager) LoadAll() {\n\tfor _, s := range m.sources {\n\t\ts.Load()\n\t}\n}\n",
	})
	caller := "example.com/m/app.(*Manager).LoadAll"
	goRangeExpectEdge(t, g, caller, "example.com/m/rules.(Source).Load", EdgeKindExact)
	goRangeExpectEdge(t, g, caller, "example.com/m/impl.(*Remote).Load", EdgeKindInterfaceDispatch)
}

func TestGoBuilder_RangeAssignmentFormTypesOnlyInsideTheLoop(t *testing.T) {
	g := buildGoGraph(t, goRangeDecls+`
type Manager struct{ cms []*Cm }

type Other struct{}

func (o *Other) Get() {}

func (m *Manager) Run(c *Other) {
	var k int
	for k, c = range m.cms {
		c.Get()
	}
	c.Get()
	_ = k
}
`)
	goRangeExpectEdge(t, g, "app.(*Manager).Run", "app.(*Cm).Get", EdgeKindExact)
	goRangeExpectEdge(t, g, "app.(*Manager).Run", "app.(*Other).Get", EdgeKindExact)
}

func TestGoBuilder_RangeUnsupportedShapesStayUnresolved(t *testing.T) {
	g := buildGoGraph(t, goRangeDecls+`
import "iter"

func PtrArray(p *[4]*Cm) {
	for _, c := range p {
		c.Get()
	}
}

func Seq(seq iter.Seq[*Cm]) {
	for c := range seq {
		c.Get()
	}
}

func Nested(a [][]*Cm) {
	a[0][1].Get()
}
`)
	for _, caller := range []string{"app.PtrArray", "app.Seq", "app.Nested"} {
		goRangeExpectNoCaller(t, g, "app.(*Cm).Get", caller)
	}
}

func TestGoBuilder_RangeFuncLiteralParamShadowsOuterTypedVar(t *testing.T) {
	g := buildGoGraph(t, goRangeDecls+`
type Other struct{}

func (o *Other) Get() {}

func Run(c *Cm, mk func() *Other) {
	func(c *Other) { c.Get() }(mk())
}
`)
	goRangeExpectNoCaller(t, g, "app.(*Cm).Get", "app.Run")
}

func TestGoBuilder_RangeMapFieldOneVariableIsTheKey(t *testing.T) {
	g := buildGoGraph(t, goRangeDecls+`
type Keyed struct{}

func (k Keyed) Name() {}

type Registry struct {
	byKey map[Keyed]*Cm
	list  []*Cm
}

func (r *Registry) Keys() {
	for k := range r.byKey {
		k.Name()
	}
}

func (r *Registry) Indexes() {
	for i := range r.list {
		i.Get()
	}
}
`)
	goRangeExpectEdge(t, g, "app.(*Registry).Keys", "app.(Keyed).Name", EdgeKindExact)
	goRangeExpectNoCaller(t, g, "app.(*Cm).Get", "app.(*Registry).Indexes")
}

func TestGoBuilder_RangeRedeclaredFromIdentifierKeepsType(t *testing.T) {
	g := buildGoGraph(t, goRangeDecls+`
type Manager struct{ cms []*Cm }

func (m *Manager) Run() {
	for _, c := range m.cms {
		c := c
		go func() { c.Get() }()
	}
}
`)
	goRangeExpectEdge(t, g, "app.(*Manager).Run", "app.(*Cm).Get", EdgeKindExact)
}

func TestGoBuilder_RangeOverTypeParameterElementsStaysUnresolved(t *testing.T) {
	g := buildGoGraph(t, goRangeDecls+`
type Getter interface{ Get() }

func Each[T Getter](xs []T) {
	for _, x := range xs {
		x.Get()
	}
	xs[0].Get()
}

type Box struct{ items []string }

func (b *Box) Run() {
	for _, s := range b.items {
		s.Get()
	}
}
`)
	for _, k := range goCalleeKeys(g) {
		if k == "app.(T).Get" {
			t.Errorf("type parameter T qualified as a package type: %q", k)
		}
	}
	goRangeExpectNoCaller(t, g, "app.(Getter).Get", "app.Each")
	goRangeExpectNoCaller(t, g, "app.(*Cm).Get", "app.Each")
	goRangeExpectNoCaller(t, g, "app.(*Cm).Get", "app.(*Box).Run")
}
