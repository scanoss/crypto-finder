// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildNodeFiles(t *testing.T, files map[string]string) *CallGraph {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := NewBuilderForEcosystem(ecosystemNode, NewNodeParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

// graphFunction finds the function declared as pkg.name or pkg.Type.name.
func graphFunction(t *testing.T, graph *CallGraph, pkg, typ, name string) (string, *FunctionDecl) {
	t.Helper()
	key := FunctionID{Package: pkg, Type: typ, Name: name}.String()
	fn := graph.Functions[key]
	if fn == nil {
		t.Fatalf("function %s not declared", key)
	}
	return key, fn
}

// calleeOnLine returns the callee the one call to method on a line resolved to.
func calleeOnLine(t *testing.T, fn *FunctionDecl, method string) FunctionID {
	t.Helper()
	var found []FunctionID
	for i := range fn.Calls {
		if fn.Calls[i].Callee.Name == method {
			found = append(found, fn.Calls[i].Callee)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: calls to %s = %v, want exactly one", fn.ID.String(), method, found)
	}
	return found[0]
}

const typedReceiverModule = `import { Imported } from './lib'
import Def from './def'
import * as ns from './lib'
import { Foreign } from 'some-library'

export class Helper { go() { return 1 } other() { return 2 } }
class Unrelated { other() { return 3 } }
interface Shape { go(): number }

const shared = new Helper()
let rebound = new Helper()
rebound = makeUnknown()

function make(): Helper { return new Helper() }

export function localNew() { const x = new Helper(); return x.go() }
export function moduleVar() { return shared.go() }
export function inlineNew() { return new Helper().go() }
export function paramType(p: Helper) { return p.go() }
export function varAnnotation() { const x: Helper = makeUnknown(); return x.go() }
export function returnType() { const t = make(); return t.go() }
export function importedClass() { const x = new Imported(); return x.go() }
export function defaultClass() { const x = new Def(); return x.go() }
export function namespaceClass() { const x = new ns.Imported(); return x.go() }
export function otherMethod() { const x = new Helper(); return x.other() }

export function reboundLocal() { let x = new Helper(); x = makeUnknown(); return x.go() }
export function reboundInNested() { const x = new Helper(); const f = () => { x = makeUnknown() }; f(); return x.go() }
export function reboundModule() { return rebound.go() }
export function shadowedModuleVar(shared: any) { return shared.go() }
export function destructuredShadow() { const { shared } = makeUnknown(); return shared.go() }
export function anyType(p: any) { return p.go() }
export function unionType(p: Helper | null) { return p.go() }
export function genericType(p: Box<Helper>) { return p.go() }
export function interfaceType(p: Shape) { return p.go() }
export function unannotated(p) { return p.go() }
export function libraryClass() { const x = new Foreign(); return x.go() }
export function undeclaredClass() { const x = new Missing(); return x.go() }
export function conflictingDeclarations(c: boolean) {
  if (c) { const x = new Helper(); x.go() } else { const x = new Unrelated(); x.go() }
}

export class Svc {
  private declared: Helper
  private prebuilt = new Helper()
  private fromCtor: Helper
  private assigned
  private mixed
  private unknown: any
  static staticField = new Helper()
  constructor(private param: Helper, other: Helper) {
    this.fromCtor = other
    this.assigned = new Helper()
    this.mixed = new Helper()
  }
  later() { this.mixed = makeUnknown() }
  viaDeclared() { return this.declared.go() }
  viaPrebuilt() { return this.prebuilt.go() }
  viaParamProperty() { return this.param.go() }
  viaCtorParam() { return this.fromCtor.go() }
  viaAssigned() { return this.assigned.go() }
  viaMixed() { return this.mixed.go() }
  viaUnknown() { return this.unknown.go() }
  viaStatic() { return this.staticField.go() }
}
`

func TestNodeTypedReceivers(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{
		"lib.ts": "export class Imported { go() { return 1 } }\n",
		"def.ts": "export default class Def { go() { return 1 } }\n",
		"m.ts":   typedReceiverModule,
	})

	helper := FunctionID{Package: "app/m", Type: "Helper", Name: "go"}
	cases := []struct {
		fn     string
		owner  string
		method string
		want   FunctionID
	}{
		{"localNew", "", "go", helper},
		{"moduleVar", "", "go", helper},
		{"inlineNew", "", "go", helper},
		{"paramType", "", "go", helper},
		{"varAnnotation", "", "go", helper},
		{"returnType", "", "go", helper},
		{"importedClass", "", "go", FunctionID{Package: "app/lib", Type: "Imported", Name: "go"}},
		{"defaultClass", "", "go", FunctionID{Package: "app/def", Type: "Def", Name: "go"}},
		{"namespaceClass", "", "go", FunctionID{Package: "app/lib", Type: "Imported", Name: "go"}},
		// The method is looked up on the declared class, never by name alone.
		{"otherMethod", "", "other", FunctionID{Package: "app/m", Type: "Helper", Name: "other"}},
		{"viaDeclared", "Svc", "go", helper},
		{"viaPrebuilt", "Svc", "go", helper},
		{"viaParamProperty", "Svc", "go", helper},
		{"viaCtorParam", "Svc", "go", helper},
		{"viaAssigned", "Svc", "go", helper},
	}
	for _, tc := range cases {
		t.Run(tc.fn, func(t *testing.T) {
			_, fn := graphFunction(t, graph, "app/m", tc.owner, tc.fn)
			if got := calleeOnLine(t, fn, tc.method); got != tc.want {
				t.Fatalf("callee = %+v, want %+v", got, tc.want)
			}
		})
	}

	// None of these declares a type the source settles: the call keeps the
	// untyped callee and links to no class.
	for _, tc := range []struct{ fn, owner string }{
		{"reboundLocal", ""},
		{"reboundInNested", ""},
		{"reboundModule", ""},
		{"shadowedModuleVar", ""},
		{"destructuredShadow", ""},
		{"anyType", ""},
		{"unionType", ""},
		{"genericType", ""},
		{"interfaceType", ""},
		{"unannotated", ""},
		{"libraryClass", ""},
		{"undeclaredClass", ""},
		{"viaMixed", "Svc"},
		{"viaUnknown", "Svc"},
		{"viaStatic", "Svc"},
	} {
		t.Run("untyped/"+tc.fn, func(t *testing.T) {
			_, fn := graphFunction(t, graph, "app/m", tc.owner, tc.fn)
			for i := range fn.Calls {
				if fn.Calls[i].Callee.Name == "go" && fn.Calls[i].Callee.Type != "" {
					t.Fatalf("typed %+v, want untyped", fn.Calls[i].Callee)
				}
			}
		})
	}
	t.Run("untyped/conflictingDeclarations", func(t *testing.T) {
		_, fn := graphFunction(t, graph, "app/m", "", "conflictingDeclarations")
		for i := range fn.Calls {
			if fn.Calls[i].Callee.Type != "" {
				t.Fatalf("typed %+v, want untyped", fn.Calls[i].Callee)
			}
		}
	})
}

// The typed call becomes an exact edge to the declared class's method, and a
// method of the same name on another class gains none.
func TestNodeTypedReceiverEdgeIsExact(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{
		"m.ts": typedReceiverModule,
		"other.ts": `export class Helper { go() { return 9 } }
export function lookalike() { return 1 }
`,
	})
	caller, _ := graphFunction(t, graph, "app/m", "", "localNew")
	target, _ := graphFunction(t, graph, "app/m", "Helper", "go")
	if !hasCaller(graph, target, caller) {
		t.Fatalf("Callers[%s] = %v, want %s", target, graph.Callers[target], caller)
	}
	if kind := edgeKindOf(graph, caller, target); kind != EdgeKindExact {
		t.Fatalf("edge kind = %q, want %q", kind, EdgeKindExact)
	}
	// A same-named class in a module the file does not import is not the target.
	foreign, _ := graphFunction(t, graph, "app/other", "Helper", "go")
	if callers := graph.Callers[foreign]; len(callers) != 0 {
		t.Fatalf("Callers[%s] = %v, want none", foreign, callers)
	}
	unrelated := FunctionID{Package: "app/m", Type: "Unrelated", Name: "other"}.String()
	if callers := graph.Callers[unrelated]; len(callers) != 0 {
		t.Fatalf("Callers[%s] = %v: a method name alone links no class", unrelated, callers)
	}
}

func TestNodeImportedSingleton(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{
		"svc/ProjectService.ts": `export class ProjectService { createProject() { return 1 } }
export const projectService = new ProjectService()
export const annotated: ProjectService = makeIt()
export let mutable = new ProjectService()
`,
		"svc/Other.ts": `class Other { make() { return 2 } }
export default new Other()
`,
		"svc/Alias.ts": `import { ProjectService } from './ProjectService'
const inst = new ProjectService()
export default inst
`,
		"svc/Lookalike.ts": `export class ProjectService { createProject() { return 3 } }
`,
		"web/handlers.ts": `import { projectService, mutable } from '../svc/ProjectService'
import other from '../svc/Other'
import aliased from '../svc/Alias'
import * as service from '../svc/ProjectService'
export function viaNamed() { return projectService.createProject() }
export function viaDefault() { return other.make() }
export function viaDefaultVar() { return aliased.createProject() }
export function viaNamespace() { return service.projectService.createProject() }
export function viaMutable() { return mutable.createProject() }
export function viaClassName() { return service.ProjectService.createProject() }
`,
	})

	service, _ := graphFunction(t, graph, "app/svc/ProjectService", "ProjectService", "createProject")
	otherMake, _ := graphFunction(t, graph, "app/svc/Other", "Other", "make")
	lookalike, _ := graphFunction(t, graph, "app/svc/Lookalike", "ProjectService", "createProject")
	reaches := func(fn, target string) bool {
		caller, _ := graphFunction(t, graph, "app/web/handlers", "", fn)
		return hasCaller(graph, target, caller)
	}
	for fn, target := range map[string]string{
		"viaNamed":      service,
		"viaDefault":    otherMake,
		"viaDefaultVar": service,
		"viaNamespace":  service,
	} {
		if !reaches(fn, target) {
			t.Errorf("%s does not reach %s", fn, target)
		}
	}
	// A `let` export may be rebound, and a class named by its import is no instance.
	for _, fn := range []string{"viaMutable", "viaClassName"} {
		if reaches(fn, service) {
			t.Errorf("%s reaches %s, want no edge", fn, service)
		}
	}
	if callers := graph.Callers[lookalike]; len(callers) != 0 {
		t.Errorf("Callers[%s] = %v, want none", lookalike, callers)
	}
}

// A module path two files share names no instance.
func TestNodeSingletonOfAmbiguousModuleResolvesToNothing(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{
		"a/box.ts": "export class A { run() { return 1 } }\nexport const box = new A()\n",
		"a/box.js": "export class B { run() { return 2 } }\nexport const box = new B()\n",
		"b/use.ts": "import { box } from '../a/box'\nexport function f() { return box.run() }\n",
	})
	caller, _ := graphFunction(t, graph, "app/b/use", "", "f")
	for key, fn := range graph.Functions {
		if fn.ID.Name == "run" && hasCaller(graph, key, caller) {
			t.Errorf("f reaches %s, want no edge: two files make the module ambiguous", key)
		}
	}
}

// A call on a value another module's function returns takes that function's
// declared return class, and an abstract class reaches the overrides of its
// subclasses.
func TestNodeReturnTypedReceiverFansOutToOverrides(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{
		"task/Base.ts": `export abstract class Task { abstract run(): string }
export function make(): Task { return new Impl() }
class Impl extends Task { run() { return 'x' } }
`,
		"impl/Sub.ts": `import { Task } from '../task/Base'
export class Sub extends Task { run() { return 'sub' } }
export class Unrelated { run() { return 'no' } }
`,
		"app/main.ts": `import { make, Task } from '../task/Base'
export function exec() { const t = make(); return t.run() }
export function declared(t: Task) { return t.run() }
`,
	})
	caller, _ := graphFunction(t, graph, "app/app/main", "", "exec")
	declared, _ := graphFunction(t, graph, "app/app/main", "", "declared")
	sub, _ := graphFunction(t, graph, "app/impl/Sub", "Sub", "run")
	impl, _ := graphFunction(t, graph, "app/task/Base", "Impl", "run")
	unrelated, _ := graphFunction(t, graph, "app/impl/Sub", "Unrelated", "run")
	for _, from := range []string{caller, declared} {
		for _, target := range []string{sub, impl} {
			if !hasCaller(graph, target, from) {
				t.Errorf("%s does not reach %s", from, target)
				continue
			}
			if kind := edgeKindOf(graph, from, target); kind != EdgeKindInterfaceDispatch {
				t.Errorf("%s -> %s kind = %q, want %q", from, target, kind, EdgeKindInterfaceDispatch)
			}
		}
		if hasCaller(graph, unrelated, from) {
			t.Errorf("%s reaches the unrelated class's run", from)
		}
	}
}

func TestNodeAbstractClassDeclaresItsMethods(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{
		"a.ts": `export abstract class Base {
  describe() { return this.name() }
  abstract name(): string
}
class Leaf extends Base { name() { return 'leaf' } }
export function use() { return new Leaf().describe() }
`,
	})
	describe, _ := graphFunction(t, graph, "app/a", "Base", "describe")
	caller, _ := graphFunction(t, graph, "app/a", "", "use")
	if !hasCaller(graph, describe, caller) {
		t.Fatalf("Callers[%s] = %v, want %s", describe, graph.Callers[describe], caller)
	}
	leafName, _ := graphFunction(t, graph, "app/a", "Leaf", "name")
	if !hasCaller(graph, leafName, describe) {
		t.Fatalf("Callers[%s] = %v: this.name() in the abstract class reaches the override", leafName, graph.Callers[leafName])
	}
}

// callbackCallee returns the callee of the one call to method made by an
// anonymous function of the module pkg.
func callbackCallee(t *testing.T, graph *CallGraph, pkg, method string) FunctionID {
	t.Helper()
	var found []FunctionID
	for _, fn := range graph.Functions {
		if fn.ID.Package != pkg || !strings.HasPrefix(fn.ID.Name, "<anonymous>@") {
			continue
		}
		for i := range fn.Calls {
			if fn.Calls[i].Callee.Name == method {
				found = append(found, fn.Calls[i].Callee)
			}
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: callback calls to %s = %v, want exactly one", pkg, method, found)
	}
	return found[0]
}

// A module variable is not the receiver in a nested function when an
// enclosing function declares the name, whatever the declaration is.
func TestNodeNestedFunctionDoesNotReadShadowedModuleVar(t *testing.T) {
	t.Parallel()
	const header = "class A { m() { return 1 } }\nclass B { m() { return 2 } }\nconst x = new A()\n"
	graph := buildNodeFiles(t, map[string]string{
		"local.ts":      header + "export function f(items: number[]) { const x = makeUnknown(); items.forEach(() => x.m()) }\n",
		"typedlocal.ts": header + "export function f(items: number[]) { const x = new B(); items.forEach(() => x.m()) }\n",
		"param.ts":      header + "export function f(x: any, items: number[]) { items.forEach(function () { x.m() }) }\n",
		"single.ts":     header + "export function f() { return [1].map(x => x.m()) }\n",
		"deep.ts":       header + "export function f(items: number[]) { const x = makeUnknown(); return items.map(() => items.map(() => x.m())) }\n",
		"module.ts":     header + "export function f(items: number[]) { items.forEach(() => x.m()) }\n",
		"own.ts":        header + "export function f(items: number[]) { items.forEach(() => { const x = new B(); x.m() }) }\n",
	})
	aM := FunctionID{Package: "app/module", Type: "A", Name: "m"}
	if got := callbackCallee(t, graph, "app/module", "m"); got != aM {
		t.Errorf("module variable read in a callback: callee = %+v, want %+v", got, aM)
	}
	if got := callbackCallee(t, graph, "app/own", "m"); got != (FunctionID{Package: "app/own", Type: "B", Name: "m"}) {
		t.Errorf("own local of the callback: callee = %+v, want B.m", got)
	}
	for _, pkg := range []string{"local", "typedlocal", "param", "single", "deep"} {
		if got := callbackCallee(t, graph, "app/"+pkg, "m"); got.Type != "" {
			t.Errorf("%s: callback typed %+v, want untyped: an enclosing function declares x", pkg, got)
		}
	}
}

// A default import is named by the importer, so its class is the one the
// module exports by default, not the class that shares the local name.
func TestNodeDefaultImportResolvesTheDefaultExportClass(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{
		"a.ts": `export default class Bar { m() { return 1 } }
export class Foo { m() { return 2 } }
`,
		"viaident.ts": `class Real { m() { return 3 } }
class Foo { m() { return 4 } }
export default Real
`,
		"nodefault.ts": `export class Foo { m() { return 5 } }
export const value = 1
`,
		"use.ts": `import Foo from './a'
import Aliased from './viaident'
import Missing from './nodefault'
import { default as Named } from './a'
export function wrongName() { const x = new Foo(); return x.m() }
export function identExport() { const x = new Aliased(); return x.m() }
export function noDefaultClass() { const x = new Missing(); return x.m() }
export function defaultAsNamed() { const x = new Named(); return x.m() }
export function annotated(p: Foo) { return p.m() }
`,
	})
	cases := []struct {
		fn   string
		want FunctionID
	}{
		{"wrongName", FunctionID{Package: "app/a", Type: "Bar", Name: "m"}},
		{"identExport", FunctionID{Package: "app/viaident", Type: "Real", Name: "m"}},
		{"defaultAsNamed", FunctionID{Package: "app/a", Type: "Bar", Name: "m"}},
		{"annotated", FunctionID{Package: "app/a", Type: "Bar", Name: "m"}},
	}
	for _, tc := range cases {
		_, fn := graphFunction(t, graph, "app/use", "", tc.fn)
		if got := calleeOnLine(t, fn, "m"); got != tc.want {
			t.Errorf("%s: callee = %+v, want %+v", tc.fn, got, tc.want)
		}
	}
	_, fn := graphFunction(t, graph, "app/use", "", "noDefaultClass")
	if got := calleeOnLine(t, fn, "m"); got.Type != "" {
		t.Errorf("noDefaultClass: callee = %+v, want untyped", got)
	}
	wrong, _ := graphFunction(t, graph, "app/a", "Foo", "m")
	if callers := graph.Callers[wrong]; len(callers) != 0 {
		t.Errorf("Callers[%s] = %v, want none: Foo is the local name of Bar", wrong, callers)
	}
}

// Only a function declared at the top level is a module function whose return
// class a call can read.
func TestNodeNestedFunctionDeclarationIsNoModuleFunction(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{
		"m.ts": `class Helper { go() { return 1 } }
export function outer() {
  function make(): Helper { return new Helper() }
  return make().go()
}
export function other() { const t = make(); return t.go() }
`,
	})
	_, fn := graphFunction(t, graph, "app/m", "", "other")
	if got := calleeOnLine(t, fn, "go"); got.Type != "" {
		t.Fatalf("other: callee = %+v, want untyped: make is declared inside outer only", got)
	}
}

// A class field typed from its initialiser stops being typed when code outside
// the class assigns that field, in any module. An annotation keeps its type.
func TestNodeInferredFieldReassignedOutsideClassIsUntyped(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{
		"svc.ts": `export class A { go() { return 1 } }
export class B { go() { return 2 } }
export class Svc {
  h = new A()
  kept: A = new A()
  free = new A()
  viaH() { return this.h.go() }
  viaKept() { return this.kept.go() }
  viaFree() { return this.free.go() }
}
`,
		"other.ts": `import { Svc, B } from './svc'
export function swap(svc: Svc) { svc.h = new B(); svc.kept = new B() }
`,
	})
	for field, wantTyped := range map[string]bool{"viaH": false, "viaKept": true, "viaFree": true} {
		_, fn := graphFunction(t, graph, "app/svc", "Svc", field)
		got := calleeOnLine(t, fn, "go")
		if typed := got.Type != ""; typed != wantTyped {
			t.Errorf("%s: callee = %+v, typed = %v, want %v", field, got, typed, wantTyped)
		}
	}
}

// Two modules each declare a class of the same name: a name resolves to the
// class of its own module or of the module it imports, never to the other.
func TestNodeSameClassNameInTwoModules(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{
		"a.ts": "export class Helper { go() { return 1 } }\nexport function useA() { return new Helper().go() }\n",
		"b.ts": "export class Helper { go() { return 2 } }\nexport function useB() { return new Helper().go() }\n",
		"c.ts": "import { Helper } from './b'\nexport function useC() { const h = new Helper(); return h.go() }\n",
	})
	for fn, pkg := range map[string]string{"useA": "app/a", "useB": "app/b", "useC": "app/c"} {
		want := FunctionID{Package: "app/a", Type: "Helper", Name: "go"}
		if fn != "useA" {
			want.Package = "app/b"
		}
		_, decl := graphFunction(t, graph, pkg, "", fn)
		if got := calleeOnLine(t, decl, "go"); got != want {
			t.Errorf("%s: callee = %+v, want %+v", fn, got, want)
		}
	}
}

// `var` is function scoped: a use before the declaration, or outside the block
// that holds it, still reads the local and never the module variable.
func TestNodeVarHoistingShadowsModuleVar(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{
		"m.ts": `class A { go() { return 1 } }
class B { go() { return 2 } }
const shared = new A()
export function beforeDeclaration() { shared.go(); var shared = makeUnknown() }
export function outsideBlock(c: boolean) { if (c) { var shared = new B() } return shared.go() }
export function beforeTypedDeclaration() { shared.go(); var shared = new B() }
export function moduleLevel() { return shared.go() }
`,
	})
	for fn, want := range map[string]FunctionID{
		"beforeDeclaration":      {},
		"outsideBlock":           {Package: "app/m", Type: "B", Name: "go"},
		"beforeTypedDeclaration": {Package: "app/m", Type: "B", Name: "go"},
		"moduleLevel":            {Package: "app/m", Type: "A", Name: "go"},
	} {
		_, decl := graphFunction(t, graph, "app/m", "", fn)
		got := calleeOnLine(t, decl, "go")
		if want == (FunctionID{}) {
			if got.Type != "" {
				t.Errorf("%s: callee = %+v, want untyped", fn, got)
			}
			continue
		}
		if got != want {
			t.Errorf("%s: callee = %+v, want %+v", fn, got, want)
		}
	}
}

// A subclass outside the callee's namespace root is an override only when its
// bases, resolved through imports, reach the callee's class.
func TestNodeCrossRootOverrideNeedsImportProof(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{
		"task/Task.ts": "export abstract class Task { abstract run(): string }\n",
		"proven/Sub.ts": `import { Task } from '../task/Task'
export class Sub extends Task { run() { return 'sub' } }
`,
		"proven/Deep.ts": `import { Sub } from './Sub'
export class Deep extends Sub { run() { return 'deep' } }
`,
		"library/Sub.ts": `import { Task } from 'some-library'
export class LibrarySub extends Task { run() { return 'lib' } }
`,
		"dup/Sub.ts": `import { Task } from 'some-library'
function inner() { class Dup { run() { return 'inner' } } return Dup }
export class Dup extends Task { run() { return 'dup' } }
`,
		"unproven/Sub.ts": `export class Unrelated { run() { return 'no' } }
export class Mixin extends mixin(Unrelated) { run() { return 'mixin' } }
`,
		"app/main.ts": `import { Task } from '../task/Task'
export function exec(t: Task) { return t.run() }
`,
	})
	caller, _ := graphFunction(t, graph, "app/app/main", "", "exec")
	for _, tc := range []struct {
		pkg, typ string
		want     bool
	}{
		{"app/proven/Sub", "Sub", true},
		{"app/proven/Deep", "Deep", true},
		{"app/library/Sub", "LibrarySub", false},
		{"app/dup/Sub", "Dup", false},
		{"app/unproven/Sub", "Unrelated", false},
		{"app/unproven/Sub", "Mixin", false},
	} {
		target, _ := graphFunction(t, graph, tc.pkg, tc.typ, "run")
		if got := hasCaller(graph, target, caller); got != tc.want {
			t.Errorf("exec reaches %s.%s = %v, want %v", tc.pkg, tc.typ, got, tc.want)
		}
		if tc.want {
			if kind := edgeKindOf(graph, caller, target); kind != EdgeKindInterfaceDispatch {
				t.Errorf("%s.%s: edge kind = %q, want %q", tc.pkg, tc.typ, kind, EdgeKindInterfaceDispatch)
			}
		}
	}
	for key, fn := range graph.Functions {
		if fn.ID.Name == "run" && hasCaller(graph, key, caller) && edgeKindOf(graph, caller, key) == EdgeKindNameOnly {
			t.Errorf("exec reaches %s by name only across roots", key)
		}
	}
}

// A type that declares no method, in a language whose parser records source
// supertypes, is not a type a simple base name can denote: only Node classes
// are admitted there.
func TestMethodlessSourceSupertypeDoesNotCompeteForSimpleBaseNames(t *testing.T) {
	t.Parallel()
	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			"q.Marker.run": {ID: FunctionID{Package: "q", Type: "Marker", Name: "run"}},
			"p.Child.run": {
				ID:         FunctionID{Package: "p", Type: "Child", Name: "run"},
				OwnerBases: []string{"Marker"},
			},
		},
		SourceSupertypes: map[string][]string{"other.Marker": {}},
	}
	h := newDispatchHierarchy(graph)
	if !h.isSubtype("p.Child", "q.Marker") {
		t.Fatalf("parents of p.Child = %v, want q.Marker: the methodless other.Marker is no Node class", h.parents["p.Child"])
	}
}
