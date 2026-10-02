// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
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
