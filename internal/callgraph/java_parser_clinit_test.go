package callgraph

import "testing"

// TestJavaParser_ClassInit_SyntheticClinitFunction verifies the recall fix for
// crypto findings that live OUTSIDE any method/constructor body: in a
// `static { ... }` initializer block or in a static `field_declaration`
// initializer.
//
// Before the fix such findings had no containing function (ContainingFunction
// returned false), so they surfaced downstream as a degenerate single-node call
// chain with a blank `{"function_name":"","file_path":""}` frame. The parser now
// emits ONE synthetic `<clinit>` FunctionDecl per class that has a static block
// or an initialized static field, spanning the whole class body, so those
// orphan findings map to a real function and become reachable from a class-init
// entry point.
func TestJavaParser_ClassInit_SyntheticClinitFunction(t *testing.T) {
	src := `package com.example;
class Sample {
    static final String OID = Registry.lookup("1.2.3");
    static {
        SomeUtil.register();
    }
    int plain;
    void doWork() {
        Cipher.getInstance("AES");
    }
}
`
	fns := parseJavaInline(t, src)

	clinit := findFunctionByName(fns, clinitMethodName)
	if clinit == nil {
		t.Fatal("synthetic <clinit> function not found")
	}

	// The clinit decl must span the whole class body so it is the loosest
	// (widest-span) container; tighter methods still win for their own lines.
	// class_body is lines 2..11 in source (1-based): "{" on line 2, "}" on line 11.
	if clinit.StartLine != 2 || clinit.EndLine != 11 {
		t.Errorf("<clinit> range = [%d,%d], want [2,11] (class body span)", clinit.StartLine, clinit.EndLine)
	}
	if clinit.FunctionType != javaFunctionTypeClassInit {
		t.Errorf("<clinit> FunctionType = %q, want %q", clinit.FunctionType, javaFunctionTypeClassInit)
	}
	if clinit.Visibility != VisibilityPrivate {
		t.Errorf("<clinit> Visibility = %q, want %q", clinit.Visibility, VisibilityPrivate)
	}
	if clinit.ID.Name != javaMethodWithArity(clinitMethodName, 0) {
		t.Errorf("<clinit> ID.Name = %q, want %q", clinit.ID.Name, javaMethodWithArity(clinitMethodName, 0))
	}

	method := findFunctionByName(fns, "doWork")
	if method == nil {
		t.Fatal("doWork method not found")
	}

	// Tightest-span selection: a line inside the static block (line 5) and a line
	// inside the field initializer (line 3) resolve to <clinit>; a line inside the
	// method body (line 9) resolves to the METHOD, not <clinit>.
	if !lineInRange(clinit, 5) {
		t.Errorf("static-block line 5 not in <clinit> range [%d,%d]", clinit.StartLine, clinit.EndLine)
	}
	if !lineInRange(clinit, 3) {
		t.Errorf("field-init line 3 not in <clinit> range [%d,%d]", clinit.StartLine, clinit.EndLine)
	}
	if tightest := tightestContainer(fns, 9); tightest != method {
		t.Errorf("line 9 (method body) tightest container = %v, want doWork", describeFn(tightest))
	}
	if tightest := tightestContainer(fns, 5); tightest != clinit {
		t.Errorf("line 5 (static block) tightest container = %v, want <clinit>", describeFn(tightest))
	}
	if tightest := tightestContainer(fns, 3); tightest != clinit {
		t.Errorf("line 3 (field init) tightest container = %v, want <clinit>", describeFn(tightest))
	}

	// <clinit> aggregates calls made in class-init context ONLY: the static-block
	// call and the field-initializer call — NOT the method's call.
	if findCallByMethod(clinit, "register", "") == nil {
		t.Error("<clinit> Calls missing static-block call SomeUtil.register()")
	}
	if findCallByMethod(clinit, "lookup", "") == nil {
		t.Error("<clinit> Calls missing field-initializer call Registry.lookup()")
	}
	if findCallByMethod(clinit, "getInstance", "") != nil {
		t.Error("<clinit> Calls wrongly include method-body call Cipher.getInstance()")
	}

	// <clinit> is an entry point: nothing in source calls it, so no FunctionDecl
	// in this analysis has an outgoing edge whose callee is <clinit>.
	for i := range fns {
		fn := &fns[i]
		for j := range fn.Calls {
			if BaseFunctionName(fn.Calls[j].Callee.Name) == clinitMethodName {
				t.Errorf("%s has an outgoing edge to <clinit>; it must have in-degree 0 (entry point)", fn.ID.Name)
			}
		}
	}
}

// TestJavaParser_ClassInit_NotEmittedWithoutInitializers verifies the synthetic
// <clinit> is NOT emitted for a class that has NO initializer code at all —
// neither a static_initializer block, an initialized static field, NOR an
// initialized instance field (avoids node-count blowup). A bare field with no
// initializer value contributes no class-init code.
func TestJavaParser_ClassInit_NotEmittedWithoutInitializers(t *testing.T) {
	src := `package com.example;
class Bare {
    int plain;
    String name;
    void doWork() {
        Cipher.getInstance("AES");
    }
}
`
	fns := parseJavaInline(t, src)
	if clinit := findFunctionByName(fns, clinitMethodName); clinit != nil {
		t.Errorf("class with no initializer code emitted a <clinit> at [%d,%d]; want none", clinit.StartLine, clinit.EndLine)
	}
}

// TestJavaParser_ClassInit_InstanceFieldInitializer is the BouncyCastle regression
// guard: crypto in an INSTANCE field initializer (e.g.
// `private final Foo agreement = new Bar();`) lives in the class body OUTSIDE any
// constructor's line range, so before the fix it had no containing function and
// surfaced downstream as a blank, reachable-but-empty frame. The synthetic
// <clinit> now folds instance-field initializers into the class-init context so
// such findings map to a real function spanning the class body and stay
// reachable from a class-init entry point. (JVM-semantically instance-field inits
// run in <init>, but for containment/reachability the class-init node is the
// correct catch-all for class-body code outside any method/constructor body.)
func TestJavaParser_ClassInit_InstanceFieldInitializer(t *testing.T) {
	src := `package com.example;
class Holder {
    private final Foo agreement = new Bar();
    public Holder() {}
    void work() {
        agreement.use();
    }
}
`
	fns := parseJavaInline(t, src)

	clinit := findFunctionByName(fns, clinitMethodName)
	if clinit == nil {
		t.Fatal("class with an instance-field object-creation initializer emitted no <clinit>; want one covering the field-init line")
	}

	// The instance-field initializer is on line 3; its tightest container must be
	// the <clinit>, not nil (the bug) — the constructor on line 4 spans only its
	// own body and does NOT cover the class-body field line.
	if !lineInRange(clinit, 3) {
		t.Errorf("instance-field-init line 3 not in <clinit> range [%d,%d]", clinit.StartLine, clinit.EndLine)
	}
	if tightest := tightestContainer(fns, 3); tightest != clinit {
		t.Errorf("line 3 (instance-field init) tightest container = %v, want <clinit>", describeFn(tightest))
	}

	// The field-initializer call (new Bar()) belongs to <clinit>: an object
	// creation surfaces as an <init> constructor call whose Raw names the type.
	if findCallByMethod(clinit, constructorMethodName, "Bar") == nil {
		t.Error("<clinit> Calls missing instance-field-initializer object creation new Bar()")
	}
}

func lineInRange(fn *FunctionDecl, line int) bool {
	return fn != nil && line >= fn.StartLine && line <= fn.EndLine
}

// tightestContainer mirrors graphfrag.Fragment.ContainingFunction's tightest-span
// selection over a slice of FunctionDecls (single file, so file path is uniform).
func tightestContainer(fns []FunctionDecl, line int) *FunctionDecl {
	var best *FunctionDecl
	bestSpan := 0
	for i := range fns {
		fn := &fns[i]
		if line < fn.StartLine || line > fn.EndLine {
			continue
		}
		span := fn.EndLine - fn.StartLine
		if best == nil || span < bestSpan {
			best = fn
			bestSpan = span
		}
	}
	return best
}

func describeFn(fn *FunctionDecl) string {
	if fn == nil {
		return "<nil>"
	}
	return fn.ID.Name
}
