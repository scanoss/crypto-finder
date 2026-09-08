// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// propagatePythonAssignedVarTypes used to take a variable's type ONLY from an
// in-graph FunctionDecl's ReturnType. That cannot reach a DEPENDENCY's factory:
// when a consumer's own code is the scanned tree, the library's FunctionDecl is
// not in graph.Functions at all, so the lookup returned nil and no binding was
// recorded.
//
// OLD BEHAVIOR, measured on an exported call graph before the change:
//
//	sig = PrivateKey(secret).sign(msg)   -> coincurve.PrivateKey.sign   (resolved)
//	key = PrivateKey(secret)             -> coincurve.PrivateKey.<init> (resolved)
//	sig = key.sign(msg)                  -> <module>.key.sign           (NOT resolved)
//
// NEW BEHAVIOR: the two-line form resolves the same as the chained one. The
// same split was measured on the already-merged `ecdsa` contract, so this is an
// ecosystem-wide gap rather than one library's, and closing it makes the
// operation entries of every Python contract reachable for the call shape real
// code actually writes.
//
// The in-graph decl still wins: the KB is consulted only where the old code
// returned nothing, so no result that already resolved can change. That is what
// TestPythonAssignedVarTypes_InGraphDeclStillWins pins.

// pythonPropagationGraph parses src and runs the propagation pass with the
// supplied KB, returning the graph so callers can assert on rewritten callees.
func pythonPropagationGraph(t *testing.T, src string, kb *contracts.KnowledgeBase) *CallGraph {
	t.Helper()
	fns := parsePythonInline(t, src)
	graph := &CallGraph{Functions: make(map[string]*FunctionDecl)}
	for i := range fns {
		fn := fns[i]
		graph.Functions[fn.ID.String()] = &fn
	}
	propagatePythonAssignedVarTypes(graph, kb)
	return graph
}

func pythonEmbeddedKB(t *testing.T) *contracts.KnowledgeBase {
	t.Helper()
	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"python\"): %v", err)
	}
	return kb
}

// assertPythonCallee finds the call to methodName inside funcName and asserts
// its rewritten Callee and ResolvedReceiverType.
func assertPythonCallee(t *testing.T, graph *CallGraph, funcName, methodName string, want FunctionID, wantReceiver string) {
	t.Helper()
	fn := graph.Functions[FunctionID{Package: "mypkg", Name: funcName}.String()]
	if fn == nil {
		t.Fatalf("%s not found in graph", funcName)
	}
	call := findPythonCallByMethod(fn, methodName)
	if call == nil {
		t.Fatalf("%s: call to %s not found", funcName, methodName)
	}
	if call.Callee != want {
		t.Errorf("%s: %s Callee = %+v, want %+v", funcName, methodName, call.Callee, want)
	}
	if call.ResolvedReceiverType != wantReceiver {
		t.Errorf("%s: %s ResolvedReceiverType = %q, want %q",
			funcName, methodName, call.ResolvedReceiverType, wantReceiver)
	}
}

// TestPythonAssignedVarTypes_ContractFactoryTypesALocal is the new behavior,
// in the shape real consumer code writes: construct into a local, then call a
// method on it on the next line.
func TestPythonAssignedVarTypes_ContractFactoryTypesALocal(t *testing.T) {
	t.Parallel()

	src := `from coincurve import PrivateKey, PublicKey

SECRET = b"x"
MESSAGE = b"m"

def sign_it():
    key = PrivateKey(SECRET)
    sig = key.sign(MESSAGE)
    return sig

def verify_it(sig):
    pub = PublicKey.from_secret(SECRET)
    ok = pub.verify(sig, MESSAGE)
    return ok
`
	graph := pythonPropagationGraph(t, src, pythonEmbeddedKB(t))

	assertPythonCallee(t, graph, "sign_it", "sign",
		FunctionID{Package: "coincurve", Type: "PrivateKey", Name: "sign"}, "PrivateKey")
	assertPythonCallee(t, graph, "verify_it", "verify",
		FunctionID{Package: "coincurve", Type: "PublicKey", Name: "verify"}, "PublicKey")
}

// TestPythonAssignedVarTypes_DeepModuleSpelling pins the second module
// spelling. `coincurve.keys.PrivateKey(secret)` is a MODULE-ATTRIBUTE call, so
// its callee has an empty Type and the key carries no `.<init>` segment — a
// different KB key from the imported-name form above, and the package's own
// tests use this one.
func TestPythonAssignedVarTypes_DeepModuleSpelling(t *testing.T) {
	t.Parallel()

	src := `import coincurve.keys

SECRET = b"x"
MESSAGE = b"m"

def sign_deep():
    key = coincurve.keys.PrivateKey(SECRET)
    sig = key.sign(MESSAGE)
    return sig
`
	graph := pythonPropagationGraph(t, src, pythonEmbeddedKB(t))

	assertPythonCallee(t, graph, "sign_deep", "sign",
		FunctionID{Package: "coincurve.keys", Type: "PrivateKey", Name: "sign"}, "PrivateKey")
}

// TestPythonAssignedVarTypes_KBLookupUsesTheParenFreeFQN is a regression guard
// on the key SHAPE, and it is the assertion that caught the first version of
// this change doing nothing.
//
// FunctionID.String() renders a type-qualified id as "pkg.(Type).Name" — with
// parentheses — while the KB is keyed "pkg.Type.Name". Looking the KB up with
// the String() form resolves nothing for any METHOD or CONSTRUCTOR while still
// working for a module-level function, so the deep-module test above would have
// passed and this one would not. A wrong key is worse than a missing one: it
// loads, it looks like data, and it joins nothing.
func TestPythonAssignedVarTypes_KBLookupUsesTheParenFreeFQN(t *testing.T) {
	t.Parallel()

	src := `from coincurve import PrivateKey

SECRET = b"x"

def ctor():
    key = PrivateKey(SECRET)
    return key
`
	fns := parsePythonInline(t, src)
	fn := findPythonFuncByName(fns, "ctor")
	if fn == nil {
		t.Fatal("ctor not found")
	}
	call := findPythonCallByMethod(fn, "<init>")
	if call == nil {
		t.Fatal("constructor call not found")
	}

	if got, want := call.Callee.String(), "coincurve.(PrivateKey).<init>"; got != want {
		t.Fatalf("FunctionID.String() = %q, want %q — if this changed, "+
			"pythonCallFQN must change with it", got, want)
	}
	if got, want := pythonCallFQN(call), "coincurve.PrivateKey.<init>"; got != want {
		t.Errorf("pythonCallFQN = %q, want %q", got, want)
	}

	kb := pythonEmbeddedKB(t)
	if len(kb.ContractsForTolerant(pythonCallFQN(call), len(call.Arguments))) == 0 {
		t.Error("the paren-free FQN does not resolve in the KB")
	}
	if len(kb.ContractsForTolerant(call.Callee.String(), len(call.Arguments))) != 0 {
		t.Error("the parenthesised String() form resolves in the KB — the two " +
			"key shapes have converged and this guard is now misleading")
	}
}

// TestPythonAssignedVarTypes_ArityToleranceApplies pins that the KB path uses
// the same tolerant lookup the contract resolver uses. The contract declares
// `<init>` at arity 0 (the generation form) while this call site passes one
// argument, and Python's default arguments and kwargs make that mismatch the
// normal case rather than the exception.
func TestPythonAssignedVarTypes_ArityToleranceApplies(t *testing.T) {
	t.Parallel()

	src := `from coincurve import PrivateKey
import coincurve.context

SECRET = b"x"
MESSAGE = b"m"

def two_args():
    key = PrivateKey(SECRET, coincurve.context.GLOBAL_CONTEXT)
    sig = key.sign(MESSAGE)
    return sig
`
	graph := pythonPropagationGraph(t, src, pythonEmbeddedKB(t))
	assertPythonCallee(t, graph, "two_args", "sign",
		FunctionID{Package: "coincurve", Type: "PrivateKey", Name: "sign"}, "PrivateKey")
}

// TestPythonAssignedVarTypes_InGraphDeclStillWins pins the PRE-EXISTING
// behavior against the new fallback. The scanned source's own declaration is
// the authority and must be preferred, so wiring the KB in cannot change any
// result that already resolved.
func TestPythonAssignedVarTypes_InGraphDeclStillWins(t *testing.T) {
	t.Parallel()

	// `make_key` is declared IN the scanned source and annotated as returning
	// a local Wrapper, even though its body calls the contracted factory. The
	// receiver must be typed Wrapper, not coincurve.PrivateKey.
	src := `from coincurve import PrivateKey

SECRET = b"x"
MESSAGE = b"m"

def make_key() -> Wrapper:
    return PrivateKey(SECRET)


def run():
    key = make_key()
    sig = key.sign(MESSAGE)
    return sig
`
	for _, tc := range []struct {
		name string
		kb   *contracts.KnowledgeBase
	}{
		{"nil KB", nil},
		{"embedded KB", pythonEmbeddedKB(t)},
	} {
		graph := pythonPropagationGraph(t, src, tc.kb)
		fn := graph.Functions[FunctionID{Package: "mypkg", Name: "run"}.String()]
		if fn == nil {
			t.Fatalf("%s: run not found", tc.name)
		}
		call := findPythonCallByMethod(fn, "sign")
		if call == nil {
			t.Fatalf("%s: key.sign call not found", tc.name)
		}
		want := FunctionID{Package: "mypkg", Type: "Wrapper", Name: "sign"}
		if call.Callee != want {
			t.Errorf("%s: Callee = %+v, want %+v (the in-graph declaration must win)",
				tc.name, call.Callee, want)
		}
	}
}

// TestPythonAssignedVarTypes_UncontractedFactoryTypesNothing is the negative
// half. A factory with no in-graph declaration AND no contract entry must leave
// the receiver untyped: the fallback may not invent a type from the callee's own
// name.
//
// The positive control in the same graph is what makes this meaningful — a
// fallback that resolved nothing at all would pass this test too.
func TestPythonAssignedVarTypes_UncontractedFactoryTypesNothing(t *testing.T) {
	t.Parallel()

	src := `from coincurve import PrivateKey
from someotherlib import Widget

SECRET = b"x"
MESSAGE = b"m"

def mixed():
    widget = Widget(SECRET)
    a = widget.sign(MESSAGE)
    key = PrivateKey(SECRET)
    b = key.sign(MESSAGE)
    return a, b
`
	graph := pythonPropagationGraph(t, src, pythonEmbeddedKB(t))
	fn := graph.Functions[FunctionID{Package: "mypkg", Name: "mixed"}.String()]
	if fn == nil {
		t.Fatal("mixed not found")
	}

	var widgetCall, keyCall *FunctionCall
	for i := range fn.Calls {
		call := &fn.Calls[i]
		if call.Callee.Name != "sign" {
			continue
		}
		switch call.ReceiverVar {
		case "widget":
			widgetCall = call
		case "key":
			keyCall = call
		}
	}
	if keyCall == nil {
		t.Fatal("positive control absent: key.sign call not found")
	}
	if keyCall.ResolvedReceiverType != "PrivateKey" {
		t.Fatalf("positive control failed: key.sign ResolvedReceiverType = %q, want %q — "+
			"the negative assertion below would pass vacuously",
			keyCall.ResolvedReceiverType, "PrivateKey")
	}
	if widgetCall == nil {
		t.Fatal("widget.sign call not found")
	}
	if widgetCall.ResolvedReceiverType != "" {
		t.Errorf("widget.sign ResolvedReceiverType = %q, want empty: someotherlib.Widget "+
			"has no contract and no in-graph declaration", widgetCall.ResolvedReceiverType)
	}
	// An unresolved Python receiver keeps the parser's own placeholder: the
	// callee is keyed on the CALLING module plus the VARIABLE name, which is
	// what `mypkg.(widget).sign` means. Asserting that placeholder is
	// unchanged is the precise statement that the fallback invented nothing —
	// asserting an empty Type would be asserting a shape the parser never
	// produces.
	if want := (FunctionID{Package: "mypkg", Type: "widget", Name: "sign"}); widgetCall.Callee != want {
		t.Errorf("widget.sign Callee = %+v, want the untouched placeholder %+v",
			widgetCall.Callee, want)
	}
}

// TestPythonAssignedVarTypes_BindingIsPerVariable pins that a KB-sourced
// binding is applied to the variable it was recorded for and to no other, and
// that it does not cross a FunctionDecl boundary.
func TestPythonAssignedVarTypes_BindingIsPerVariable(t *testing.T) {
	t.Parallel()

	src := `from coincurve import PrivateKey

SECRET = b"x"
MESSAGE = b"m"

def binds():
    key = PrivateKey(SECRET)
    sig = key.sign(MESSAGE)
    return sig


def other(key):
    return key.sign(MESSAGE)
`
	graph := pythonPropagationGraph(t, src, pythonEmbeddedKB(t))

	assertPythonCallee(t, graph, "binds", "sign",
		FunctionID{Package: "coincurve", Type: "PrivateKey", Name: "sign"}, "PrivateKey")

	fn := graph.Functions[FunctionID{Package: "mypkg", Name: "other"}.String()]
	if fn == nil {
		t.Fatal("other not found")
	}
	call := findPythonCallByMethod(fn, "sign")
	if call == nil {
		t.Fatal("other: key.sign call not found")
	}
	if call.ResolvedReceiverType != "" {
		t.Errorf("other: ResolvedReceiverType = %q, want empty — the binding in `binds` "+
			"must not cross into another FunctionDecl on a matching variable name",
			call.ResolvedReceiverType)
	}
}

// TestPythonAssignedVarTypes_RebindToUnknowableInvalidates covers the defect
// review found in the first version of this pass: on an assignment whose callee
// has no knowable return type the pass used to `continue`, which left the
// PREVIOUS binding for that name live and over-propagated it to a later
// receiver call. Measured before the fix, with the coincurve contract loaded,
// all three shapes below resolved to `coincurve.PrivateKey.sign`.
//
// This corrupts `matched_operation.symbol` and call-chain evidence rather than
// the asset set — an asset is emitted by a rule match, which this pass does not
// influence — but a wrong symbol looks like data, so it is worse than a missing
// one.
func TestPythonAssignedVarTypes_RebindToUnknowableInvalidates(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		src  string
	}{
		{
			"straight reassignment",
			`from coincurve import PrivateKey

def run(m):
    key = PrivateKey(b"s")
    key = helper()
    return key.sign(m)
`,
		},
		{
			"conditional else-branch rebind",
			`from coincurve import PrivateKey

def run(flag, m):
    if flag:
        key = PrivateKey(b"s")
    else:
        key = helper()
    return key.sign(m)
`,
		},
		{
			"del then rebind",
			`from coincurve import PrivateKey

def run(m):
    key = PrivateKey(b"s")
    del key
    key = helper()
    return key.sign(m)
`,
		},
	} {
		graph := pythonPropagationGraph(t, tc.src, pythonEmbeddedKB(t))
		fn := graph.Functions[FunctionID{Package: "mypkg", Name: "run"}.String()]
		if fn == nil {
			t.Fatalf("%s: run not found", tc.name)
		}
		call := findPythonCallByMethod(fn, "sign")
		if call == nil {
			t.Fatalf("%s: key.sign call not found", tc.name)
		}
		if call.ResolvedReceiverType != "" {
			t.Errorf("%s: ResolvedReceiverType = %q, want empty — the binding from the "+
				"earlier assignment is stale once the name is rebound to an "+
				"unknowable callee", tc.name, call.ResolvedReceiverType)
		}
		if got, want := call.Callee, (FunctionID{Package: "mypkg", Type: "key", Name: "sign"}); got != want {
			t.Errorf("%s: Callee = %+v, want the untouched placeholder %+v", tc.name, got, want)
		}
	}
}

// TestPythonAssignedVarTypes_RebindToContractedFactoryTakesTheNewType is the
// other half, and it is what localizes the defect above to the
// unknowable-return path alone: re-binding to a DIFFERENT contracted factory was
// always correct, because the assignment overwrites the tracked entry.
func TestPythonAssignedVarTypes_RebindToContractedFactoryTakesTheNewType(t *testing.T) {
	t.Parallel()

	src := `from coincurve import PrivateKey, PublicKey

def run(sig, m):
    key = PrivateKey(b"s")
    key = PublicKey.from_secret(b"s")
    return key.verify(sig, m)
`
	graph := pythonPropagationGraph(t, src, pythonEmbeddedKB(t))
	assertPythonCallee(t, graph, "run", "verify",
		FunctionID{Package: "coincurve", Type: "PublicKey", Name: "verify"}, "PublicKey")
}

// TestPythonAssignedVarTypes_KnownLimitation_RebindWithoutACallIsInvisible pins
// the two shapes this pass CANNOT reach, so the gap is visible in the suite
// rather than discovered later.
//
// The pass walks `fn.Calls`. A rebind that is not a call produces no entry
// there, so nothing signals that the name changed meaning:
//
//   - a `for` target (`for key in xs:`) — measured: the loop rebind emits no
//     FunctionCall at all, so `key` keeps the type of the pre-loop assignment;
//   - a nested `def`'s PARAMETER — measured: a nested function is NOT a separate
//     FunctionDecl (the probe reports `decls=1`), its calls are attributed to the
//     enclosing decl, and its parameter list is not visible here, so a parameter
//     shadowing an outer name inherits the outer binding.
//
// The same blindness applies to a rebind from a literal, a tuple unpack, a
// `with ... as`, and a comprehension target. The function's doc comment says
// this pass "never crosses FunctionDecl boundaries"; that bound is real but it
// does NOT imply lexical-scope correctness, because an inner scope is not a
// separate decl.
//
// Fixing either shape needs a signal this pass does not have — statement-level
// binding events, or nested defs as their own decls — so it belongs to the
// parser rather than here. THIS TEST ASSERTS THE CURRENT, WRONG BEHAVIOR ON
// PURPOSE: if a future change makes either shape resolve correctly, this test
// fails and should be deleted along with this comment.
func TestPythonAssignedVarTypes_KnownLimitation_RebindWithoutACallIsInvisible(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ name, src string }{
		{
			"for-loop target shadows the earlier binding",
			`from coincurve import PrivateKey

def run(xs, m):
    key = PrivateKey(b"s")
    for key in xs:
        key.sign(m)
`,
		},
		{
			"nested def parameter shadows the outer name",
			`from coincurve import PrivateKey

def run(m):
    key = PrivateKey(b"s")

    def inner(key):
        return key.sign(m)

    return inner
`,
		},
	} {
		graph := pythonPropagationGraph(t, tc.src, pythonEmbeddedKB(t))
		fn := graph.Functions[FunctionID{Package: "mypkg", Name: "run"}.String()]
		if fn == nil {
			t.Fatalf("%s: run not found", tc.name)
		}
		call := findPythonCallByMethod(fn, "sign")
		if call == nil {
			t.Fatalf("%s: sign call not found", tc.name)
		}
		if call.ResolvedReceiverType != "PrivateKey" {
			t.Errorf("%s: ResolvedReceiverType = %q, want %q — this is the KNOWN "+
				"over-propagation this test documents; if it is now empty the "+
				"limitation is fixed and this test should be removed",
				tc.name, call.ResolvedReceiverType, "PrivateKey")
		}
	}
}
