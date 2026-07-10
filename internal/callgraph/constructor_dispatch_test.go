// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

package callgraph

import (
	"path/filepath"
	"testing"
)

// TestBuilder_DoesNotDispatchExpandConstructors guards the constructor
// exclusion in expandAbstractClassDispatch: `new Foo(x)` invokes exactly
// Foo.<init> and can never dispatch virtually, so a constructor call whose
// exact declaration is missing from the graph (implicit default constructor,
// unparsed overload) must NOT fan out to other classes' same-arity
// constructors. On the bcprov corpus this fan-out synthesized 6.58M of the
// graph's 7.16M edge resolutions before the guard existed.
func TestBuilder_DoesNotDispatchExpandConstructors(t *testing.T) {
	root := t.TempDir()

	// class Widget { Widget(int size) {...} }  — parsed, so knownClassTypes
	// contains Widget, but only the #1-arity ctor below is declared; the
	// call site invokes an UNDECLARED Widget ctor via a second file's shape.
	widgetCtor := FunctionDecl{
		ID:         FunctionID{Package: "com.example", Type: "Widget", Name: "<init>#1"},
		FilePath:   filepath.Join(root, "Widget.java"),
		StartLine:  3,
		EndLine:    5,
		OwnerType:  "class",
		OwnerName:  "Widget",
		Parameters: []FunctionParameter{{Type: "int"}},
	}

	// class Gadget { Gadget(int size) {...} } — an unrelated class whose
	// same-arity constructor must NOT become a dispatch target.
	gadgetCtor := FunctionDecl{
		ID:         FunctionID{Package: "com.example", Type: "Gadget", Name: "<init>#1"},
		FilePath:   filepath.Join(root, "Gadget.java"),
		StartLine:  3,
		EndLine:    5,
		OwnerType:  "class",
		OwnerName:  "Gadget",
		Parameters: []FunctionParameter{{Type: "int"}},
	}

	// class App { void run() { new Widget(cfg); } } — the callee resolves to a
	// Widget constructor signature that has no declaration in the graph
	// (different arity spelling), the exact shape that used to trigger the
	// namespace-wide constructor fan-out.
	appRun := FunctionDecl{
		ID:        FunctionID{Package: "com.example", Type: "App", Name: "run#0"},
		FilePath:  filepath.Join(root, "App.java"),
		StartLine: 10,
		EndLine:   14,
		OwnerType: "class",
		OwnerName: "App",
		Calls: []FunctionCall{
			{
				Callee:    FunctionID{Package: "com.example", Type: "Widget", Name: "<init>#2"},
				Raw:       "new Widget",
				FilePath:  filepath.Join(root, "App.java"),
				Line:      12,
				Arguments: []string{"cfg", "flags"},
			},
		},
	}

	parser := &stubParser{
		sep: ".",
		analyses: map[string][]*FileAnalysis{
			root: {
				{Functions: []FunctionDecl{widgetCtor, gadgetCtor, appRun}},
			},
		},
	}

	graph, err := NewBuilder(parser).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "com.example"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	appRunKey := appRun.ID.String()

	// The direct (exact) edge to the invoked constructor signature must survive.
	directCalleeKey := FunctionID{Package: "com.example", Type: "Widget", Name: "<init>#2"}.String()
	if !sliceContainsAbstractDispatchKey(graph.Callers[directCalleeKey], appRunKey) {
		t.Fatalf("Callers[%s] = %v, want to include %s (direct constructor call edge)",
			directCalleeKey, graph.Callers[directCalleeKey], appRunKey)
	}

	// No dispatch fan-out: neither the unrelated Gadget ctor nor the sibling
	// Widget ctor overload may gain App.run as a synthesized caller.
	for _, calleeKey := range []string{gadgetCtor.ID.String(), widgetCtor.ID.String()} {
		if sliceContainsAbstractDispatchKey(graph.Callers[calleeKey], appRunKey) {
			t.Fatalf("Callers[%s] = %v, must not include %s (constructor dispatch fan-out)",
				calleeKey, graph.Callers[calleeKey], appRunKey)
		}
	}

	// And no interface_dispatch edge resolutions may exist for <init> callees.
	for _, res := range graph.EdgeResolutions {
		if res.Kind == EdgeKindInterfaceDispatch && res.MethodName == "<init>" {
			t.Fatalf("found interface_dispatch edge resolution for a constructor: %+v", res)
		}
	}
}
