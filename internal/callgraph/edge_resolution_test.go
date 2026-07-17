package callgraph

import (
	"path/filepath"
	"testing"
)

// TestBuildCallerIndex_ClassifiesEdgeResolution proves the builder records HOW
// each caller->callee edge was resolved, so downstream consumers can distinguish
// exact typed edges from over-broad name/arity dispatch guesses.
//
// Scenario: a controller calls an interface method directly. The direct edge to
// the interface method is exact; the edges the builder synthesizes to the
// concrete implementations (by name+arity+namespace) are interface_dispatch.
func TestBuildCallerIndex_ClassifiesEdgeResolution(t *testing.T) {
	root := t.TempDir()

	controller := FunctionDecl{
		ID:        FunctionID{Package: "app", Type: "Controller", Name: "handle#0"},
		FilePath:  filepath.Join(root, "Controller.java"),
		StartLine: 1,
		EndLine:   5,
		OwnerType: "class",
		OwnerName: "Controller",
		Calls: []FunctionCall{
			{
				Callee:   FunctionID{Package: "com.dep", Type: "Sink", Name: "run#0"},
				Raw:      "sink.run()",
				FilePath: filepath.Join(root, "Controller.java"),
				Line:     3,
			},
		},
	}
	ifaceRun := FunctionDecl{
		ID:         FunctionID{Package: "com.dep", Type: "Sink", Name: "run#0"},
		FilePath:   filepath.Join(root, "Sink.java"),
		StartLine:  1,
		EndLine:    2,
		OwnerType:  "interface",
		OwnerName:  "Sink",
		Parameters: []FunctionParameter{},
	}
	implRun := FunctionDecl{
		ID:         FunctionID{Package: "com.dep.impl", Type: "SinkImpl", Name: "run#0"},
		FilePath:   filepath.Join(root, "SinkImpl.java"),
		StartLine:  1,
		EndLine:    4,
		OwnerType:  "class",
		OwnerName:  "SinkImpl",
		Parameters: []FunctionParameter{},
	}

	parser := &stubParser{
		sep: ".",
		analyses: map[string][]*FileAnalysis{
			root: {{Functions: []FunctionDecl{controller, ifaceRun, implRun}}},
		},
	}

	graph, err := NewBuilder(parser).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	callerKey := controller.ID.String()
	ifaceKey := ifaceRun.ID.String()
	implKey := implRun.ID.String()

	directKind := graph.EdgeResolutions[EdgeResolutionKey(callerKey, ifaceKey, EdgeResolution{
		Kind:       EdgeKindExact,
		MethodName: "run",
		Arity:      0,
		CallSite:   3,
	})]
	if directKind.Kind != EdgeKindExact {
		t.Fatalf("direct edge kind = %q, want %q", directKind.Kind, EdgeKindExact)
	}

	implRes, ok := graph.EdgeResolutions[EdgeResolutionKey(callerKey, implKey, EdgeResolution{
		Kind:         EdgeKindInterfaceDispatch,
		DeclaredType: "com.dep.Sink",
		MethodName:   "run",
		Arity:        0,
		CallSite:     3,
	})]
	if !ok {
		t.Fatalf("expected an EdgeResolution for the synthesized impl edge %q", implKey)
	}
	if implRes.Kind != EdgeKindInterfaceDispatch {
		t.Fatalf("impl edge kind = %q, want %q", implRes.Kind, EdgeKindInterfaceDispatch)
	}
	if implRes.DeclaredType != "com.dep.Sink" {
		t.Fatalf("impl edge declared type = %q, want %q", implRes.DeclaredType, "com.dep.Sink")
	}
	if implRes.MethodName != "run" || implRes.Arity != 0 {
		t.Fatalf("impl edge method/arity = %q/%d, want run/0", implRes.MethodName, implRes.Arity)
	}
	if implRes.CallSite != 3 {
		t.Fatalf("impl edge call site = %d, want 3 (the call expression line)", implRes.CallSite)
	}
}

func TestBuildCallerIndex_PreservesSameLineCallColumns(t *testing.T) {
	root := t.TempDir()
	caller := FunctionDecl{
		ID:       FunctionID{Package: "app", Type: "Controller", Name: "handle#0"},
		FilePath: filepath.Join(root, "Controller.java"),
		Calls: []FunctionCall{
			{Callee: FunctionID{Package: "com.dep", Type: "Sink", Name: "run#0"}, Line: 3, StartCol: 4, EndCol: 14},
			{Callee: FunctionID{Package: "com.dep", Type: "Sink", Name: "run#0"}, Line: 3, StartCol: 20, EndCol: 30},
		},
	}
	iface := FunctionDecl{
		ID: FunctionID{Package: "com.dep", Type: "Sink", Name: "run#0"}, OwnerType: "interface", OwnerName: "Sink",
	}
	impl := FunctionDecl{
		ID: FunctionID{Package: "com.dep.impl", Type: "SinkImpl", Name: "run#0"}, OwnerType: "class", OwnerName: "SinkImpl",
	}
	parser := &stubParser{sep: ".", analyses: map[string][]*FileAnalysis{root: {{Functions: []FunctionDecl{caller, iface, impl}}}}}

	graph, err := NewBuilder(parser).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	for _, cols := range [][2]int{{4, 14}, {20, 30}} {
		key := EdgeResolutionKey(caller.ID.String(), impl.ID.String(), EdgeResolution{
			DeclaredType: "com.dep.Sink", MethodName: "run", Arity: 0, CallSite: 3,
			StartCol: cols[0], EndCol: cols[1],
		})
		resolution, ok := graph.EdgeResolutions[key]
		if !ok {
			t.Fatalf("missing same-line dispatch resolution at columns %d:%d", cols[0], cols[1])
		}
		if resolution.StartCol != cols[0] || resolution.EndCol != cols[1] {
			t.Fatalf("resolution columns = %d:%d, want %d:%d", resolution.StartCol, resolution.EndCol, cols[0], cols[1])
		}
	}
}
