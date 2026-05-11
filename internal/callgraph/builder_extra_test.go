package callgraph

import "testing"

func TestResolveFluentCallsInFunction_NormalizesReturnTypeAndRemovesStaleCaller(t *testing.T) {
	caller := &FunctionDecl{
		ID: FunctionID{Package: "app", Type: "Controller", Name: "issue#0"},
		Calls: []FunctionCall{
			{
				Callee:    FunctionID{Package: "io.jsonwebtoken", Type: "Jwts", Name: "builder#0"},
				Raw:       "Jwts.builder()",
				Line:      10,
				Arguments: nil,
			},
			{
				Callee:    FunctionID{Package: "app", Type: "Jwts.builder()", Name: "setId#1"},
				Raw:       "Jwts.builder().setId(id)",
				Line:      10,
				Arguments: []string{"id"},
			},
		},
	}

	builderFn := &FunctionDecl{
		ID:         FunctionID{Package: "io.jsonwebtoken", Type: "Jwts", Name: "builder#0"},
		ReturnType: "io.jsonwebtoken.ClaimsMutator<io.jsonwebtoken.JwtBuilder>",
	}
	targetFn := &FunctionDecl{
		ID:         FunctionID{Package: "io.jsonwebtoken", Type: "ClaimsMutator", Name: "setId#1"},
		Parameters: []FunctionParameter{{Type: "String"}},
		ReturnType: "io.jsonwebtoken.JwtBuilder",
	}

	oldCalleeKey := caller.Calls[1].Callee.String()
	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			caller.ID.String():    caller,
			builderFn.ID.String(): builderFn,
			targetFn.ID.String():  targetFn,
		},
		Callers: map[string][]string{
			oldCalleeKey: {caller.ID.String()},
		},
	}

	resolved := resolveFluentCallsInFunction(
		caller,
		graph,
		buildTypePackageIndex(graph),
		indexMethodsByQualifiedArity(graph),
	)
	if resolved != 1 {
		t.Fatalf("resolveFluentCallsInFunction resolved %d calls, want 1", resolved)
	}

	if got := caller.Calls[1].Callee; got != targetFn.ID {
		t.Fatalf("rewritten callee = %#v, want %#v", got, targetFn.ID)
	}
	if callers := graph.Callers[oldCalleeKey]; len(callers) != 0 {
		t.Fatalf("stale callers[%q] = %#v, want empty", oldCalleeKey, callers)
	}
	if callers := graph.Callers[targetFn.ID.String()]; len(callers) != 1 || callers[0] != caller.ID.String() {
		t.Fatalf("callers[%q] = %#v, want [%q]", targetFn.ID.String(), callers, caller.ID.String())
	}
}
