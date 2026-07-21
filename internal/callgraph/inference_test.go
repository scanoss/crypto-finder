package callgraph

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mustParseID parses a FunctionID string and panics on error (test helper only).
func mustParseID(s string) FunctionID {
	id, err := ParseFunctionID(s)
	if err != nil {
		panic(fmt.Sprintf("mustParseID(%q): %v", s, err))
	}
	return id
}

// buildSimpleGraph builds a CallGraph with the given functions and edges.
// functions: list of function ID strings (e.g. "pkg.(Type).name#0")
// edges: caller→callee pairs using those same strings.
func buildSimpleGraph(functions []string, edges [][2]string) *CallGraph {
	g := &CallGraph{
		Functions:     make(map[string]*FunctionDecl),
		Callers:       make(map[string][]string),
		TypeHierarchy: make(map[string][]string),
	}
	for _, fid := range functions {
		id := mustParseID(fid)
		g.Functions[fid] = &FunctionDecl{
			ID:         id,
			ReturnType: "", // trigger type by default
		}
	}
	for _, e := range edges {
		caller, callee := e[0], e[1]
		// Add call from caller to callee
		decl := g.Functions[caller]
		calleeID := mustParseID(callee)
		decl.Calls = append(decl.Calls, FunctionCall{Callee: calleeID})
		// Build Callers reverse index
		g.Callers[callee] = append(g.Callers[callee], caller)
	}
	return g
}

// ---------------------------------------------------------------------------
// T4.1 / T4.2 — computeSCCs: single node
// ---------------------------------------------------------------------------

// TestComputeSCCs_SingleNode asserts that a graph with 1 function and no calls
// produces exactly 1 SCC containing that single node.
func TestComputeSCCs_SingleNode(t *testing.T) {
	g := buildSimpleGraph([]string{"pkg.A"}, nil)
	sccs := computeSCCs(g)
	if len(sccs) != 1 {
		t.Fatalf("expected 1 SCC, got %d", len(sccs))
	}
	if len(sccs[0]) != 1 {
		t.Fatalf("expected SCC of size 1, got %d", len(sccs[0]))
	}
	if sccs[0][0] != "pkg.A" {
		t.Errorf("expected SCC node %q, got %q", "pkg.A", sccs[0][0])
	}
}

// ---------------------------------------------------------------------------
// T4.3 — computeSCCs: mutual recursion
// ---------------------------------------------------------------------------

// TestComputeSCCs_MutualRecursion asserts that A→B, B→A forms a single SCC.
func TestComputeSCCs_MutualRecursion(t *testing.T) {
	g := buildSimpleGraph(
		[]string{"pkg.A", "pkg.B"},
		[][2]string{{"pkg.A", "pkg.B"}, {"pkg.B", "pkg.A"}},
	)
	sccs := computeSCCs(g)
	if len(sccs) != 1 {
		t.Fatalf("expected 1 SCC (cycle), got %d", len(sccs))
	}
	if len(sccs[0]) != 2 {
		t.Fatalf("expected SCC of size 2, got %d", len(sccs[0]))
	}
}

// ---------------------------------------------------------------------------
// T4.4 — computeSCCs: chain (no cycle)
// ---------------------------------------------------------------------------

// TestComputeSCCs_Chain asserts that A→B→C (no cycles) produces 3 singleton SCCs
// in reverse-topological order: C first, then B, then A.
func TestComputeSCCs_Chain(t *testing.T) {
	g := buildSimpleGraph(
		[]string{"pkg.A", "pkg.B", "pkg.C"},
		[][2]string{{"pkg.A", "pkg.B"}, {"pkg.B", "pkg.C"}},
	)
	sccs := computeSCCs(g)
	if len(sccs) != 3 {
		t.Fatalf("expected 3 SCCs, got %d", len(sccs))
	}
	// reverse-topological: callee-first. C is leaf → first SCC.
	order := []string{sccs[0][0], sccs[1][0], sccs[2][0]}
	if order[0] != "pkg.C" || order[1] != "pkg.B" || order[2] != "pkg.A" {
		t.Errorf("expected order [C, B, A], got %v", order)
	}
}

// ---------------------------------------------------------------------------
// T4.5 / T4.6 — latticeJoin: single identical type
// ---------------------------------------------------------------------------

// TestLatticeJoin_SingleType asserts that joining two candidates of the same
// type returns that type with confidence = minimum of the two and no downgrade.
func TestLatticeJoin_SingleType(t *testing.T) {
	hier := map[string][]string{
		"javax.crypto.SecretKey": {"java.security.Key"},
	}
	cands := []candidate{
		{typ: "javax.crypto.SecretKey", confidence: ConfidenceHigh, origin: OriginKBDirect},
		{typ: "javax.crypto.SecretKey", confidence: ConfidenceHigh, origin: OriginKBDirect},
	}
	got, ok := latticeJoin(cands, hier)
	if !ok {
		t.Fatal("latticeJoin returned ok=false for identical types")
	}
	if got.typ != "javax.crypto.SecretKey" {
		t.Errorf("got type %q, want %q", got.typ, "javax.crypto.SecretKey")
	}
	if got.confidence != ConfidenceHigh {
		t.Errorf("got confidence %q, want %q", got.confidence, ConfidenceHigh)
	}
}

// ---------------------------------------------------------------------------
// T4.7 — latticeJoin: SecretKey ∪ PrivateKey → Key (downgrade)
// ---------------------------------------------------------------------------

// TestLatticeJoin_SecretKeyAndPrivateKey asserts that joining SecretKey and
// PrivateKey produces java.security.Key with confidence downgraded to medium.
func TestLatticeJoin_SecretKeyAndPrivateKey(t *testing.T) {
	hier := map[string][]string{
		"javax.crypto.SecretKey":   {"java.security.Key"},
		"java.security.PrivateKey": {"java.security.Key"},
		"java.security.Key":        {"java.lang.Object"},
	}
	cands := []candidate{
		{typ: "javax.crypto.SecretKey", confidence: ConfidenceHigh, origin: OriginKBDirect},
		{typ: "java.security.PrivateKey", confidence: ConfidenceHigh, origin: OriginKBDirect},
	}
	got, ok := latticeJoin(cands, hier)
	if !ok {
		t.Fatal("latticeJoin returned ok=false; expected Key as LUB")
	}
	if got.typ != "java.security.Key" {
		t.Errorf("got LUB %q, want %q", got.typ, "java.security.Key")
	}
	if got.confidence != ConfidenceMedium {
		t.Errorf("got confidence %q after join, want medium", got.confidence)
	}
}

// ---------------------------------------------------------------------------
// T4.8 — latticeJoin: no common ancestor → ok=false
// ---------------------------------------------------------------------------

// TestLatticeJoin_NoCommonAncestor asserts that joining SecretKey and String
// produces ok=false (join failed — no useful LUB).
func TestLatticeJoin_NoCommonAncestor(t *testing.T) {
	hier := map[string][]string{
		"javax.crypto.SecretKey": {"java.security.Key"},
		"java.security.Key":      {"java.lang.Object"},
		"java.lang.String":       {"java.lang.Object"},
	}
	cands := []candidate{
		{typ: "javax.crypto.SecretKey", confidence: ConfidenceHigh, origin: OriginKBDirect},
		{typ: "java.lang.String", confidence: ConfidenceHigh, origin: OriginKBDirect},
	}
	_, ok := latticeJoin(cands, hier)
	if ok {
		t.Fatal("latticeJoin returned ok=true for SecretKey ∪ String; expected join-failed")
	}
}

// ---------------------------------------------------------------------------
// T4.9 / T4.10 — InferReturnTypes: empty graph
// ---------------------------------------------------------------------------

// TestInferReturnTypes_EmptyGraph asserts that calling InferReturnTypes on a
// graph with no functions returns no error and performs no inferences.
func TestInferReturnTypes_EmptyGraph(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\"): %v", err)
	}
	g := &CallGraph{
		Functions:     make(map[string]*FunctionDecl),
		Callers:       make(map[string][]string),
		TypeHierarchy: make(map[string][]string),
	}
	if err := InferReturnTypes(g, kb); err != nil {
		t.Fatalf("InferReturnTypes: unexpected error: %v", err)
	}
	for _, fn := range g.Functions {
		if fn.InferredReturn != nil {
			t.Errorf("expected nil InferredReturn, got %+v", fn.InferredReturn)
		}
	}
}

// ---------------------------------------------------------------------------
// T4.11 — constructor return
// ---------------------------------------------------------------------------

// TestInferReturnTypes_ConstructorReturn asserts that a function whose sole
// return source is a constructor call gets an InferredReturn with the
// constructed type, high confidence, and "constructor" origin.
func TestInferReturnTypes_ConstructorReturn(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\"): %v", err)
	}

	g := &CallGraph{
		Functions:     make(map[string]*FunctionDecl),
		Callers:       make(map[string][]string),
		TypeHierarchy: make(map[string][]string),
	}
	// <init>#2 with constructed type SecretKeySpec
	initID := FunctionID{Package: "javax.crypto.spec", Type: "SecretKeySpec", Name: "<init>#2"}
	fn := &FunctionDecl{
		ID:         FunctionID{Package: "com.example", Type: "KeyUtil", Name: "makeKey#0"},
		ReturnType: "", // trigger
		ReturnSources: []SourceNode{
			{
				Type:         "CALL_RESULT",
				DeclaredType: "javax.crypto.spec.SecretKeySpec",
				CallTarget:   &initID,
			},
		},
	}
	g.Functions["com.example.(KeyUtil).makeKey#0"] = fn

	if err := InferReturnTypes(g, kb); err != nil {
		t.Fatalf("InferReturnTypes: %v", err)
	}
	if fn.InferredReturn == nil {
		t.Fatal("expected InferredReturn to be populated")
	}
	if fn.InferredReturn.Type != "javax.crypto.spec.SecretKeySpec" {
		t.Errorf("Type = %q, want %q", fn.InferredReturn.Type, "javax.crypto.spec.SecretKeySpec")
	}
	if fn.InferredReturn.Confidence != ConfidenceHigh {
		t.Errorf("Confidence = %q, want high", fn.InferredReturn.Confidence)
	}
	if fn.InferredReturn.Origin != OriginConstructor {
		t.Errorf("Origin = %q, want constructor", fn.InferredReturn.Origin)
	}
}

// ---------------------------------------------------------------------------
// T4.12 — KB direct hit
// ---------------------------------------------------------------------------

// TestInferReturnTypes_KBDirect asserts that a function calling
// KeyGenerator.generateKey#0 gets InferredReturn{SecretKey, high, kb-direct}.
func TestInferReturnTypes_KBDirect(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\"): %v", err)
	}
	g := &CallGraph{
		Functions:     make(map[string]*FunctionDecl),
		Callers:       make(map[string][]string),
		TypeHierarchy: make(map[string][]string),
	}
	calleeID := FunctionID{
		Package: "javax.crypto",
		Type:    "KeyGenerator",
		Name:    "generateKey#0",
	}
	fn := &FunctionDecl{
		ID:         FunctionID{Package: "com.example", Type: "Util", Name: "getKey#0"},
		ReturnType: "",
		ReturnSources: []SourceNode{
			{Type: "CALL_RESULT", CallTarget: &calleeID},
		},
	}
	g.Functions["com.example.(Util).getKey#0"] = fn

	if err := InferReturnTypes(g, kb); err != nil {
		t.Fatalf("InferReturnTypes: %v", err)
	}
	if fn.InferredReturn == nil {
		t.Fatal("expected InferredReturn")
	}
	if fn.InferredReturn.Type != "javax.crypto.SecretKey" {
		t.Errorf("Type = %q, want javax.crypto.SecretKey", fn.InferredReturn.Type)
	}
	if fn.InferredReturn.Confidence != ConfidenceHigh {
		t.Errorf("Confidence = %q, want high", fn.InferredReturn.Confidence)
	}
	if fn.InferredReturn.Origin != OriginKBDirect {
		t.Errorf("Origin = %q, want kb-direct", fn.InferredReturn.Origin)
	}
}

// ---------------------------------------------------------------------------
// T4.13 — KB conditional resolved
// ---------------------------------------------------------------------------

// TestInferReturnTypes_KBConditional_Resolved asserts that a function calling
// Cipher.unwrap#3 with arg[2]="Cipher.SECRET_KEY" resolves to SecretKey, high.
func TestInferReturnTypes_KBConditional_Resolved(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\"): %v", err)
	}
	g := &CallGraph{
		Functions:     make(map[string]*FunctionDecl),
		Callers:       make(map[string][]string),
		TypeHierarchy: make(map[string][]string),
	}
	calleeID := FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "unwrap#3"}
	fn := &FunctionDecl{
		ID:         FunctionID{Package: "com.example", Type: "U", Name: "doUnwrap#0"},
		ReturnType: "",
		ReturnSources: []SourceNode{
			{
				Type:       "CALL_RESULT",
				CallTarget: &calleeID,
				// arg[2] literal = "Cipher.SECRET_KEY" matches the KB contract
				SourceNodes: []SourceNode{
					{Type: "VALUE", ParameterIndex: 0},
					{Type: "VALUE", ParameterIndex: 1},
					{Type: "VALUE", Value: "Cipher.SECRET_KEY", ParameterIndex: 2},
				},
			},
		},
	}
	g.Functions["com.example.(U).doUnwrap#0"] = fn

	if err := InferReturnTypes(g, kb); err != nil {
		t.Fatalf("InferReturnTypes: %v", err)
	}
	if fn.InferredReturn == nil {
		t.Fatal("expected InferredReturn")
	}
	if fn.InferredReturn.Type != "javax.crypto.SecretKey" {
		t.Errorf("Type = %q, want javax.crypto.SecretKey", fn.InferredReturn.Type)
	}
	if fn.InferredReturn.Confidence != ConfidenceHigh {
		t.Errorf("Confidence = %q, want high", fn.InferredReturn.Confidence)
	}
	if fn.InferredReturn.Origin != OriginKBConditional {
		t.Errorf("Origin = %q, want kb-conditional", fn.InferredReturn.Origin)
	}
}

// ---------------------------------------------------------------------------
// T4.14 — KB conditional single plausible branch
// ---------------------------------------------------------------------------

// TestInferReturnTypes_KBConditional_SinglePlausible asserts that when arg is
// unresolved but only one KB branch is plausible, confidence is medium.
func TestInferReturnTypes_KBConditional_SinglePlausible(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\"): %v", err)
	}
	// Build a minimal KB with 3 conditional branches for "test.Op.call#1"
	// Branch A: arg[0] in {"A"} → TypeA, high
	// Branch B: arg[0] in {"B"} → TypeB, high
	// Branch C: arg[0] in {"C"} → TypeC, high
	// Argument source: VARIABLE (unresolved) — declared type "java.lang.String"
	//   but we can eliminate B and C by knowing arg is declared as "AType" — no,
	//   per design: with a declared type we cannot eliminate branches (we don't
	//   know the runtime value). Instead we test: only 1 conditional contract at all.
	// Simplest: use a KB with only ONE conditional entry for a method.
	// Use the embedded KB: Cipher.unwrap#3 has 3 branches. Let's build a
	// synthetic KB with 1 conditional entry.
	customYAML := []byte(`
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: com.example.Op.call
    arity: 1
    when:
      arg_index: 0
      arg_value_in: ["X"]
    return:
      type: com.example.TypeX
      confidence: high
hierarchy: {}
`)
	customKB, err := contracts.Load(customYAML)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_ = kb // only use customKB

	g := &CallGraph{
		Functions:     make(map[string]*FunctionDecl),
		Callers:       make(map[string][]string),
		TypeHierarchy: make(map[string][]string),
	}
	calleeID := FunctionID{Package: "com.example", Type: "Op", Name: "call#1"}
	fn := &FunctionDecl{
		ID:         FunctionID{Package: "com.example", Type: "U", Name: "doIt#0"},
		ReturnType: "",
		ReturnSources: []SourceNode{
			{
				Type:       "CALL_RESULT",
				CallTarget: &calleeID,
				// arg[0] is unresolved (VARIABLE, no Value)
				SourceNodes: []SourceNode{
					{Type: "VARIABLE", Name: "mode"},
				},
			},
		},
	}
	g.Functions["com.example.(U).doIt#0"] = fn

	if err := InferReturnTypes(g, customKB); err != nil {
		t.Fatalf("InferReturnTypes: %v", err)
	}
	if fn.InferredReturn == nil {
		t.Fatal("expected InferredReturn (single plausible branch → medium)")
	}
	if fn.InferredReturn.Confidence != ConfidenceMedium {
		t.Errorf("Confidence = %q, want medium", fn.InferredReturn.Confidence)
	}
	if fn.InferredReturn.Origin != OriginKBConditional {
		t.Errorf("Origin = %q, want kb-conditional", fn.InferredReturn.Origin)
	}
}

// ---------------------------------------------------------------------------
// T4.15 — KB conditional multiple plausible → nil
// ---------------------------------------------------------------------------

// TestInferReturnTypes_KBConditional_MultiplePlausible asserts that when arg is
// unresolved and multiple KB branches are plausible, no inference fires.
func TestInferReturnTypes_KBConditional_MultiplePlausible(t *testing.T) {
	// Cipher.unwrap#3 has 3 conditional branches (SECRET_KEY, PRIVATE_KEY, PUBLIC_KEY).
	// With an unresolved arg[2], all 3 are plausible → InferredReturn should be nil.
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\"): %v", err)
	}
	g := &CallGraph{
		Functions:     make(map[string]*FunctionDecl),
		Callers:       make(map[string][]string),
		TypeHierarchy: make(map[string][]string),
	}
	calleeID := FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "unwrap#3"}
	fn := &FunctionDecl{
		ID:         FunctionID{Package: "com.example", Type: "U", Name: "doUnwrap#0"},
		ReturnType: "",
		ReturnSources: []SourceNode{
			{
				Type:       "CALL_RESULT",
				CallTarget: &calleeID,
				// arg[2] is unresolved
				SourceNodes: []SourceNode{
					{Type: "VALUE", ParameterIndex: 0},
					{Type: "VALUE", ParameterIndex: 1},
					{Type: "VARIABLE", Name: "keyType", ParameterIndex: 2},
				},
			},
		},
	}
	g.Functions["com.example.(U).doUnwrap#0"] = fn

	if err := InferReturnTypes(g, kb); err != nil {
		t.Fatalf("InferReturnTypes: %v", err)
	}
	if fn.InferredReturn != nil {
		t.Errorf("expected nil InferredReturn (multiple plausible branches), got %+v", fn.InferredReturn)
	}
}

// ---------------------------------------------------------------------------
// T4.16 — propagation from callee
// ---------------------------------------------------------------------------

// TestInferReturnTypes_Propagated asserts that function A returning result of
// function B (which has InferredReturn) inherits B's type via "propagated".
func TestInferReturnTypes_Propagated(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\"): %v", err)
	}
	g := &CallGraph{
		Functions:     make(map[string]*FunctionDecl),
		Callers:       make(map[string][]string),
		TypeHierarchy: make(map[string][]string),
	}
	// B has a KB direct hit
	kgID := FunctionID{Package: "javax.crypto", Type: "KeyGenerator", Name: "generateKey#0"}
	fnB := &FunctionDecl{
		ID:         FunctionID{Package: "com.example", Type: "U", Name: "getKey#0"},
		ReturnType: "",
		ReturnSources: []SourceNode{
			{Type: "CALL_RESULT", CallTarget: &kgID},
		},
	}
	// A returns result of B
	bID := FunctionID{Package: "com.example", Type: "U", Name: "getKey#0"}
	fnA := &FunctionDecl{
		ID:         FunctionID{Package: "com.example", Type: "U", Name: "wrapKey#0"},
		ReturnType: "",
		ReturnSources: []SourceNode{
			{Type: "CALL_RESULT", CallTarget: &bID},
		},
	}
	g.Functions["com.example.(U).getKey#0"] = fnB
	g.Functions["com.example.(U).wrapKey#0"] = fnA
	g.Callers["com.example.(U).getKey#0"] = []string{"com.example.(U).wrapKey#0"}

	if err := InferReturnTypes(g, kb); err != nil {
		t.Fatalf("InferReturnTypes: %v", err)
	}
	if fnA.InferredReturn == nil {
		t.Fatal("expected fnA to inherit InferredReturn from fnB")
	}
	if fnA.InferredReturn.Type != "javax.crypto.SecretKey" {
		t.Errorf("fnA type = %q, want javax.crypto.SecretKey", fnA.InferredReturn.Type)
	}
	if fnA.InferredReturn.Origin != OriginPropagated {
		t.Errorf("fnA origin = %q, want propagated", fnA.InferredReturn.Origin)
	}
}

func TestInferReturnTypes_PropagatedFromArityQualifiedCallee(t *testing.T) {
	kb, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: c
library:
  name: test-c
contracts:
  - method: example.EVP_CIPHER_CTX_new
    arity: 0
    return:
      type: EVP_CIPHER_CTX*
      confidence: high
`))
	if err != nil {
		t.Fatalf("load test KB: %v", err)
	}

	externalID := FunctionID{Package: "example", Name: "EVP_CIPHER_CTX_new#0"}
	leafID := FunctionID{Package: "example", Name: "leaf"}
	leaf := &FunctionDecl{
		ID:            leafID,
		ReturnType:    "EVP_CIPHER_CTX*",
		ReturnSources: []SourceNode{{Type: sourceNodeCallResult, CallTarget: &externalID}},
	}
	wrapper := &FunctionDecl{
		ID:            FunctionID{Package: "example", Name: "wrapper"},
		ReturnType:    "EVP_CIPHER_CTX*",
		Calls:         []FunctionCall{{Callee: leafID}},
		ReturnSources: []SourceNode{{Type: sourceNodeCallResult, CallTarget: &FunctionID{Package: "example", Name: "leaf#0"}}},
	}
	graph := buildTestCallGraph(leaf, wrapper)

	if err := InferReturnTypes(graph, kb); err != nil {
		t.Fatalf("InferReturnTypes: %v", err)
	}
	if wrapper.InferredReturn == nil || wrapper.InferredReturn.Type != "EVP_CIPHER_CTX*" || wrapper.InferredReturn.Origin != OriginPropagated {
		t.Fatalf("wrapper InferredReturn = %#v, want propagated EVP_CIPHER_CTX*", wrapper.InferredReturn)
	}
}

// ---------------------------------------------------------------------------
// T4.17 — mutual recursion fixpoint
// ---------------------------------------------------------------------------

// TestInferReturnTypes_MutualRecycleFixpoint asserts that a mutual recursion
// A→B, B→A converges when A also has a direct constructor source.
func TestInferReturnTypes_MutualRecycleFixpoint(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\"): %v", err)
	}
	g := &CallGraph{
		Functions:     make(map[string]*FunctionDecl),
		Callers:       make(map[string][]string),
		TypeHierarchy: make(map[string][]string),
	}
	bID := FunctionID{Package: "com.example", Type: "U", Name: "B#0"}
	aID := FunctionID{Package: "com.example", Type: "U", Name: "A#0"}
	initID := FunctionID{Package: "javax.crypto.spec", Type: "SecretKeySpec", Name: "<init>#2"}

	fnA := &FunctionDecl{
		ID:         aID,
		ReturnType: "",
		ReturnSources: []SourceNode{
			// direct constructor source
			{Type: "CALL_RESULT", DeclaredType: "javax.crypto.spec.SecretKeySpec", CallTarget: &initID},
			// also calls B (cycle)
			{Type: "CALL_RESULT", CallTarget: &bID},
		},
	}
	fnB := &FunctionDecl{
		ID:         bID,
		ReturnType: "",
		ReturnSources: []SourceNode{
			{Type: "CALL_RESULT", CallTarget: &aID},
		},
	}
	g.Functions["com.example.(U).A#0"] = fnA
	g.Functions["com.example.(U).B#0"] = fnB
	g.Callers["com.example.(U).B#0"] = []string{"com.example.(U).A#0"}
	g.Callers["com.example.(U).A#0"] = []string{"com.example.(U).B#0"}
	fnA.Calls = []FunctionCall{{Callee: bID}}
	fnB.Calls = []FunctionCall{{Callee: aID}}

	if err := InferReturnTypes(g, kb); err != nil {
		t.Fatalf("InferReturnTypes: %v", err)
	}
	// Both A and B should converge to SecretKeySpec
	if fnA.InferredReturn == nil {
		t.Fatal("fnA.InferredReturn is nil")
	}
	if fnB.InferredReturn == nil {
		t.Fatal("fnB.InferredReturn is nil")
	}
}

// ---------------------------------------------------------------------------
// T4.18 — iteration cap with stable type
// ---------------------------------------------------------------------------

// TestInferReturnTypes_IterationCapWithStableType asserts that a chain of
// functions deeper than inferenceMaxIterations converges to the base type.
func TestInferReturnTypes_IterationCapWithStableType(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\"): %v", err)
	}
	g := &CallGraph{
		Functions:     make(map[string]*FunctionDecl),
		Callers:       make(map[string][]string),
		TypeHierarchy: make(map[string][]string),
	}

	// Build: F0 has KB-direct source; F1 calls F0; ... F11 calls F10.
	// This forms a 12-deep linear chain (no cycle), so Tarjan breaks into 12 SCCs.
	// Each SCC is processed in callee-first order, so propagation flows up.
	n := 12
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		ids[i] = fmt.Sprintf("com.example.(U).f%d#0", i)
	}
	// F0: KB-direct via KeyGenerator.generateKey
	kgID := FunctionID{Package: "javax.crypto", Type: "KeyGenerator", Name: "generateKey#0"}
	f0 := &FunctionDecl{
		ID:            mustParseID(ids[0]),
		ReturnType:    "",
		ReturnSources: []SourceNode{{Type: "CALL_RESULT", CallTarget: &kgID}},
	}
	g.Functions[ids[0]] = f0

	for i := 1; i < n; i++ {
		prev := mustParseID(ids[i-1])
		fi := &FunctionDecl{
			ID:            mustParseID(ids[i]),
			ReturnType:    "",
			ReturnSources: []SourceNode{{Type: "CALL_RESULT", CallTarget: &prev}},
		}
		g.Functions[ids[i]] = fi
		g.Callers[ids[i-1]] = append(g.Callers[ids[i-1]], ids[i])
		fi.Calls = []FunctionCall{{Callee: prev}}
	}

	if err := InferReturnTypes(g, kb); err != nil {
		t.Fatalf("InferReturnTypes: %v", err)
	}
	top := g.Functions[ids[n-1]]
	if top.InferredReturn == nil {
		t.Fatal("expected top function to inherit type through chain")
	}
	if top.InferredReturn.Type != "javax.crypto.SecretKey" {
		t.Errorf("top type = %q, want javax.crypto.SecretKey", top.InferredReturn.Type)
	}
}

// ---------------------------------------------------------------------------
// T4.19 — iteration cap, purely cyclic, no stable type
// ---------------------------------------------------------------------------

// TestInferReturnTypes_IterationCapNoStableType asserts that a purely cyclic
// graph with no ground-truth source leaves InferredReturn nil after cap.
func TestInferReturnTypes_IterationCapNoStableType(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\"): %v", err)
	}
	g := &CallGraph{
		Functions:     make(map[string]*FunctionDecl),
		Callers:       make(map[string][]string),
		TypeHierarchy: make(map[string][]string),
	}
	// Pure cycle: A→B→C→A, none has a direct source
	aID := FunctionID{Package: "cyc", Type: "X", Name: "A#0"}
	bID := FunctionID{Package: "cyc", Type: "X", Name: "B#0"}
	cID := FunctionID{Package: "cyc", Type: "X", Name: "C#0"}

	fnA := &FunctionDecl{ID: aID, ReturnType: "", ReturnSources: []SourceNode{{Type: "CALL_RESULT", CallTarget: &bID}}}
	fnB := &FunctionDecl{ID: bID, ReturnType: "", ReturnSources: []SourceNode{{Type: "CALL_RESULT", CallTarget: &cID}}}
	fnC := &FunctionDecl{ID: cID, ReturnType: "", ReturnSources: []SourceNode{{Type: "CALL_RESULT", CallTarget: &aID}}}

	g.Functions["cyc.(X).A#0"] = fnA
	g.Functions["cyc.(X).B#0"] = fnB
	g.Functions["cyc.(X).C#0"] = fnC
	fnA.Calls = []FunctionCall{{Callee: bID}}
	fnB.Calls = []FunctionCall{{Callee: cID}}
	fnC.Calls = []FunctionCall{{Callee: aID}}
	g.Callers["cyc.(X).A#0"] = []string{"cyc.(X).C#0"}
	g.Callers["cyc.(X).B#0"] = []string{"cyc.(X).A#0"}
	g.Callers["cyc.(X).C#0"] = []string{"cyc.(X).B#0"}

	if err := InferReturnTypes(g, kb); err != nil {
		t.Fatalf("InferReturnTypes: %v", err)
	}
	for _, fn := range []*FunctionDecl{fnA, fnB, fnC} {
		if fn.InferredReturn != nil {
			t.Errorf("expected nil InferredReturn for pure cycle node, got %+v", fn.InferredReturn)
		}
	}
}

// ---------------------------------------------------------------------------
// T4.20 — declared type suppresses inference
// ---------------------------------------------------------------------------

// TestInferReturnTypes_DeclaredTypeSuppresses asserts that a function declared
// with a specific non-trigger type (javax.crypto.Cipher) does not get inference
// even when ReturnSources are populated.
func TestInferReturnTypes_DeclaredTypeSuppresses(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\"): %v", err)
	}
	g := &CallGraph{
		Functions:     make(map[string]*FunctionDecl),
		Callers:       make(map[string][]string),
		TypeHierarchy: make(map[string][]string),
	}
	initID := FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "<init>#0"}
	fn := &FunctionDecl{
		ID:         FunctionID{Package: "com.example", Type: "U", Name: "getCipher#0"},
		ReturnType: "javax.crypto.Cipher", // specific declared type → suppressed
		ReturnSources: []SourceNode{
			{Type: "CALL_RESULT", DeclaredType: "javax.crypto.Cipher", CallTarget: &initID},
		},
	}
	g.Functions["com.example.(U).getCipher#0"] = fn

	if err := InferReturnTypes(g, kb); err != nil {
		t.Fatalf("InferReturnTypes: %v", err)
	}
	if fn.InferredReturn != nil {
		t.Errorf("expected nil InferredReturn (declared type suppresses), got %+v", fn.InferredReturn)
	}
}

// ---------------------------------------------------------------------------
// T4.21 — declared "Object" fires inference
// ---------------------------------------------------------------------------

// TestInferReturnTypes_DeclaredObjectFires asserts that a function declared as
// returning "Object" (a trigger type) does get inference when sources are present.
func TestInferReturnTypes_DeclaredObjectFires(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(\"java\"): %v", err)
	}
	g := &CallGraph{
		Functions:     make(map[string]*FunctionDecl),
		Callers:       make(map[string][]string),
		TypeHierarchy: make(map[string][]string),
	}
	initID := FunctionID{Package: "javax.crypto.spec", Type: "SecretKeySpec", Name: "<init>#2"}
	fn := &FunctionDecl{
		ID:         FunctionID{Package: "com.example", Type: "U", Name: "getObj#0"},
		ReturnType: "Object", // trigger type
		ReturnSources: []SourceNode{
			{Type: "CALL_RESULT", DeclaredType: "javax.crypto.spec.SecretKeySpec", CallTarget: &initID},
		},
	}
	g.Functions["com.example.(U).getObj#0"] = fn

	if err := InferReturnTypes(g, kb); err != nil {
		t.Fatalf("InferReturnTypes: %v", err)
	}
	if fn.InferredReturn == nil {
		t.Fatal("expected InferredReturn to fire for Object declared type")
	}
	if fn.InferredReturn.Origin != OriginConstructor {
		t.Errorf("Origin = %q, want constructor", fn.InferredReturn.Origin)
	}
}

// ---------------------------------------------------------------------------
// T4.22 — latticeJoin: branch join with no LUB → nil origin join-failed
// ---------------------------------------------------------------------------

// TestLatticeJoin_JoinFailedMeansDifferentTypes asserts that a join across
// two candidates with no non-trivial LUB returns ok=false (join-failed).
func TestLatticeJoin_JoinFailedMeansDifferentTypes(t *testing.T) {
	hier := map[string][]string{
		"javax.crypto.SecretKey": {"java.security.Key"},
		"java.security.Key":      {"java.lang.Object"},
		"java.lang.String":       {"java.lang.Object"},
	}
	cands := []candidate{
		{typ: "javax.crypto.SecretKey", confidence: ConfidenceMedium, origin: OriginKBDirect},
		{typ: "java.lang.String", confidence: ConfidenceHigh, origin: OriginKBDirect},
	}
	_, ok := latticeJoin(cands, hier)
	if ok {
		t.Error("expected ok=false for join-failed (no useful LUB)")
	}
}

// shouldInfer tests (T4.9 — but part of inference_test.go group)

// TestShouldInfer_TriggerTypes asserts that common trigger types fire inference.
func TestShouldInfer_TriggerTypes(t *testing.T) {
	triggers := []string{
		"", "Object", "java.lang.Object", "byte[]", "Object[]",
		"Key", "java.security.Key", "T", "E", "V", "?",
		"int", "long", "boolean", "void", "EVP_CIPHER_CTX*", "EVP_CIPHER_CTX *",
	}
	for _, typ := range triggers {
		if !shouldInfer(typ) {
			t.Errorf("shouldInfer(%q) = false, want true", typ)
		}
	}
}

// TestShouldInfer_NonTriggerTypes asserts that specific declared types block inference.
func TestShouldInfer_NonTriggerTypes(t *testing.T) {
	nonTriggers := []string{
		"javax.crypto.SecretKey",
		"java.lang.String",
		"javax.crypto.Cipher",
		"java.security.PrivateKey",
		"EVP_CIPHER_CTX",
	}
	for _, typ := range nonTriggers {
		if shouldInfer(typ) {
			t.Errorf("shouldInfer(%q) = true, want false", typ)
		}
	}
}

func TestInferReturnTypes_CPointerReturn(t *testing.T) {
	kb, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: c
library:
  name: test-c
contracts:
  - method: EVP_CIPHER_CTX_new
    arity: 0
    return:
      type: EVP_CIPHER_CTX*
      confidence: high
`))
	if err != nil {
		t.Fatalf("load test KB: %v", err)
	}
	callee := FunctionID{Package: "example/crypto", Name: "EVP_CIPHER_CTX_new#0", Linkage: LinkageExternal}
	fn := &FunctionDecl{
		ID:            FunctionID{Package: "example/crypto", Name: "factory"},
		ReturnType:    "EVP_CIPHER_CTX *",
		ReturnSources: []SourceNode{{Type: sourceNodeCallResult, CallTarget: &callee}},
	}

	if err := InferReturnTypes(buildTestCallGraph(fn), kb); err != nil {
		t.Fatalf("InferReturnTypes: %v", err)
	}
	if fn.InferredReturn == nil || fn.InferredReturn.Type != "EVP_CIPHER_CTX*" || fn.InferredReturn.Origin != OriginKBDirect {
		t.Fatalf("InferredReturn = %#v, want KB-direct EVP_CIPHER_CTX*", fn.InferredReturn)
	}
}

func TestInferReturnTypes_CGlobalContractDoesNotMatchLocalSymbol(t *testing.T) {
	kb, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: c
library:
  name: test-c
contracts:
  - method: EVP_CIPHER_CTX_new
    arity: 0
    return:
      type: EVP_CIPHER_CTX*
      confidence: high
`))
	if err != nil {
		t.Fatalf("load test KB: %v", err)
	}

	for _, tt := range []struct {
		name    string
		linkage Linkage
		local   bool
	}{
		{name: "static", linkage: LinkageInternal},
		{name: "project global", linkage: LinkageExternal, local: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			callee := FunctionID{Package: "example/crypto", Name: "EVP_CIPHER_CTX_new#0", Linkage: tt.linkage}
			wrapper := &FunctionDecl{
				ID:            FunctionID{Package: "example/crypto", Name: "wrapper"},
				ReturnType:    "EVP_CIPHER_CTX*",
				ReturnSources: []SourceNode{{Type: sourceNodeCallResult, CallTarget: &callee}},
			}
			graph := buildTestCallGraph(wrapper)
			if tt.local {
				localID := FunctionID{Package: "example/crypto", Name: "EVP_CIPHER_CTX_new", Linkage: tt.linkage}
				graph.Functions[localID.String()] = &FunctionDecl{ID: localID, ReturnType: "EVP_CIPHER_CTX*"}
			}

			if err := InferReturnTypes(graph, kb); err != nil {
				t.Fatalf("InferReturnTypes: %v", err)
			}
			if wrapper.InferredReturn != nil {
				t.Fatalf("InferredReturn = %#v, want nil for local symbol", wrapper.InferredReturn)
			}
		})
	}
}

func TestInferReturnTypes_CGlobalFallbackDoesNotChangePythonArity(t *testing.T) {
	kb, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: python
library:
  name: test-python
contracts:
  - method: cryptography.Fernet.encrypt
    arity: 1
    return:
      type: builtins.bytes
      confidence: high
`))
	if err != nil {
		t.Fatalf("load test KB: %v", err)
	}
	callee := FunctionID{Package: "cryptography", Type: "Fernet", Name: "encrypt#2"}
	fn := &FunctionDecl{
		ID:            FunctionID{Package: "example", Name: "encrypt"},
		ReturnType:    "byte[]",
		ReturnSources: []SourceNode{{Type: sourceNodeCallResult, CallTarget: &callee}},
	}

	if err := InferReturnTypes(buildTestCallGraph(fn), kb); err != nil {
		t.Fatalf("InferReturnTypes: %v", err)
	}
	if fn.InferredReturn != nil {
		t.Fatalf("InferredReturn = %#v, want nil for Python arity mismatch", fn.InferredReturn)
	}
}

// ---------------------------------------------------------------------------
// Origin / Confidence constant tests (Batch 1, preserved)
// ---------------------------------------------------------------------------

// TestOriginConstants asserts that origin string constants are defined with
// their exact expected values. These constants feed the InferredReturn.Origin
// field and the export layer; any drift would break downstream consumers.
func TestOriginConstants(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"OriginConstructor", OriginConstructor, "constructor"},
		{"OriginKBDirect", OriginKBDirect, "kb-direct"},
		{"OriginKBConditional", OriginKBConditional, "kb-conditional"},
		{"OriginPropagated", OriginPropagated, "propagated"},
		{"OriginJoinFailed", OriginJoinFailed, "join-failed"},
	}

	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("constant %s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// TestConfidenceConstants asserts that confidence level constants are defined
// with their exact expected values.
func TestConfidenceConstants(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"ConfidenceHigh", ConfidenceHigh, "high"},
		{"ConfidenceMedium", ConfidenceMedium, "medium"},
		{"ConfidenceLow", ConfidenceLow, "low"},
	}

	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("constant %s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}
