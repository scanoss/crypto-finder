package callgraph

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// TestResolveFluentChainCalleesByContract_Password4J verifies that fluent method
// chains rooted at a static/library call have their intermediate links resolved
// through the contract KB rather than mis-guessed against a wildcard import.
//
// For `Password.hash(p).addRandomSalt().withBcrypt()`, addRandomSalt() and
// withBcrypt() arrive mis-resolved to org.bouncycastle.crypto.params.* (the file
// has `import org.bouncycastle.crypto.params.*`). Propagating the KB return type
// of Password.hash (-> HashBuilder) down the chain must correct both links to
// com.password4j.HashBuilder.
func TestResolveFluentChainCalleesByContract_Password4J(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	fn := &FunctionDecl{
		ID: FunctionID{Package: "com.example", Type: "Svc", Name: "hash#1"},
		Calls: []FunctionCall{
			// DFS append order is outermost-first; the pass must order by chain depth.
			{Callee: FunctionID{Package: "org.bouncycastle.crypto.params", Name: "withBcrypt#0"}, ChainID: "100", Raw: "Password.hash(p).addRandomSalt().withBcrypt", Line: 6},
			{Callee: FunctionID{Package: "org.bouncycastle.crypto.params", Name: "addRandomSalt#0"}, ChainID: "100", Raw: "Password.hash(p).addRandomSalt", Line: 6},
			{Callee: FunctionID{Package: "com.password4j", Type: "Password", Name: "hash#1"}, ChainID: "100", Raw: "Password.hash(p)", Line: 6},
		},
	}
	graph := &CallGraph{Functions: map[string]*FunctionDecl{fn.ID.String(): fn}}

	resolveFluentChainCalleesByContract(graph, kb)

	want := map[string]string{
		"withBcrypt":    "com.password4j.(HashBuilder).withBcrypt#0",
		"addRandomSalt": "com.password4j.(HashBuilder).addRandomSalt#0",
	}
	for i := range fn.Calls {
		base := BaseFunctionName(fn.Calls[i].Callee.Name)
		if expected, ok := want[base]; ok {
			if got := fn.Calls[i].Callee.String(); got != expected {
				t.Errorf("%s callee = %q, want %q", base, got, expected)
			}
		}
	}
}

// TestResolveFluentChainCalleesByContract_Password4JCheck verifies the verify-path
// fluent chain `Password.check(p, h).withBcrypt()` resolves through the KB the same
// way the hash-path does. Password.check returns a HashChecker (not a HashBuilder),
// so withBcrypt() must be rewritten to com.password4j.HashChecker.withBcrypt rather
// than left at the parser's mis-guessed receiver. Regression for the IBM dummy
// project where this link resolved to e.g. Password.withBcrypt / params.withBcrypt.
func TestResolveFluentChainCalleesByContract_Password4JCheck(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	fn := &FunctionDecl{
		ID: FunctionID{Package: "com.example", Type: "Svc", Name: "verify#2"},
		Calls: []FunctionCall{
			{Callee: FunctionID{Package: "com.password4j", Type: "Password", Name: "withBcrypt#0"}, ChainID: "300", Raw: "Password.check(p, h).withBcrypt", Line: 8},
			{Callee: FunctionID{Package: "com.password4j", Type: "Password", Name: "check#2"}, ChainID: "300", Raw: "Password.check(p, h)", Line: 8},
		},
	}
	graph := &CallGraph{Functions: map[string]*FunctionDecl{fn.ID.String(): fn}}

	resolveFluentChainCalleesByContract(graph, kb)

	const want = "com.password4j.(HashChecker).withBcrypt#0"
	for i := range fn.Calls {
		if BaseFunctionName(fn.Calls[i].Callee.Name) == "withBcrypt" {
			if got := fn.Calls[i].Callee.String(); got != want {
				t.Errorf("withBcrypt callee = %q, want %q", got, want)
			}
		}
	}
}

// TestResolveFluentChainCalleesByContract_LeavesUnknownChainsAlone ensures the
// pass is conservative: a chain whose methods are not in the KB is not rewritten.
func TestResolveFluentChainCalleesByContract_LeavesUnknownChainsAlone(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}
	fn := &FunctionDecl{
		ID: FunctionID{Package: "com.example", Type: "Svc", Name: "run#0"},
		Calls: []FunctionCall{
			{Callee: FunctionID{Package: "com.unknown", Type: "Foo", Name: "bar#0"}, ChainID: "200", Raw: "thing.bar", Line: 9},
			{Callee: FunctionID{Package: "com.unknown", Type: "Foo", Name: "baz#0"}, ChainID: "200", Raw: "thing.bar().baz", Line: 9},
		},
	}
	graph := &CallGraph{Functions: map[string]*FunctionDecl{fn.ID.String(): fn}}

	before := fn.Calls[1].Callee.String()
	resolveFluentChainCalleesByContract(graph, kb)
	if after := fn.Calls[1].Callee.String(); after != before {
		t.Errorf("unknown chain was rewritten: %q -> %q", before, after)
	}
}

// TestResolveFluentChainCalleesByContract_ReconcilesCallerIndex is the regression
// guard for the stale-index bug: buildCallerIndex runs in Phase 1 with the
// pre-resolution (messy, name-only fallback) callee keys; when the contract KB
// later rewrites a fluent link's Callee, the caller index MUST be reconciled to
// the resolved key, or the fragment export (and stitch) emit stale messy edges
// with no object identity. This asserts the caller moves from the old key to the
// resolved key and the resolved edge is recorded Exact.
func TestResolveFluentChainCalleesByContract_ReconcilesCallerIndex(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	fn := &FunctionDecl{
		ID: FunctionID{Package: "com.example", Type: "Svc", Name: "hash#1"},
		Calls: []FunctionCall{
			{Callee: FunctionID{Package: "org.bouncycastle.crypto.params", Name: "withBcrypt#0"}, ChainID: "100", Raw: "Password.hash(p).addRandomSalt().withBcrypt", Line: 6},
			{Callee: FunctionID{Package: "org.bouncycastle.crypto.params", Name: "addRandomSalt#0"}, ChainID: "100", Raw: "Password.hash(p).addRandomSalt", Line: 6},
			{Callee: FunctionID{Package: "com.password4j", Type: "Password", Name: "hash#1"}, ChainID: "100", Raw: "Password.hash(p)", Line: 6},
		},
	}
	callerKey := fn.ID.String()
	oldWithBcrypt := fn.Calls[0].Callee.String()    // org.bouncycastle.crypto.params.withBcrypt#0 (messy)
	oldAddRandomSalt := fn.Calls[1].Callee.String() // org.bouncycastle.crypto.params.addRandomSalt#0 (messy)

	// Simulate the Phase-1 caller index: the messy fallback keys point at the caller.
	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{callerKey: fn},
		Callers: map[string][]string{
			oldWithBcrypt:    {callerKey},
			oldAddRandomSalt: {callerKey},
		},
	}

	resolveFluentChainCalleesByContract(graph, kb)

	hasCaller := func(key string) bool {
		for _, c := range graph.Callers[key] {
			if c == callerKey {
				return true
			}
		}
		return false
	}

	for _, clean := range []string{
		"com.password4j.(HashBuilder).withBcrypt#0",
		"com.password4j.(HashBuilder).addRandomSalt#0",
	} {
		if !hasCaller(clean) {
			t.Errorf("caller index not reconciled: %q missing caller %q; Callers=%v", clean, callerKey, graph.Callers)
		}
	}
	if hasCaller(oldWithBcrypt) {
		t.Errorf("stale messy key %q still references the caller after reconciliation", oldWithBcrypt)
	}
	if hasCaller(oldAddRandomSalt) {
		t.Errorf("stale messy key %q still references the caller after reconciliation", oldAddRandomSalt)
	}
}
