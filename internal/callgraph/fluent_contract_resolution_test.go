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
