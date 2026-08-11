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

// TestResolveFluentChainCalleesByContract_JavaVarargsArity is the chain-pass
// regression for scanoss/crypto-finder#195: a fluent chain link that passes
// more literal arguments than the contract's collapsed varargs arity
// (`.protocols("TLSv1.3", "TLSv1.2")` at literal arity 2 vs the
// protocols(String...) contract keyed at arity 1) must still resolve against
// the varargs contract — normalized to the contract's declared arity — and
// resolution must keep walking so the terminal build() link resolves too.
func TestResolveFluentChainCalleesByContract_JavaVarargsArity(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	// Mirrors the parser's output for
	// SslContextBuilder.forServer(c, k).sslProvider(P).protocols("a", "b").build():
	// the links after the static root arrive unresolved, with the raw receiver
	// expression as the callee package.
	messy := "SslContextBuilder.forServer(c, k).sslProvider(P)"
	fn := &FunctionDecl{
		ID: FunctionID{Package: "com.example", Type: "TlsSetup", Name: "setup#2"},
		Calls: []FunctionCall{
			{Callee: FunctionID{Package: messy + ".protocols(\"a\", \"b\")", Name: "build#0"}, ChainID: "400", Raw: messy + ".protocols(\"a\", \"b\").build", Line: 4},
			{Callee: FunctionID{Package: messy, Name: "protocols#2"}, ChainID: "400", Raw: messy + ".protocols", Line: 4, Arguments: []string{"\"a\"", "\"b\""}},
			{Callee: FunctionID{Package: "io.netty.handler.ssl", Type: "SslContextBuilder", Name: "sslProvider#1"}, ChainID: "400", Raw: messy, Line: 4, Arguments: []string{"P"}},
			{Callee: FunctionID{Package: "io.netty.handler.ssl", Type: "SslContextBuilder", Name: "forServer#2"}, ChainID: "400", Raw: "SslContextBuilder.forServer", Line: 4, Arguments: []string{"c", "k"}},
		},
	}
	graph := &CallGraph{Functions: map[string]*FunctionDecl{fn.ID.String(): fn}}

	resolveFluentChainCalleesByContract(graph, kb)

	want := map[string]string{
		// The 2-arg varargs call site resolves to the contract's collapsed
		// arity-1 key, per the KB convention that a Java varargs parameter
		// occupies one slot.
		"protocols": "io.netty.handler.ssl.(SslContextBuilder).protocols#1",
		"build":     "io.netty.handler.ssl.(SslContextBuilder).build#0",
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

// TestResolveFluentChainCalleesByContract_VarargsFallbackRejectsPositionalOverloads
// guards the varargs fallback against false matches: a call site with MORE
// arguments than any contracted arity of the same method name must NOT
// collapse onto an ordinary positional (non-varargs) lower-arity overload —
// it would inherit a contract role that does not belong to the call.
// SslContextBuilder.ciphers is contracted at arities 1 and 2, neither
// varargs, so a 3-argument .ciphers(a, b, c) link must stay unresolved
// (while the chain walk still continues past it).
func TestResolveFluentChainCalleesByContract_VarargsFallbackRejectsPositionalOverloads(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	messy := "SslContextBuilder.forServer(c, k)"
	fn := &FunctionDecl{
		ID: FunctionID{Package: "com.example", Type: "TlsSetup", Name: "setup#2"},
		Calls: []FunctionCall{
			{Callee: FunctionID{Package: messy + ".ciphers(a, b, c)", Name: "build#0"}, ChainID: "600", Raw: messy + ".ciphers(a, b, c).build", Line: 9},
			{Callee: FunctionID{Package: messy, Name: "ciphers#3"}, ChainID: "600", Raw: messy + ".ciphers", Line: 9, Arguments: []string{"a", "b", "c"}},
			{Callee: FunctionID{Package: "io.netty.handler.ssl", Type: "SslContextBuilder", Name: "forServer#2"}, ChainID: "600", Raw: "SslContextBuilder.forServer", Line: 9, Arguments: []string{"c", "k"}},
		},
	}
	graph := &CallGraph{Functions: map[string]*FunctionDecl{fn.ID.String(): fn}}

	ciphersBefore := fn.Calls[1].Callee.String()
	resolveFluentChainCalleesByContract(graph, kb)

	if got := fn.Calls[1].Callee.String(); got != ciphersBefore {
		t.Errorf("3-arg ciphers link collapsed onto a positional overload: %q -> %q (contracts at arities 1 and 2 are not varargs)", ciphersBefore, got)
	}
	// The unresolved link must still not orphan the rest of the chain.
	const wantBuild = "io.netty.handler.ssl.(SslContextBuilder).build#0"
	if got := fn.Calls[0].Callee.String(); got != wantBuild {
		t.Errorf("build callee = %q, want %q", got, wantBuild)
	}
}

// TestResolveFluentChainCalleesByContract_ContinuesPastUnknownLink asserts the
// chain walk is not halted by one link the KB has no contract for: the unknown
// link itself is left untouched (no guessing), but — fluent builder methods
// return their receiver — the propagated receiver type carries forward so the
// downstream contracted links still resolve. Companion regression to the
// varargs case above (scanoss/crypto-finder#195): before the fix the first
// unmatched link orphaned every remaining link in the chain.
func TestResolveFluentChainCalleesByContract_ContinuesPastUnknownLink(t *testing.T) {
	kb, err := contracts.LoadEmbedded("java")
	if err != nil {
		t.Fatalf("LoadEmbedded(java): %v", err)
	}

	messy := "SslContextBuilder.forServer(c, k).withCustomTweak()"
	fn := &FunctionDecl{
		ID: FunctionID{Package: "com.example", Type: "TlsSetup", Name: "setup#2"},
		Calls: []FunctionCall{
			{Callee: FunctionID{Package: messy, Name: "build#0"}, ChainID: "500", Raw: messy + ".build", Line: 7},
			{Callee: FunctionID{Package: "SslContextBuilder.forServer(c, k)", Name: "withCustomTweak#0"}, ChainID: "500", Raw: "SslContextBuilder.forServer(c, k).withCustomTweak", Line: 7},
			{Callee: FunctionID{Package: "io.netty.handler.ssl", Type: "SslContextBuilder", Name: "forServer#2"}, ChainID: "500", Raw: "SslContextBuilder.forServer", Line: 7, Arguments: []string{"c", "k"}},
		},
	}
	graph := &CallGraph{Functions: map[string]*FunctionDecl{fn.ID.String(): fn}}

	unknownBefore := fn.Calls[1].Callee.String()
	resolveFluentChainCalleesByContract(graph, kb)

	if got := fn.Calls[1].Callee.String(); got != unknownBefore {
		t.Errorf("unknown link was rewritten: %q -> %q", unknownBefore, got)
	}
	const wantBuild = "io.netty.handler.ssl.(SslContextBuilder).build#0"
	if got := fn.Calls[0].Callee.String(); got != wantBuild {
		t.Errorf("build callee = %q, want %q (chain walk must continue past the unknown link)", got, wantBuild)
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
