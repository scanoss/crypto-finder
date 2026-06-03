package scan

import (
	"sort"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
)

// methodsOf returns the sorted resolved method base names of the derived calls,
// for order-independent assertions.
func methodsOf(calls []*callgraph.FunctionCall) []string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, callgraph.BaseFunctionName(c.Callee.Name))
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestDeriveObjectLifecycleCalls_StatefulObject covers the BouncyCastle digest
// pattern: the terminal is the constructor (AssignedVar=digest); supporting
// calls are the methods invoked on `digest`. Calls on other variables (getBytes
// on `input`) and free-function calls (Hex.toHexString) are excluded.
func TestDeriveObjectLifecycleCalls_StatefulObject(t *testing.T) {
	fn := &callgraph.FunctionDecl{
		Calls: []callgraph.FunctionCall{
			{Callee: callgraph.FunctionID{Type: "SHA3Digest", Name: "<init>#1"}, AssignedVar: "digest", Line: 6},
			{Callee: callgraph.FunctionID{Type: "String", Name: "getBytes#0"}, ReceiverVar: "input", Line: 7},
			{Callee: callgraph.FunctionID{Type: "SHA3Digest", Name: "update#3"}, ReceiverVar: "digest", Line: 8},
			{Callee: callgraph.FunctionID{Type: "SHA3Digest", Name: "getDigestSize#0"}, ReceiverVar: "digest", Line: 9},
			{Callee: callgraph.FunctionID{Type: "SHA3Digest", Name: "doFinal#2"}, ReceiverVar: "digest", Line: 10},
			{Callee: callgraph.FunctionID{Type: "Hex", Name: "toHexString#1"}, Line: 11},
		},
	}
	terminal := &fn.Calls[0] // the constructor

	got := methodsOf(deriveObjectLifecycleCalls(fn, terminal))
	want := []string{"doFinal", "getDigestSize", "update"}
	if !equalStrings(got, want) {
		t.Errorf("derived = %v, want %v", got, want)
	}
}

// TestDeriveObjectLifecycleCalls_FluentChain covers the Password4J pattern: the
// terminal is the chain root (withBcrypt, ChainID set, AssignedVar=hash);
// supporting calls are the other chain links plus the follow-up getResult() on
// the assigned variable.
func TestDeriveObjectLifecycleCalls_FluentChain(t *testing.T) {
	fn := &callgraph.FunctionDecl{
		Calls: []callgraph.FunctionCall{
			{Callee: callgraph.FunctionID{Type: "Password", Name: "hash#1"}, ChainID: "100", Line: 6},
			{Callee: callgraph.FunctionID{Type: "HashBuilder", Name: "addRandomSalt#0"}, ChainID: "100", Line: 6},
			{Callee: callgraph.FunctionID{Type: "HashBuilder", Name: "withBcrypt#0"}, ChainID: "100", AssignedVar: "hash", Line: 6},
			{Callee: callgraph.FunctionID{Type: "Hash", Name: "getResult#0"}, ReceiverVar: "hash", Line: 7},
		},
	}
	terminal := &fn.Calls[2] // withBcrypt (chain root)

	got := methodsOf(deriveObjectLifecycleCalls(fn, terminal))
	want := []string{"addRandomSalt", "getResult", "hash"}
	if !equalStrings(got, want) {
		t.Errorf("derived = %v, want %v", got, want)
	}
}

// TestDeriveObjectLifecycleCalls_KeygenObjectAndConstructor covers EC keygen:
// the terminal is generateKeyPair() on `generator` (ReceiverVar=generator);
// supporting calls include the configuration call init() on the same object and
// the constructor that produced it (AssignedVar=generator). A parameter object
// bound to a different variable (`params`) is NOT pulled in (object-lifecycle
// scope, not data-flow closure).
func TestDeriveObjectLifecycleCalls_KeygenObjectAndConstructor(t *testing.T) {
	fn := &callgraph.FunctionDecl{
		Calls: []callgraph.FunctionCall{
			{Callee: callgraph.FunctionID{Type: "ECKeyPairGenerator", Name: "<init>#0"}, AssignedVar: "generator", Line: 5},
			{Callee: callgraph.FunctionID{Type: "ECKeyGenerationParameters", Name: "<init>#2"}, AssignedVar: "params", Line: 6},
			{Callee: callgraph.FunctionID{Type: "ECKeyPairGenerator", Name: "init#1"}, ReceiverVar: "generator", Line: 7},
			{Callee: callgraph.FunctionID{Type: "ECKeyPairGenerator", Name: "generateKeyPair#0"}, ReceiverVar: "generator", Line: 8},
		},
	}
	terminal := &fn.Calls[3] // generateKeyPair

	got := methodsOf(deriveObjectLifecycleCalls(fn, terminal))
	want := []string{"<init>", "init"} // ECKeyPairGenerator ctor + init; NOT the params ctor
	if !equalStrings(got, want) {
		t.Errorf("derived = %v, want %v", got, want)
	}
}
