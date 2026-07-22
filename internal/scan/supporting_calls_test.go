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

func TestDeriveObjectLifecycleCalls_FollowsProducedPrimitive(t *testing.T) {
	fn := &callgraph.FunctionDecl{
		Calls: []callgraph.FunctionCall{
			{Callee: callgraph.FunctionID{Type: "KeysetHandle", Name: "generateNew#1"}, AssignedVar: "handle", Line: 5},
			{Callee: callgraph.FunctionID{Type: "KeysetHandle", Name: "getPrimitive#1"}, ReceiverVar: "handle", AssignedVar: "aead", Line: 6},
			{Callee: callgraph.FunctionID{Type: "Aead", Name: "encrypt#2"}, ReceiverVar: "aead", AssignedVar: "ciphertext", Line: 7},
			{Callee: callgraph.FunctionID{Type: "Aead", Name: "decrypt#2"}, ReceiverVar: "aead", Line: 8},
			{Callee: callgraph.FunctionID{Type: "Logger", Name: "info#1"}, ReceiverVar: "logger", Line: 9},
		},
	}

	got := methodsOf(deriveObjectLifecycleCalls(fn, &fn.Calls[0]))
	want := []string{"decrypt", "encrypt", "getPrimitive"}
	if !equalStrings(got, want) {
		t.Errorf("derived = %v, want %v", got, want)
	}
}

func TestDeriveObjectLifecycleCalls_DoesNotCrossProducedPrimitiveBranches(t *testing.T) {
	fn := &callgraph.FunctionDecl{
		Calls: []callgraph.FunctionCall{
			{Callee: callgraph.FunctionID{Type: "KeysetHandle", Name: "generateNew#1"}, AssignedVar: "handle", Line: 5},
			{Callee: callgraph.FunctionID{Type: "KeysetHandle", Name: "getPrimitive#1"}, ReceiverVar: "handle", AssignedVar: "aead", Line: 6},
			{Callee: callgraph.FunctionID{Type: "KeysetHandle", Name: "getPrimitive#1"}, ReceiverVar: "handle", AssignedVar: "mac", Line: 7},
			{Callee: callgraph.FunctionID{Type: "Aead", Name: "encrypt#2"}, ReceiverVar: "aead", Line: 8},
			{Callee: callgraph.FunctionID{Type: "Mac", Name: "computeMac#1"}, ReceiverVar: "mac", Line: 9},
		},
	}

	got := methodsOf(deriveObjectLifecycleCalls(fn, &fn.Calls[3]))
	want := []string{"generateNew", "getPrimitive"}
	if !equalStrings(got, want) {
		t.Errorf("derived = %v, want %v", got, want)
	}
}

func TestDeriveObjectLifecycleCalls_FollowsReceiverFactoryResultOnly(t *testing.T) {
	fn := &callgraph.FunctionDecl{
		Calls: []callgraph.FunctionCall{
			{Callee: callgraph.FunctionID{Type: "Factory", Name: "<init>#0"}, AssignedVar: "factory", Line: 5},
			{Callee: callgraph.FunctionID{Type: "Factory", Name: "create#1"}, ReceiverVar: "factory", AssignedVar: "encryptor", Line: 6},
			{Callee: callgraph.FunctionID{Type: "Factory", Name: "create#1"}, ReceiverVar: "factory", AssignedVar: "decryptor", Line: 7},
			{Callee: callgraph.FunctionID{Type: "Cipher", Name: "init#2"}, ReceiverVar: "encryptor", Line: 8},
			{Callee: callgraph.FunctionID{Type: "Cipher", Name: "doFinal#2"}, ReceiverVar: "encryptor", Line: 9},
			{Callee: callgraph.FunctionID{Type: "Cipher", Name: "doFinal#2"}, ReceiverVar: "decryptor", Line: 10},
		},
	}

	got := methodsOf(deriveObjectLifecycleCalls(fn, &fn.Calls[1]))
	want := []string{"<init>", "doFinal", "init"}
	if !equalStrings(got, want) {
		t.Errorf("derived = %v, want %v", got, want)
	}
}

func TestDeriveObjectLifecycleCalls_KeepsReceiverSetupWhenOperationResultIsUsed(t *testing.T) {
	fn := &callgraph.FunctionDecl{
		Calls: []callgraph.FunctionCall{
			{Callee: callgraph.FunctionID{Type: "MessageDigest", Name: "getInstance#1"}, AssignedVar: "digest", Line: 5},
			{Callee: callgraph.FunctionID{Type: "MessageDigest", Name: "update#1"}, ReceiverVar: "digest", Line: 6},
			{Callee: callgraph.FunctionID{Type: "MessageDigest", Name: "digest#0"}, ReceiverVar: "digest", AssignedVar: "hash", Line: 7},
			{Callee: callgraph.FunctionID{Type: "byte[]", Name: "clone#0"}, ReceiverVar: "hash", Line: 8},
		},
	}

	got := methodsOf(deriveObjectLifecycleCalls(fn, &fn.Calls[2]))
	want := []string{"clone", "getInstance", "update"}
	if !equalStrings(got, want) {
		t.Errorf("derived = %v, want %v", got, want)
	}
}
