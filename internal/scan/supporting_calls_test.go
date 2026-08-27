package scan

import (
	"os"
	"path/filepath"
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

// TestDeriveObjectLifecycleCalls_ParameterReceiver covers a Python parameter
// object: the terminal call and a prior setup call are both invoked on the
// same function parameter (ReceiverVar), so the setup call must be grouped
// as a supporting call for the terminal.
func TestDeriveObjectLifecycleCalls_ParameterReceiver(t *testing.T) {
	fn := &callgraph.FunctionDecl{
		Calls: []callgraph.FunctionCall{
			{Callee: callgraph.FunctionID{Name: "set_key"}, ReceiverVar: "cipher", Line: 2},
			{Callee: callgraph.FunctionID{Name: "encrypt"}, ReceiverVar: "cipher", Line: 3},
		},
	}
	terminal := &fn.Calls[1] // encrypt

	got := methodsOf(deriveObjectLifecycleCalls(fn, terminal))
	want := []string{"set_key"}
	if !equalStrings(got, want) {
		t.Errorf("derived = %v, want %v", got, want)
	}
}

// TestDeriveObjectLifecycleCalls_SelfAttrRebinding covers the selector's
// positional protection for an AssignedVar-only constructor terminal. The
// parser-to-selector operation-terminal case is covered separately below.
func TestDeriveObjectLifecycleCalls_SelfAttrRebinding(t *testing.T) {
	fn := &callgraph.FunctionDecl{
		Calls: []callgraph.FunctionCall{
			{Callee: callgraph.FunctionID{Type: "self.cipher", Name: "<init>"}, AssignedVar: "self.cipher", Line: 2}, // AES()
			{Callee: callgraph.FunctionID{Name: "encrypt"}, ReceiverVar: "self.cipher", Line: 3},                     // encrypt(a)
			{Callee: callgraph.FunctionID{Type: "self.cipher", Name: "<init>"}, AssignedVar: "self.cipher", Line: 4}, // RSA()
			{Callee: callgraph.FunctionID{Name: "encrypt"}, ReceiverVar: "self.cipher", Line: 5},                     // encrypt(b)
		},
	}

	// The finding is the SECOND constructor (RSA()) — an AssignedVar-only
	// producer, which is the shape deriveObjectLifecycleCalls can order-protect.
	secondCtor := &fn.Calls[2]
	got := indexOf(fn.Calls, secondCtor)
	derived := lifecycleCallIndices(toIdentities(fn.Calls), got)

	if selected(derived, 1) {
		t.Errorf("second self.cipher constructor derived = %v; must NOT include encrypt(a), bound to the FIRST assignment", derived)
	}
	if !selected(derived, 3) {
		t.Errorf("second self.cipher constructor derived = %v; must include encrypt(b), bound to this assignment", derived)
	}
}

// toIdentities projects FunctionCall fixtures into the objectIdentity shape
// lifecycleCallIndices operates on.
func toIdentities(calls []callgraph.FunctionCall) []objectIdentity {
	out := make([]objectIdentity, len(calls))
	for i := range calls {
		out[i] = objectIdentity{ReceiverVar: calls[i].ReceiverVar, AssignedVar: calls[i].AssignedVar, ChainID: calls[i].ChainID}
	}
	return out
}

// indexOf returns the index of target within calls by pointer identity.
func indexOf(calls []callgraph.FunctionCall, target *callgraph.FunctionCall) int {
	for i := range calls {
		if &calls[i] == target {
			return i
		}
	}
	return -1
}

// selected reports whether idx is present in got.
func selected(got []int, idx int) bool {
	for _, i := range got {
		if i == idx {
			return true
		}
	}
	return false
}

// TestDeriveObjectLifecycleCalls_ModuleSyntheticReceiver covers a Python
// module-level object: `cipher = Cipher()` followed by `cipher.set_key(k)`
// and `cipher.encrypt(data)`, all direct children of the synthetic
// `<module>` decl. The setup call must group as a supporting call for the
// terminal, exactly like any other receiver/producer pair — the `<module>`
// decl is just a regular FunctionDecl container from this function's view.
func TestDeriveObjectLifecycleCalls_ModuleSyntheticReceiver(t *testing.T) {
	fn := &callgraph.FunctionDecl{
		Calls: []callgraph.FunctionCall{
			{Callee: callgraph.FunctionID{Type: "Cipher", Name: "<init>"}, AssignedVar: "cipher", Line: 1},
			{Callee: callgraph.FunctionID{Name: "set_key"}, ReceiverVar: "cipher", Line: 2},
			{Callee: callgraph.FunctionID{Name: "encrypt"}, ReceiverVar: "cipher", Line: 3},
		},
	}
	terminal := &fn.Calls[2] // encrypt

	got := methodsOf(deriveObjectLifecycleCalls(fn, terminal))
	want := []string{"<init>", "set_key"}
	if !equalStrings(got, want) {
		t.Errorf("derived = %v, want %v", got, want)
	}
}

// TestLifecycleCallIndices_ReassignedReceiverExcludesEarlierCalls pins that a
// reassigned variable does not merge two objects into one lifecycle. It mirrors
// how a Java client wraps a plain socket in TLS:
//
//	socket.setSoTimeout(t);                       // plain TCP socket
//	factory = SSLSocketFactory.getDefault();      // terminal crypto call
//	socket  = factory.createSocket(socket, ...);  // socket now holds the TLS one
//	socket.setSSLParameters(p);
//
// Without an order constraint the pre-TLS setSoTimeout joins the TLS finding's
// evidence, because it is a call on a variable that later holds the TLS socket.
func TestLifecycleCallIndices_ReassignedReceiverExcludesEarlierCalls(t *testing.T) {
	calls := []objectIdentity{
		{ReceiverVar: "socket"},                         // 0: setSoTimeout, plain socket
		{AssignedVar: "factory"},                        // 1: terminal getDefault()
		{ReceiverVar: "factory", AssignedVar: "socket"}, // 2: createSocket, rebinds socket
		{ReceiverVar: "socket"},                         // 3: setSSLParameters
		{ReceiverVar: "socket"},                         // 4: getSession
	}

	got := lifecycleCallIndices(calls, 1)

	selected := map[int]bool{}
	for _, i := range got {
		selected[i] = true
	}
	if selected[0] {
		t.Errorf("index 0 selected: a call made before the receiver was rebound belongs to the previous object (got %v)", got)
	}
	for _, want := range []int{2, 3, 4} {
		if !selected[want] {
			t.Errorf("index %d missing from lifecycle %v", want, got)
		}
	}
}

// TestPythonSelfAttrRebindingSplitsOperationLifecycle builds a real Python
// callgraph and proves that a terminal operation after self.attr reassignment
// derives only calls belonging to the new object generation. The selector is
// unchanged; the parser supplies generation-aware identities.
func TestPythonSelfAttrRebindingSplitsOperationLifecycle(t *testing.T) {
	dir := t.TempDir()
	src := `from Crypto.Cipher import AES, RSA

class Worker:
    def run(self, key, first, second):
        self.cipher = AES.new(key)
        self.cipher.configure(first)
        self.cipher.encrypt(first)
        self.cipher = RSA.new(key)
        self.cipher.configure(second)
        self.cipher.encrypt(second)
`
	if err := os.WriteFile(filepath.Join(dir, "worker.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "mypkg"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	run := graph.Functions["mypkg.(Worker).run"]
	if run == nil {
		t.Fatalf("missing mypkg.(Worker).run; functions=%v", graph.Functions)
	}

	var terminal *callgraph.FunctionCall
	for i := range run.Calls {
		if callgraph.BaseFunctionName(run.Calls[i].Callee.Name) == "encrypt" && run.Calls[i].Line == 10 {
			terminal = &run.Calls[i]
			break
		}
	}
	if terminal == nil {
		t.Fatalf("second encrypt operation not found: %#v", run.Calls)
	}
	derived := deriveObjectLifecycleCalls(run, terminal)
	seenLines := make(map[int]bool, len(derived))
	for _, call := range derived {
		seenLines[call.Line] = true
	}
	for _, line := range []int{5, 6, 7} {
		if seenLines[line] {
			t.Errorf("second-generation terminal derived first-generation line %d: %#v", line, derived)
		}
	}
	for _, line := range []int{8, 9} {
		if !seenLines[line] {
			t.Errorf("second-generation terminal omitted line %d: %#v", line, derived)
		}
	}
}
