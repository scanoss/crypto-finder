package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildGoGraph(t *testing.T, src string) *CallGraph {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	g, err := NewBuilderForEcosystem("go", NewGoParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return g
}

func goCalleeKeys(g *CallGraph) []string {
	var keys []string
	for _, fn := range g.Functions {
		for i := range fn.Calls {
			keys = append(keys, fn.Calls[i].Callee.String())
		}
	}
	return keys
}

func assertGoCall(t *testing.T, g *CallGraph, want string) {
	t.Helper()
	for _, k := range goCalleeKeys(g) {
		if k == want {
			return
		}
	}
	t.Errorf("missing call %q; recorded: %v", want, goCalleeKeys(g))
}

// TestGoBuilder_ChainedCallResolvesViaContract pins the fluent-chain idiom.
// The chained link was not emitted at all — parseSelectorCall only recognized
// identifier operands, so `sha256.New().Sum(x)` lost its Sum: the crypto
// OPERATION vanished from the graph while the factory survived. The link is
// now emitted with ChainID grouping, and the builder's contract pass resolves
// it through the KB (whose Go method keys use the `pkg.(Type).method`
// spelling, which the chain lookup previously never composed).
func TestGoBuilder_ChainedCallResolvesViaContract(t *testing.T) {
	g := buildGoGraph(t, `package app

import "crypto/sha256"

func HashChain(data []byte) []byte {
	return sha256.New().Sum(data)
}
`)
	assertGoCall(t, g, "crypto/sha256.New")
	assertGoCall(t, g, "hash.(Hash).Sum")
}

// TestGoBuilder_AssignedVarReceiverResolvesViaContract pins the dominant Go
// crypto shape: a `:=` binding from a KB-known producer, then method calls on
// it. The receiver's type only exists as the producer's contract return, so
// per-file resolution fell back to the caller's package — `app.Seal` — and,
// worse, could coincide with a real same-package function name and join it.
func TestGoBuilder_AssignedVarReceiverResolvesViaContract(t *testing.T) {
	g := buildGoGraph(t, `package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
)

// Encrypt collides by name with the method call below on purpose: the
// KB-typed receiver must win over the coincidental package function.
func Encrypt(dst, src []byte) {}

func Seal(key, nonce, data []byte) []byte {
	block, _ := aes.NewCipher(key)
	block.Encrypt(data, data)
	gcm, _ := cipher.NewGCM(block)
	return gcm.Seal(nil, nonce, data, nil)
}

func Digest(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

func DigestVar(data []byte) []byte {
	var h = sha256.New()
	return h.Sum(data)
}
`)
	assertGoCall(t, g, "crypto/cipher.(Block).Encrypt")
	assertGoCall(t, g, "crypto/cipher.(AEAD).Seal")
	assertGoCall(t, g, "hash.(Hash).Write")
	assertGoCall(t, g, "hash.(Hash).Sum")
}

// TestGoBuilder_AssignedVarConflictIsSkipped pins the conservative side: a
// variable rebound with a DIFFERENT contract type in the same function is not
// guessed at. The per-function map cannot see block scope, and guessing here
// is how an AES receiver gets reported as a Mac.
func TestGoBuilder_AssignedVarConflictIsSkipped(t *testing.T) {
	g := buildGoGraph(t, `package app

import (
	"crypto/sha256"
	"crypto/aes"
)

func f(key, data []byte) {
	x := sha256.New()
	x.Write(data)
	x, _ = aes.NewCipher(key)
	_ = x
}
`)
	for _, k := range goCalleeKeys(g) {
		if strings.HasPrefix(k, "hash.(Hash).") || strings.HasPrefix(k, "crypto/cipher.(Block).") {
			t.Errorf("conflicted variable was typed anyway: %q", k)
		}
	}
}

// TestGoBuilder_ReconciliationKeepsLegitimateEdge pins the caller-index
// reconciliation: a caller that invokes BOTH the method call and the
// same-named plain package function keeps its edge to the latter.
func TestGoBuilder_ReconciliationKeepsLegitimateEdge(t *testing.T) {
	g := buildGoGraph(t, `package app

import "crypto/aes"

func Encrypt(dst, src []byte) {}

func f(key, data []byte) {
	Encrypt(data, data)
	block, _ := aes.NewCipher(key)
	block.Encrypt(data, data)
}
`)
	assertGoCall(t, g, "crypto/cipher.(Block).Encrypt")
	callers := g.Callers["app.Encrypt"]
	found := false
	for _, c := range callers {
		if c == "app.f" {
			found = true
		}
	}
	if !found {
		t.Errorf("plain call edge to app.Encrypt was lost in reconciliation; callers: %v", callers)
	}
}

// TestGoBuilder_InCorpusProducerTypesReceiver pins the in-graph half of the
// assigned-var pass: a := binding from a function DECLARED IN THE CORPUS types
// through that declaration's return — no contract involved. Requires the
// declared return type to actually be extracted ("result" is a field of the
// declaration node, not a node type; matching a child typed "result" never
// fired, so every Go declaration carried an empty ReturnType).
func TestGoBuilder_InCorpusProducerTypesReceiver(t *testing.T) {
	g := buildGoGraph(t, `package app

type Keyring struct{}

func (k *Keyring) Unwrap(data []byte) []byte { return data }

func NewKeyring() *Keyring { return &Keyring{} }

func Open() (*Keyring, error) { return NewKeyring(), nil }

func use(data []byte) {
	k := NewKeyring()
	k.Unwrap(data)
	kr, _ := Open()
	kr.Unwrap(data)
}
`)
	found := 0
	for _, fn := range g.Functions {
		for i := range fn.Calls {
			if fn.Calls[i].Callee.String() == "app.(*Keyring).Unwrap" {
				found++
			}
		}
	}
	if found != 2 {
		t.Errorf("expected both := receivers to join app.(*Keyring).Unwrap, got %d; calls: %v", found, goCalleeKeys(g))
	}
}

// TestGoBuilder_AliasQualifiedProducerReturn pins the cross-package half of
// in-corpus producer typing: a helper in the root package returning a type
// from a subpackage, spelled through the file's import alias. The stored
// ReturnType used to carry the alias verbatim ("*format.Header"), which means
// nothing outside its file, so the := receiver could not be typed. The parser
// now expands the alias from the file's imports at extraction time. This is
// age's own Encrypt/encryptHdr shape.
func TestGoBuilder_AliasQualifiedProducerReturn(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "format"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"format/format.go": `package format

type Header struct{}

func (h *Header) Marshal() {}
`,
		"main.go": `package app

import "example.com/app/format"

func makeHeader() (*format.Header, error) {
	return &format.Header{}, nil
}

func run() {
	hdr, _ := makeHeader()
	hdr.Marshal()
}
`,
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	g, err := NewBuilderForEcosystem("go", NewGoParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "example.com/app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertGoCall(t, g, "example.com/app/format.(*Header).Marshal")
}
