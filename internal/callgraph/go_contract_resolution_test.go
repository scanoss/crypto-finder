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

// TestGoBuilder_InterfaceMethodDispatch pins Go interface extraction: an
// interface method has no body, so the walk never declared it — a call on an
// interface-typed receiver had nothing to join and the builder's generic
// expandInterfaceDispatch, keyed on OwnerType "interface", never fired for Go.
func TestGoBuilder_InterfaceMethodDispatch(t *testing.T) {
	g := buildGoGraph(t, `package app

type Identity interface {
	Unwrap(data []byte) []byte
}

type X25519 struct{}

func (x *X25519) Unwrap(data []byte) []byte { return data }

type Scrypt struct{}

func (s *Scrypt) Unwrap(data []byte) []byte { return data }

func decrypt(id Identity, data []byte) []byte {
	return id.Unwrap(data)
}
`)
	if _, ok := g.Functions["app.(Identity).Unwrap"]; !ok {
		t.Fatalf("interface method not declared; decls: %v", goCalleeKeys(g))
	}
	assertGoCall(t, g, "app.(Identity).Unwrap")
	// the generic expansion must link decrypt to both implementations
	for _, impl := range []string{"app.(*X25519).Unwrap", "app.(*Scrypt).Unwrap"} {
		found := false
		for _, c := range g.Callers[impl] {
			if c == "app.decrypt" {
				found = true
			}
		}
		if !found {
			t.Errorf("interface dispatch did not link %s; callers: %v", impl, g.Callers[impl])
		}
	}
}

// TestGoParser_BlockScopedBindings pins Go lexical scoping (Go spec,
// "Declarations and scope"). One flat map per function let the type assertion
// in `if r, ok := r.(RecipientWithLabels); ok { ... }` rebind r for the WHOLE
// function, so the outer r's calls after the if were typed against the
// asserted interface — a silently wrong receiver, the same defect the Java
// parser had with sibling blocks.
func TestGoParser_BlockScopedBindings(t *testing.T) {
	g := buildGoGraph(t, `package app

type Recipient interface {
	Wrap(fileKey []byte) []byte
}

type RecipientWithLabels interface {
	WrapWithLabels(fileKey []byte) []byte
}

func wrap(r Recipient, fileKey []byte) []byte {
	if r, ok := r.(RecipientWithLabels); ok {
		return r.WrapWithLabels(fileKey)
	}
	return r.Wrap(fileKey)
}
`)
	assertGoCall(t, g, "app.(RecipientWithLabels).WrapWithLabels")
	assertGoCall(t, g, "app.(Recipient).Wrap")
	for _, k := range goCalleeKeys(g) {
		if k == "app.(RecipientWithLabels).Wrap" {
			t.Errorf("outer receiver typed against the asserted interface: %q", k)
		}
	}
}

// TestGoParser_ResidueClassesAreHonest pins the remaining shapes: a struct's
// func-typed field is declared as a member of its type; a conversion to a
// file-declared type is not a call; a bare call through a local func value or
// through a func-typed method receiver carries the honest empty identity; and
// an interface embedded in the same file contributes its methods to the
// embedder.
func TestGoParser_ResidueClassesAreHonest(t *testing.T) {
	g := buildGoGraph(t, `package app

type WriterFunc func(p []byte) (int, error)

func (f WriterFunc) Write(p []byte) (int, error) { return f(p) }

type Base interface {
	Wrap(data []byte) []byte
}

type Labeled interface {
	Base
	Labels() []string
}

type UI struct {
	DisplayMessage func(msg string) error
}

func use(ui *UI, l Labeled, data []byte) {
	ui.DisplayMessage("hello")
	l.Wrap(data)
	w := WriterFunc(nil)
	_ = w
	getLine := func() []byte { return nil }
	getLine()
}
`)
	assertGoCall(t, g, "app.(*UI).DisplayMessage")
	assertGoCall(t, g, "app.(Labeled).Wrap")
	for _, k := range goCalleeKeys(g) {
		if strings.HasSuffix(k, ".WriterFunc") {
			t.Errorf("conversion recorded as a call: %q", k)
		}
		if strings.HasSuffix(k, ".getLine") && !strings.HasPrefix(k, ".") {
			t.Errorf("func-value call claims an owner: %q", k)
		}
		if k == "app.f" {
			t.Errorf("func-typed receiver call claims the package: %q", k)
		}
	}
}

// TestGoParser_OracleParityShapes pins the three shapes the go/types
// differential surfaced: a call whose receiver is a field chain was dropped
// entirely; a call in a package-level var initializer had no containing
// function; and a rebinding `pk, ok := pk.(T)` must resolve its own right-hand
// side against the OUTER binding (Go's declared-before-use), which a
// scope-level overlay got wrong and only textual-order collection gets right.
func TestGoParser_OracleParityShapes(t *testing.T) {
	g := buildGoGraph(t, `package app

import "crypto/sha256"

type inner struct{}

func (inner) XORKeyStream(dst, src []byte) {}

type outer struct{ c inner }

var packageDigest = sha256.New()

type PublicKey interface {
	Type() string
}

type CryptoPublicKey interface {
	CryptoPublicKey() PublicKey
}

func (s *outer) run(data []byte, pk PublicKey) {
	s.c.XORKeyStream(data, data)
	if pk, ok := pk.(CryptoPublicKey); ok {
		_ = pk
	}
}
`)
	// campo-cadena: emitida (honesta), no ausente
	foundField := false
	for _, fn := range g.Functions {
		for i := range fn.Calls {
			if fn.Calls[i].Raw == "s.c.XORKeyStream" {
				foundField = true
			}
		}
	}
	if !foundField {
		t.Error("field-chain receiver call was dropped from the graph")
	}
	// var a nivel paquete: la llamada existe dentro del <varinit> del archivo
	assertGoCall(t, g, "crypto/sha256.New")
	foundInit := false
	for k := range g.Functions {
		if strings.HasPrefix(k, "app.<varinit:") {
			foundInit = true
		}
	}
	if !foundInit {
		t.Error("package-level var initializer produced no containing declaration")
	}
	// la asercion que se rebindea a si misma no debe fabricar un tipo para su RHS
	for _, fn := range g.Functions {
		for i := range fn.Calls {
			c := &fn.Calls[i]
			if c.Raw == "pk.Type" && c.Callee.Type == "CryptoPublicKey" {
				t.Errorf("assertion binding leaked into its own right-hand side: %s", c.Callee.String())
			}
		}
	}
}

// TestGoBuilder_IdentityCollisionsAndSpelling pins three graph-identity rules
// the go/types differential surfaced: multiple init functions coexist (each
// under a file-discriminated name — one shared key kept only the last one's
// calls); build-tagged duplicates of one function union their calls instead of
// the later file silently dropping the earlier body; and a value-spelled call
// to a pointer-declared method is respelled to the declared form, as go/types
// reports it, so the same member joins instead of dangling.
func TestGoBuilder_IdentityCollisionsAndSpelling(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"a.go": `package app

import "crypto/sha256"

func init() { sha256.New() }

type Box struct{ n int }

func (b *Box) Bump() { b.n++ }

func use() {
	var b Box
	b.Bump()
}
`,
		"b.go": `package app

import "crypto/hmac"
import "crypto/sha256"

func init() { hmac.New(sha256.New, nil) }
`,
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	g, err := NewBuilderForEcosystem("go", NewGoParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// ambos init sobreviven, con sus llamadas
	assertGoCall(t, g, "crypto/sha256.New")
	assertGoCall(t, g, "crypto/hmac.New")
	inits := 0
	for k := range g.Functions {
		if strings.HasPrefix(k, "app.<init:") {
			inits++
		}
	}
	if inits != 2 {
		t.Errorf("expected 2 file-discriminated init declarations, got %d", inits)
	}
	// respelling: la llamada por valor joinea el metodo declarado en puntero
	assertGoCall(t, g, "app.(*Box).Bump")
}

// TestGoParser_LocalsShadowImportedPackages pins Go's innermost-scope rule
// against the import table: a local named like an imported package makes
// `key.AESKeyBytes()` a METHOD call, yet the import lookup ran first and
// emitted a call into the package. Found by the go/types differential on
// tink-go (a parameter named key next to the imported package key) and on
// x/crypto (hash, ok := HashIdToHash(...) next to the package hash — a name
// bound with no known type must still shadow).
func TestGoParser_LocalsShadowImportedPackages(t *testing.T) {
	g := buildGoGraph(t, `package app

import (
	"crypto/sha256"
	"hash"
)

type Key struct{}

func (k *Key) Bytes() []byte { return nil }

func lookup(id int) (hash.Hash, bool) { return sha256.New(), true }

func use(key *Key) []byte {
	hash, ok := lookup(1)
	if !ok {
		return nil
	}
	hash.Reset()
	for _, key := range []*Key{key} {
		key.Bytes()
	}
	return key.Bytes()
}
`)
	// el local hash sombrea al paquete Y se tipa por el retorno del productor
	assertGoCall(t, g, "hash.(Hash).Reset")
	// el parametro key sombrea y joinea su metodo
	assertGoCall(t, g, "app.(*Key).Bytes")
	for _, k := range goCalleeKeys(g) {
		if k == "hash.Reset" {
			t.Errorf("local hash did not shadow package hash: %q", k)
		}
		// la range var sombrea (queda honesta-sin-anclar); nunca una llamada de paquete
		if k == "app.Bytes" {
			t.Errorf("range-bound key resolved as a package call: %q", k)
		}
	}
}
