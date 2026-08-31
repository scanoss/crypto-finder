package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGoParser_PredeclaredIdentifiersAreNotCalls pins Go's universe scope: a
// predeclared identifier with no backing declaration must not survive as a
// call into the caller's package — `app.len` matches nothing and reaches no
// user code (26% of this repository's own call sites before the fix). The
// pruning lives in the builder so a package that declares its own `new` or
// `print` (etcd does both) keeps those calls; see the shadowing test below.
func TestGoParser_PredeclaredIdentifiersAreNotCalls(t *testing.T) {
	src := `package app

import "crypto/aes"

func encrypt(key []byte) error {
	buf := make([]byte, len(key))
	n := int(len(buf))
	copy(buf, key)
	block, err := aes.NewCipher(buf)
	if err != nil {
		panic(err)
	}
	_ = n
	_ = block
	return helper()
}

func helper() error { return nil }
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	g, err := NewBuilderForEcosystem("go", NewGoParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	var keys []string
	for _, fn := range g.Functions {
		for j := range fn.Calls {
			keys = append(keys, fn.Calls[j].Callee.String())
		}
	}

	for _, predeclared := range []string{"make", "len", "int", "copy", "panic"} {
		for _, k := range keys {
			if strings.HasSuffix(k, "."+predeclared) {
				t.Errorf("predeclared %q recorded as a call to %q; it belongs to no package", predeclared, k)
			}
		}
	}

	// las llamadas reales siguen ahi
	wantAny := []string{"crypto/aes.NewCipher", "app.helper"}
	for _, want := range wantAny {
		found := false
		for _, k := range keys {
			if k == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing real call %q; recorded: %v", want, keys)
		}
	}
}

// TestGoParser_GenericReceiverIdentity pins the identity of methods declared on
// generic types. A `Gen[T]` value receiver parsed as generic_type, which no
// case matched, so the method lost its owning type entirely — an orphaned
// declaration no call can join. The pointer form kept the raw `[T]` in the
// identity, which a call on a Gen[int] likewise cannot match. Both must erase
// to the bare type name, as Go itself does when forming a method set.
func TestGoParser_GenericReceiverIdentity(t *testing.T) {
	src := `package p

type Plain struct{ v int }

func (x Plain) Get() int     { return x.v }
func (x *Plain) Set(v int)   { x.v = v }

type Gen[T any] struct{ v T }

func (g Gen[T]) Get() T      { return g.v }
func (g *Gen[T]) Set(v T)    { g.v = v }

type Pair[K comparable, V any] struct{ k K; v V }

func (p *Pair[K, V]) Key() K { return p.k }
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	analyses, err := NewGoParser().ParseDirectory(dir, "p")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	got := map[string]bool{}
	for _, a := range analyses {
		for i := range a.Functions {
			got[a.Functions[i].ID.String()] = true
		}
	}
	for _, want := range []string{
		"p.(Plain).Get",
		"p.(*Plain).Set",
		"p.(Gen).Get",
		"p.(*Gen).Set",
		"p.(*Pair).Key",
	} {
		if !got[want] {
			t.Errorf("missing declaration %q; got %v", want, got)
		}
	}
	for k := range got {
		if strings.Contains(k, "[") {
			t.Errorf("declaration %q keeps unerased type parameters", k)
		}
	}
}

// TestGoParser_ShortVarSyntacticTypes pins the bindings a := declaration states
// in its own syntax: composite literals, conversions, make, new, and & of a
// composite literal. Only `var x T` and parameters were read before, so the
// receiver type of a call on any :=-declared local was unknown.
func TestGoParser_ShortVarSyntacticTypes(t *testing.T) {
	src := `package p

import "crypto/cipher"

type AEADBox struct{ aead cipher.AEAD }

func (b *AEADBox) Open() {}

func f() {
	box := &AEADBox{}
	box.Open()
	plain := AEADBox{}
	plain.Open()
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	analyses, err := NewGoParser().ParseDirectory(dir, "p")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	resolved := 0
	for _, a := range analyses {
		for i := range a.Functions {
			for j := range a.Functions[i].Calls {
				c := &a.Functions[i].Calls[j]
				if c.Callee.Name == "Open" && strings.Contains(c.Callee.Type, "AEADBox") {
					resolved++
				}
			}
		}
	}
	if resolved != 2 {
		t.Errorf("expected both := receivers to resolve to AEADBox, resolved %d", resolved)
	}
}
