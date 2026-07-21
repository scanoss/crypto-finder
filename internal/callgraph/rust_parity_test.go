package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func buildRustParityGraph(t *testing.T, src string) *CallGraph {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lib.rs"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	builder := NewBuilderForEcosystem("rust", NewRustParser())
	builder.SetTypeResolver(NewRustContractTypeResolverFromEmbedded())
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "chacha20poly1305"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

func rustGraphFunction(t *testing.T, graph *CallGraph, id FunctionID) *FunctionDecl {
	t.Helper()

	fn := graph.Functions[id.String()]
	if fn == nil {
		t.Fatalf("function %s not found", id.String())
	}
	return fn
}

func TestRustParity_ParserInferenceAndGracefulDegradation(t *testing.T) {
	graph := buildRustParityGraph(t, `
struct ChaCha20Poly1305;

impl ChaCha20Poly1305 {
    fn new(key: &[u8]) { let _ = key; }
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) { let _ = (nonce, plaintext); }
}

fn seal(key: &[u8], nonce: &[u8], plaintext: &[u8]) {
    let cipher: ChaCha20Poly1305 = chacha20poly1305::ChaCha20Poly1305::new(key);
    cipher.encrypt(nonce, plaintext);
}

fn relay(key: &[u8]) {
    return ChaCha20Poly1305::new(key);
}

fn unsupported() { return; }
`)

	constructor := rustGraphFunction(t, graph, FunctionID{Package: "chacha20poly1305", Type: "ChaCha20Poly1305", Name: "new"})
	if constructor.ReturnType != "chacha20poly1305::ChaCha20Poly1305" {
		t.Fatalf("constructor ReturnType = %q, want contract-inferred Chacha20Poly1305", constructor.ReturnType)
	}

	seal := rustGraphFunction(t, graph, FunctionID{Package: "chacha20poly1305", Name: "seal"})
	if len(seal.Calls) != 2 {
		t.Fatalf("seal calls = %#v, want constructor and encrypt", seal.Calls)
	}
	for _, want := range []FunctionID{
		{Package: "chacha20poly1305", Type: "ChaCha20Poly1305", Name: "new"},
		{Package: "chacha20poly1305", Type: "ChaCha20Poly1305", Name: "encrypt"},
	} {
		found := false
		for _, call := range seal.Calls {
			if call.Callee == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("seal calls = %#v, missing %#v", seal.Calls, want)
		}
	}

	relay := rustGraphFunction(t, graph, FunctionID{Package: "chacha20poly1305", Name: "relay"})
	if len(relay.ReturnSources) != 1 || relay.ReturnSources[0].CallTarget == nil || relay.ReturnSources[0].CallTarget.Name != "new" {
		t.Fatalf("relay ReturnSources = %#v, want constructor call result", relay.ReturnSources)
	}

	unsupported := rustGraphFunction(t, graph, FunctionID{Package: "chacha20poly1305", Name: "unsupported"})
	if unsupported.InferredReturn != nil || len(unsupported.ReturnSources) != 0 {
		t.Fatalf("unsupported function should degrade without inference: %#v", unsupported)
	}
}
