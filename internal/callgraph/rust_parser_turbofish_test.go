package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// A turbofish must not change a call's identity: neither the generic_function
// wrapper on a free function nor type arguments inside a scoped path.
func TestRustParserResolvesTurbofishCalls(t *testing.T) {
	dir := t.TempDir()
	src := `use pbkdf2::Pbkdf2;
use chacha20poly1305::{ChaCha20Poly1305, Key};

fn derive(pw: &[u8], salt: &[u8], out: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw, salt, 600000, out);
    let _a = pbkdf2::pbkdf2_hmac_array::<sha2::Sha256, 32>(pw, salt, 600000);
    let _d = Pbkdf2::default();
    let _k = Key::<ChaCha20Poly1305>::generate(&mut rng);
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.rs"), []byte(src), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}

	type key struct {
		method string
		arity  int
	}
	got := map[key]bool{}
	for _, a := range analyses {
		for _, fn := range a.Functions {
			for _, c := range fn.Calls {
				id := c.Callee
				m, _ := splitMethodArity(&id)
				got[key{m, len(c.Arguments)}] = true
			}
		}
	}

	want := []key{
		{"pbkdf2.pbkdf2_hmac", 4},
		{"pbkdf2.pbkdf2_hmac_array", 3},
		{"pbkdf2.Pbkdf2.default", 0},
		{"chacha20poly1305.Key.generate", 1},
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing call %s#%d; got %v", w.method, w.arity, got)
		}
	}
}

func TestStripRustTypeArguments(t *testing.T) {
	tests := []struct{ in, want string }{
		{"pbkdf2::pbkdf2_hmac", "pbkdf2::pbkdf2_hmac"},
		{"Key::<ChaCha20Poly1305>::generate", "Key::generate"},
		{"a::<Vec<Vec<u8>>>::b", "a::b"},
		{"a::<T, 32>::b::<U>::c", "a::b::c"},
		{"a::<[u8; 32]>::b", "a::b"},
		{"Foo::<Bar::<u8>>::baz", "Foo::baz"},
		{"a::<>::b", "a::b"},
		// The ">" of a return arrow closes nothing.
		{"foo::<fn() -> u8>::bar", "foo::bar"},
		{"foo::<fn(&[u8]) -> u32>::bar", "foo::bar"},
		// Unbalanced input is returned unchanged: a truncated path becomes a
		// wrong callee identity, which is worse than an unstripped one.
		{"foo::<T", "foo::<T"},
		{"foo::<Vec<u8>::bar", "foo::<Vec<u8>::bar"},
		// A qualified path carries no "::<" and passes through.
		{"<Sha256 as Digest>::new", "<Sha256 as Digest>::new"},
	}
	for _, tt := range tests {
		if got := stripRustTypeArguments(tt.in); got != tt.want {
			t.Errorf("stripRustTypeArguments(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
