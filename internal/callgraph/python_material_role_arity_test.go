package callgraph

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// TestPythonMaterialRoles_ReachRealCallArity parses real calls and looks up the
// contract at the arity the parser records. Keyword arguments count toward the
// arity and the lookup is exact, so a material role seeded on an arity no real
// call has would never be read.
func TestPythonMaterialRoles_ReachRealCallArity(t *testing.T) {
	src := `def run(key, iv, n, tag):
    AES.new(key, AES.MODE_CBC, iv=iv)
    AES.new(key, AES.MODE_GCM, nonce=n, mac_len=16)
    modes.GCM(iv)
    modes.GCM(iv, tag)
`
	fn := findPythonFuncByName(parsePythonInline(t, src), "run")
	if fn == nil {
		t.Fatal("run function not found")
	}

	kb, err := contracts.LoadEmbedded("python")
	if err != nil {
		t.Fatalf("LoadEmbedded(python): %v", err)
	}

	cases := []struct {
		method   string
		callIdx  int
		index    int
		keyword  string
		material string
	}{
		{"Crypto.Cipher.AES.new", 0, -1, "iv", "initialization-vector"},
		{"Cryptodome.Cipher.AES.new", 1, -1, "nonce", "nonce"},
		{"cryptography.hazmat.primitives.ciphers.modes.GCM", 2, 0, "", "initialization-vector"},
		{"cryptography.hazmat.primitives.ciphers.modes.GCM", 3, 0, "", "initialization-vector"},
	}
	for _, c := range cases {
		if c.callIdx >= len(fn.Calls) {
			t.Fatalf("call %d not parsed; got %d calls", c.callIdx, len(fn.Calls))
		}
		arity := len(fn.Calls[c.callIdx].Arguments)
		ctrs := kb.ContractsFor(c.method, arity)
		if len(ctrs) != 1 {
			t.Errorf("%s#%d (call %d): %d contracts, want 1", c.method, arity, c.callIdx, len(ctrs))
			continue
		}
		if got := ctrs[0].MaterialAt(c.index, c.keyword); got != c.material {
			t.Errorf("%s#%d role (%d, %q) = %q, want %q", c.method, arity, c.index, c.keyword, got, c.material)
		}
	}
}
