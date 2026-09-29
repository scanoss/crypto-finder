package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The libscrypt contracts key on bare C function names. This pins, against what the
// C parser emits, that the scrypt KDF, MCF hashing and verification and salt
// generation each resolve to exactly one libscrypt contract, and that MCF formatting
// and the base64 helpers resolve to nothing.
func TestLibscryptContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <libscrypt.h>

int flows(uint8_t *salt, uint8_t *out, char *mcf, char *text) {
    libscrypt_salt_gen(salt, 16);
    libscrypt_scrypt((const uint8_t *)"pw", 2, salt, 16, 16384, 8, 1, out, 64);
    libscrypt_hash(mcf, "pw", 16384, 8, 1);
    int ok = libscrypt_check(mcf, "pw");

    /* Formatting and encoding. None may resolve to a contract. */
    libscrypt_mcf(16384, 8, 1, "c2FsdA==", "aGFzaA==", mcf);
    libscrypt_b64_encode(out, 64, text, 128);
    return ok;
}
`
	if err := os.WriteFile(filepath.Join(dir, "app.c"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]struct {
		arity int
		role  string
	}{
		"libscrypt_salt_gen": {2, "factory"},
		"libscrypt_scrypt":   {9, "operation"},
		"libscrypt_hash":     {5, "operation"},
		"libscrypt_check":    {2, "operation"},
	}
	negative := map[string]bool{
		"libscrypt_mcf":        true,
		"libscrypt_b64_encode": true,
	}

	seen := map[string]bool{}
	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method, _ := splitMethodArity(&callee)
				bare := method
				if idx := strings.LastIndex(bare, "."); idx >= 0 {
					bare = bare[idx+1:]
				}
				if negative[bare] {
					if got := kb.ContractsForCFunction(method, len(call.Arguments), true); len(got) != 0 {
						t.Fatalf("%q resolved to %d contract(s), want none", bare, len(got))
					}
					seen[bare] = true
					continue
				}
				expect, ok := want[bare]
				if !ok {
					continue
				}
				if len(call.Arguments) != expect.arity {
					t.Fatalf("%s: parsed arity %d, want %d", bare, len(call.Arguments), expect.arity)
				}
				got := kb.ContractsForCFunction(method, expect.arity, true)
				if len(got) != 1 {
					t.Fatalf("ContractsForCFunction(%q, %d) = %d, want exactly one", method, expect.arity, len(got))
				}
				if got[0].Role != expect.role || got[0].SourceLibrary != "libscrypt" {
					t.Fatalf("%s: role %q library %q, want %q libscrypt", bare, got[0].Role, got[0].SourceLibrary, expect.role)
				}
				seen[bare] = true
			}
		}
	}
	for method := range want {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover %q", method)
		}
	}
	for method := range negative {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover negative %q", method)
		}
	}
}

// N, r and p describe the scrypt instance, so each must be published at its real
// index on both the raw KDF and the MCF hashing call.
func TestLibscryptContractsMarkSelectors(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}
	for _, tc := range []struct {
		method         string
		arity, index   int
		property, role string
	}{
		{"libscrypt_scrypt", 9, 4, "cost", "metadata-contributing"},
		{"libscrypt_scrypt", 9, 5, "blockSize", "metadata-contributing"},
		{"libscrypt_scrypt", 9, 6, "parallelism", "metadata-contributing"},
		{"libscrypt_scrypt", 9, 8, "outputLength", "metadata-contributing"},
		{"libscrypt_hash", 5, 2, "cost", "metadata-contributing"},
		{"libscrypt_hash", 5, 3, "blockSize", "metadata-contributing"},
		{"libscrypt_hash", 5, 4, "parallelism", "metadata-contributing"},
	} {
		got := kb.ContractsFor(tc.method, tc.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", tc.method, tc.arity, len(got))
		}
		var ok bool
		for _, p := range got[0].Parameters {
			if p.Index != nil && *p.Index == tc.index && p.Role == tc.role && p.Contributes != nil &&
				p.Contributes.Property == tc.property {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s/%d: parameter %d is not %s %s", tc.method, tc.arity, tc.index, tc.role, tc.property)
		}
	}
}
