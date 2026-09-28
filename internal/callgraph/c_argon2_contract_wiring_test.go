package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The reference Argon2 contracts key on bare C function names across the 20151206
// and 20190702 releases. This pins, against what the C parser emits, that raw,
// encoded, generic and context hashing and verification each resolve to exactly one
// contract, and that the error, length and type-name helpers resolve to nothing.
func TestArgon2ContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <argon2.h>

int flows(uint8_t *pwd, uint8_t *salt, uint8_t *hash, char *encoded, argon2_context *ctx) {
    argon2i_hash_raw(3, 4096, 1, pwd, 16, salt, 16, hash, 32);
    argon2id_hash_raw(3, 65536, 4, pwd, 16, salt, 16, hash, 32);
    argon2id_hash_encoded(3, 65536, 4, pwd, 16, salt, 16, 32, encoded, 128);
    argon2_hash(3, 65536, 4, pwd, 16, salt, 16, hash, 32, encoded, 128, Argon2_id, ARGON2_VERSION_13);
    argon2id_verify(encoded, pwd, 16);
    argon2_verify(encoded, pwd, 16, Argon2_id);
    argon2_ctx(ctx, Argon2_id);
    argon2id_ctx(ctx);
    argon2_verify_ctx(ctx, (const char *)hash, Argon2_id);
    argon2i(ctx);

    /* Helpers. None may resolve to a contract. */
    argon2_error_message(ARGON2_OK);
    argon2_encodedlen(3, 65536, 4, 16, 32, Argon2_id);
    argon2_type2string(Argon2_id, 1);
    return 0;
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
		"argon2i_hash_raw":      {9, "operation"},
		"argon2id_hash_raw":     {9, "operation"},
		"argon2id_hash_encoded": {10, "operation"},
		"argon2_hash":           {13, "operation"},
		"argon2id_verify":       {3, "operation"},
		"argon2_verify":         {4, "operation"},
		"argon2_ctx":            {2, "operation"},
		"argon2id_ctx":          {1, "operation"},
		"argon2_verify_ctx":     {3, "operation"},
		"argon2i":               {1, "operation"},
	}
	negative := map[string]bool{
		"argon2_error_message": true,
		"argon2_encodedlen":    true,
		"argon2_type2string":   true,
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
				if got[0].Role != expect.role || got[0].SourceLibrary != "phc-winner-argon2" {
					t.Fatalf("%s: role %q library %q, want %q phc-winner-argon2", bare, got[0].Role, got[0].SourceLibrary, expect.role)
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

// The Argon2 type selects the variant and the cost arguments describe it: the type
// must be operation-determining, the costs metadata-contributing, at their real indexes.
func TestArgon2ContractsMarkSelectors(t *testing.T) {
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
		{"argon2_hash", 13, 11, "variant", "operation-determining"},
		{"argon2_hash", 12, 11, "variant", "operation-determining"},
		{"argon2_verify", 4, 3, "variant", "operation-determining"},
		{"argon2_ctx", 2, 1, "variant", "operation-determining"},
		{"argon2_verify_ctx", 3, 2, "variant", "operation-determining"},
		{"argon2id_hash_raw", 9, 0, "iterations", "metadata-contributing"},
		{"argon2id_hash_raw", 9, 1, "memoryLimit", "metadata-contributing"},
		{"argon2id_hash_raw", 9, 2, "parallelism", "metadata-contributing"},
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
