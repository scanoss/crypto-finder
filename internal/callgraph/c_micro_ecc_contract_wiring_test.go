package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The micro-ecc contracts key on bare C function names, which is what the C
// parser emits for a free-function call. This pins that agreement for the whole
// contracted surface: the curve selector, the entropy configuration, key
// generation and derivation, ECDH, and both signing spellings plus verification.
// It also pins the negative half, since the library's arithmetic internals share
// the uECC_ prefix and must not resolve to a contract.
func TestMicroEccContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include "uECC.h"
#include "uECC_vli.h"

static int rng(uint8_t *dest, unsigned size) { return 1; }

int agree(uint8_t *pub, uint8_t *priv, uint8_t *secret) {
    uECC_set_rng(&rng);
    uECC_Curve curve = uECC_secp256r1();
    if (!uECC_make_key(pub, priv, curve)) {
        return 0;
    }
    uECC_compute_public_key(priv, pub, curve);
    return uECC_shared_secret(pub, priv, secret, curve);
}

int sign_and_verify(const uint8_t *priv, const uint8_t *pub,
                    const uint8_t *hash, uint8_t *sig) {
    uECC_Curve curve = uECC_secp192r1();
    uECC_sign(priv, hash, 32, sig, curve);
    uECC_sign_deterministic(priv, hash, 32, NULL, sig, curve);
    return uECC_verify(pub, hash, 32, sig, curve);
}

/* Arithmetic internals. None of these may resolve to a contract. */
void internals(uECC_word_t *a, uECC_word_t *b, uECC_Curve curve) {
    uECC_vli_add(a, a, b, 8);
    uECC_vli_modMult_fast(a, a, b, curve);
    uECC_vli_isZero(a, 8);
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
		"uECC_secp256r1":          {0, "factory"},
		"uECC_secp192r1":          {0, "factory"},
		"uECC_set_rng":            {1, "config"},
		"uECC_make_key":           {3, "factory"},
		"uECC_compute_public_key": {3, "factory"},
		"uECC_shared_secret":      {4, "operation"},
		"uECC_sign":               {5, "operation"},
		"uECC_sign_deterministic": {6, "operation"},
		"uECC_verify":             {5, "operation"},
	}
	// Arithmetic internals: parsed, but deliberately uncontracted.
	negative := []string{"uECC_vli_add", "uECC_vli_modMult_fast", "uECC_vli_isZero"}

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

				for _, n := range negative {
					if bare == n {
						if got := kb.ContractsForCFunction(method, len(call.Arguments), true); len(got) != 0 {
							t.Fatalf("arithmetic internal %q resolved to %d contract(s), want none",
								bare, len(got))
						}
					}
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
					t.Fatalf("ContractsForCFunction(%q, %d) = %d, want exactly one contract",
						method, expect.arity, len(got))
				}
				if got[0].Role != expect.role {
					t.Fatalf("%s: role = %q, want %q", bare, got[0].Role, expect.role)
				}
				if got[0].SourceLibrary != "micro-ecc" {
					t.Fatalf("%s: library = %q, want micro-ecc", bare, got[0].SourceLibrary)
				}
				seen[bare] = true
			}
		}
	}

	for method := range want {
		if !seen[method] {
			t.Fatalf("parsed calls did not cover %q; seen = %v", method, seen)
		}
	}
}

// The curve is chosen by the consumer at the call site, so every operation must
// carry its curve argument as operation-determining rather than leaving the
// algorithm identity unattributed.
func TestMicroEccContractsMarkCurveOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	// method -> the 0-based index its curve handle occupies.
	curveArg := map[string]struct{ arity, index int }{
		"uECC_make_key":           {3, 2},
		"uECC_compute_public_key": {3, 2},
		"uECC_shared_secret":      {4, 3},
		"uECC_sign":               {5, 4},
		"uECC_sign_deterministic": {6, 5},
		"uECC_verify":             {5, 4},
	}

	for method, want := range curveArg {
		got := kb.ContractsFor(method, want.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", method, want.arity, len(got))
		}
		var found bool
		for _, p := range got[0].Parameters {
			if p.Index == nil || *p.Index != want.index {
				continue
			}
			found = true
			if p.Role != "operation-determining" {
				t.Errorf("%s: parameters[%d].role = %q, want operation-determining",
					method, want.index, p.Role)
			}
			if p.Contributes == nil || p.Contributes.Property != "curve" {
				t.Errorf("%s: parameters[%d] contributes %#v, want property curve",
					method, want.index, p.Contributes)
			}
		}
		if !found {
			t.Errorf("%s: no parameter entry at index %d", method, want.index)
		}
	}
}
