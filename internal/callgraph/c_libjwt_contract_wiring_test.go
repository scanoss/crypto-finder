package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The libjwt contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: same-prefix calls outside the contracted surface must not
// resolve to a contract.
func TestLibJWTContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <jwt.h>

void every_contract(void *a0, void *a1, void *a2, void *a3) {
    jwt_new(a0);
    jwt_dup(a0);
    jwt_set_alg(a0, a1, a2, a3);
    jwt_add_grant(a0, a1, a2);
    jwt_add_grant_int(a0, a1, a2);
    jwt_add_grant_bool(a0, a1, a2);
    jwt_add_grants_json(a0, a1);
    jwt_add_header(a0, a1, a2);
    jwt_encode_str(a0);
    jwt_encode_fp(a0, a1);
    jwt_decode(a0, a1, a2, a3);
    jwt_decode_2(a0, a1, a2);
    jwt_get_alg(a0);
    jwt_get_grant(a0, a1);
    jwt_valid_new(a0, a1);
    jwt_valid_add_grant(a0, a1, a2);
    jwt_validate(a0, a1);
    jwt_builder_new();
    jwt_builder_setkey(a0, a1, a2);
    jwt_builder_claim_set(a0, a1);
    jwt_builder_header_set(a0, a1);
    jwt_builder_generate(a0);
    jwt_checker_new();
    jwt_checker_setkey(a0, a1, a2);
    jwt_checker_claim_set(a0, a1, a2);
    jwt_checker_verify(a0, a1);
    jwks_create(a0);
    jwks_create_strn(a0, a1);
    jwks_create_fromfile(a0);
    jwks_create_fromfp(a0);
    jwks_load(a0, a1);
    jwks_load_strn(a0, a1, a2);
    jwks_load_fromfile(a0, a1);
    jwks_load_fromfp(a0, a1);
    jwks_item_get(a0, a1);
    jwks_find_bykid(a0, a1);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3) {
    jwt_free(a0);
    jwt_valid_free(a0);
    jwt_alg_str(a0);
    jwt_dump_str(a0, 0);
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
		"jwt_new":                {1, "factory"},
		"jwt_dup":                {1, "factory"},
		"jwt_set_alg":            {4, "config"},
		"jwt_add_grant":          {3, "config"},
		"jwt_add_grant_int":      {3, "config"},
		"jwt_add_grant_bool":     {3, "config"},
		"jwt_add_grants_json":    {2, "config"},
		"jwt_add_header":         {3, "config"},
		"jwt_encode_str":         {1, "operation"},
		"jwt_encode_fp":          {2, "operation"},
		"jwt_decode":             {4, "operation"},
		"jwt_decode_2":           {3, "operation"},
		"jwt_get_alg":            {1, "output"},
		"jwt_get_grant":          {2, "output"},
		"jwt_valid_new":          {2, "factory"},
		"jwt_valid_add_grant":    {3, "config"},
		"jwt_validate":           {2, "operation"},
		"jwt_builder_new":        {0, "factory"},
		"jwt_builder_setkey":     {3, "config"},
		"jwt_builder_claim_set":  {2, "config"},
		"jwt_builder_header_set": {2, "config"},
		"jwt_builder_generate":   {1, "operation"},
		"jwt_checker_new":        {0, "factory"},
		"jwt_checker_setkey":     {3, "config"},
		"jwt_checker_claim_set":  {3, "config"},
		"jwt_checker_verify":     {2, "operation"},
		"jwks_create":            {1, "factory"},
		"jwks_create_strn":       {2, "factory"},
		"jwks_create_fromfile":   {1, "factory"},
		"jwks_create_fromfp":     {1, "factory"},
		"jwks_load":              {2, "config"},
		"jwks_load_strn":         {3, "config"},
		"jwks_load_fromfile":     {2, "config"},
		"jwks_load_fromfp":       {2, "config"},
		"jwks_item_get":          {2, "output"},
		"jwks_find_bykid":        {2, "output"},
	}
	negative := []string{"jwt_free", "jwt_valid_free", "jwt_alg_str", "jwt_dump_str"}

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
							t.Fatalf("%q resolved to %d contract(s), want none", bare, len(got))
						}
						seen[bare] = true
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
				if got[0].SourceLibrary != "libjwt" {
					t.Fatalf("%s: library = %q, want libjwt", bare, got[0].SourceLibrary)
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
	for _, n := range negative {
		if !seen[n] {
			t.Fatalf("parsed calls did not cover negative %q", n)
		}
	}
}

// The consumer names the algorithm, parameter set or mode at the call site. Each
// call that takes that selector must carry it as operation-determining at the
// right index, or the identity of the finding it supports is unattributed.
func TestLibJWTContractsMarkSelectorsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	selector := map[string]struct {
		arity, index int
		property     string
	}{
		"jwt_set_alg":        {4, 1, "algorithm"},
		"jwt_valid_new":      {2, 1, "algorithm"},
		"jwt_builder_setkey": {3, 1, "algorithm"},
		"jwt_checker_setkey": {3, 1, "algorithm"},
	}

	for method, want := range selector {
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
				t.Errorf("%s: parameters[%d].role = %q, want operation-determining", method, want.index, p.Role)
			}
			if p.Contributes == nil || p.Contributes.Property != want.property {
				t.Errorf("%s: parameters[%d] contributes %#v, want property %s", method, want.index, p.Contributes, want.property)
			}
		}
		if !found {
			t.Errorf("%s: no parameter entry at index %d", method, want.index)
		}
	}
}
