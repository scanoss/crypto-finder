package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The intel-ipsec-mb contracts key on bare C function names, which is what the C parser
// emits for a free-function call. This pins that agreement for every contracted
// symbol, with the arity the parser counts and the lifecycle role, and pins the
// negative half: same-prefix calls outside the contracted surface must not
// resolve to a contract.
func TestIntelIPsecMBContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <intel-ipsec-mb.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10) {
    alloc_mb_mgr(a0);
    init_mb_mgr_auto(a0, a1);
    init_mb_mgr_sse(a0);
    init_mb_mgr_avx2(a0);
    init_mb_mgr_avx512(a0);
    IMB_GET_NEXT_JOB(a0);
    IMB_SUBMIT_JOB(a0);
    IMB_SUBMIT_JOB_NOCHECK(a0);
    IMB_FLUSH_JOB(a0);
    IMB_GET_COMPLETED_JOB(a0);
    IMB_GET_NEXT_BURST(a0, a1, a2);
    IMB_SUBMIT_BURST(a0, a1, a2);
    IMB_FLUSH_BURST(a0, a1, a2);
    IMB_AES_KEYEXP_128(a0, a1, a2, a3);
    IMB_AES_KEYEXP_192(a0, a1, a2, a3);
    IMB_AES_KEYEXP_256(a0, a1, a2, a3);
    IMB_AES_XCBC_KEYEXP(a0, a1, a2, a3, a4);
    IMB_AES_CMAC_SUBKEY_GEN_128(a0, a1, a2, a3);
    IMB_AES128_GCM_PRE(a0, a1, a2);
    IMB_AES128_GCM_INIT(a0, a1, a2, a3, a4, a5);
    IMB_AES128_GCM_ENC_UPDATE(a0, a1, a2, a3, a4, a5);
    IMB_AES128_GCM_DEC_UPDATE(a0, a1, a2, a3, a4, a5);
    IMB_AES128_GCM_ENC_FINALIZE(a0, a1, a2, a3, a4);
    IMB_AES128_GCM_DEC_FINALIZE(a0, a1, a2, a3, a4);
    IMB_AES128_GCM_ENC(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    IMB_AES128_GCM_DEC(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    IMB_AES192_GCM_PRE(a0, a1, a2);
    IMB_AES192_GCM_INIT(a0, a1, a2, a3, a4, a5);
    IMB_AES192_GCM_ENC_UPDATE(a0, a1, a2, a3, a4, a5);
    IMB_AES192_GCM_DEC_UPDATE(a0, a1, a2, a3, a4, a5);
    IMB_AES192_GCM_ENC_FINALIZE(a0, a1, a2, a3, a4);
    IMB_AES192_GCM_DEC_FINALIZE(a0, a1, a2, a3, a4);
    IMB_AES192_GCM_ENC(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    IMB_AES192_GCM_DEC(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    IMB_AES256_GCM_PRE(a0, a1, a2);
    IMB_AES256_GCM_INIT(a0, a1, a2, a3, a4, a5);
    IMB_AES256_GCM_ENC_UPDATE(a0, a1, a2, a3, a4, a5);
    IMB_AES256_GCM_DEC_UPDATE(a0, a1, a2, a3, a4, a5);
    IMB_AES256_GCM_ENC_FINALIZE(a0, a1, a2, a3, a4);
    IMB_AES256_GCM_DEC_FINALIZE(a0, a1, a2, a3, a4);
    IMB_AES256_GCM_ENC(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    IMB_AES256_GCM_DEC(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    IMB_SHA1(a0, a1, a2, a3);
    IMB_SHA224(a0, a1, a2, a3);
    IMB_SHA256(a0, a1, a2, a3);
    IMB_SHA384(a0, a1, a2, a3);
    IMB_SHA512(a0, a1, a2, a3);
    IMB_SHA1_ONE_BLOCK(a0, a1, a2);
    IMB_MD5_ONE_BLOCK(a0, a1, a2);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3) {
    free_mb_mgr(a0);
    imb_get_errno(a0);
    IMB_QUEUE_SIZE(a0);
    IMB_CRC32_ETHERNET_FCS(a0, a1, a2);
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
		"alloc_mb_mgr/1":                {1, "factory"},
		"init_mb_mgr_auto/2":            {2, "config"},
		"init_mb_mgr_sse/1":             {1, "config"},
		"init_mb_mgr_avx2/1":            {1, "config"},
		"init_mb_mgr_avx512/1":          {1, "config"},
		"IMB_GET_NEXT_JOB/1":            {1, "factory"},
		"IMB_SUBMIT_JOB/1":              {1, "operation"},
		"IMB_SUBMIT_JOB_NOCHECK/1":      {1, "operation"},
		"IMB_FLUSH_JOB/1":               {1, "operation"},
		"IMB_GET_COMPLETED_JOB/1":       {1, "output"},
		"IMB_GET_NEXT_BURST/3":          {3, "factory"},
		"IMB_SUBMIT_BURST/3":            {3, "operation"},
		"IMB_FLUSH_BURST/3":             {3, "operation"},
		"IMB_AES_KEYEXP_128/4":          {4, "config"},
		"IMB_AES_KEYEXP_192/4":          {4, "config"},
		"IMB_AES_KEYEXP_256/4":          {4, "config"},
		"IMB_AES_XCBC_KEYEXP/5":         {5, "config"},
		"IMB_AES_CMAC_SUBKEY_GEN_128/4": {4, "config"},
		"IMB_AES128_GCM_PRE/3":          {3, "config"},
		"IMB_AES128_GCM_INIT/6":         {6, "config"},
		"IMB_AES128_GCM_ENC_UPDATE/6":   {6, "operation"},
		"IMB_AES128_GCM_DEC_UPDATE/6":   {6, "operation"},
		"IMB_AES128_GCM_ENC_FINALIZE/5": {5, "output"},
		"IMB_AES128_GCM_DEC_FINALIZE/5": {5, "output"},
		"IMB_AES128_GCM_ENC/11":         {11, "operation"},
		"IMB_AES128_GCM_DEC/11":         {11, "operation"},
		"IMB_AES192_GCM_PRE/3":          {3, "config"},
		"IMB_AES192_GCM_INIT/6":         {6, "config"},
		"IMB_AES192_GCM_ENC_UPDATE/6":   {6, "operation"},
		"IMB_AES192_GCM_DEC_UPDATE/6":   {6, "operation"},
		"IMB_AES192_GCM_ENC_FINALIZE/5": {5, "output"},
		"IMB_AES192_GCM_DEC_FINALIZE/5": {5, "output"},
		"IMB_AES192_GCM_ENC/11":         {11, "operation"},
		"IMB_AES192_GCM_DEC/11":         {11, "operation"},
		"IMB_AES256_GCM_PRE/3":          {3, "config"},
		"IMB_AES256_GCM_INIT/6":         {6, "config"},
		"IMB_AES256_GCM_ENC_UPDATE/6":   {6, "operation"},
		"IMB_AES256_GCM_DEC_UPDATE/6":   {6, "operation"},
		"IMB_AES256_GCM_ENC_FINALIZE/5": {5, "output"},
		"IMB_AES256_GCM_DEC_FINALIZE/5": {5, "output"},
		"IMB_AES256_GCM_ENC/11":         {11, "operation"},
		"IMB_AES256_GCM_DEC/11":         {11, "operation"},
		"IMB_SHA1/4":                    {4, "operation"},
		"IMB_SHA224/4":                  {4, "operation"},
		"IMB_SHA256/4":                  {4, "operation"},
		"IMB_SHA384/4":                  {4, "operation"},
		"IMB_SHA512/4":                  {4, "operation"},
		"IMB_SHA1_ONE_BLOCK/3":          {3, "operation"},
		"IMB_MD5_ONE_BLOCK/3":           {3, "operation"},
	}
	negative := []string{"free_mb_mgr", "imb_get_errno", "IMB_QUEUE_SIZE", "IMB_CRC32_ETHERNET_FCS"}

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

				key := fmt.Sprintf("%s/%d", bare, len(call.Arguments))
				expect, ok := want[key]
				if !ok {
					continue
				}
				got := kb.ContractsForCFunction(method, expect.arity, true)
				if len(got) != 1 {
					t.Fatalf("ContractsForCFunction(%q, %d) = %d, want exactly one contract",
						method, expect.arity, len(got))
				}
				if got[0].Role != expect.role {
					t.Fatalf("%s: role = %q, want %q", key, got[0].Role, expect.role)
				}
				if got[0].SourceLibrary != "intel-ipsec-mb" {
					t.Fatalf("%s: library = %q, want intel-ipsec-mb", bare, got[0].SourceLibrary)
				}
				seen[key] = true
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
