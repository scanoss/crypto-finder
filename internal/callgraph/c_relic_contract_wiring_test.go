// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The RELIC contracts key on bare C function and macro names, which is what the
// C parser emits for a call: a macro such as ep_map or pc_map is seen by the
// name the source spells, not its build-time backend. This pins that agreement
// for every contracted symbol at every arity a tag declares, with the lifecycle
// role, and pins the negative half: generic big-integer, field and point
// arithmetic and the build-selected md_map resolve to nothing.
func TestRELICContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	dir := t.TempDir()
	src := `#include <relic.h>

void every_contract(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10) {
    core_init();
    core_clean();
    ep_param_set(a0);
    ep_param_set_any();
    ep_param_set_any_endom();
    ep_param_set_any_kbltz();
    ep_param_set_any_ordin();
    ep_param_set_any_pairf();
    ep_param_set_any_plain();
    ep_param_set_any_super();
    pc_param_set_any();
    rand_seed(a0, a1);
    rand_bytes(a0, a1);
    md_map_sh224(a0, a1, a2);
    md_map_sh256(a0, a1, a2);
    md_map_sh384(a0, a1, a2);
    md_map_sh512(a0, a1, a2);
    md_map_b2s160(a0, a1, a2);
    md_map_b2s256(a0, a1, a2);
    md_hmac(a0, a1, a2, a3, a4);
    md_kdf(a0, a1, a2, a3);
    bc_aes_cbc_enc(a0, a1, a2, a3, a4, a5, a6);
    bc_aes_cbc_dec(a0, a1, a2, a3, a4, a5, a6);
    ep_map(a0, a1, a2);
    ep2_map(a0, a1, a2);
    g1_map(a0, a1, a2);
    g2_map(a0, a1, a2);
    ep_map_dst(a0, a1, a2, a3, a4);
    ep2_map_dst(a0, a1, a2, a3, a4);
    pc_map(a0, a1, a2);
    pc_map_sim(a0, a1, a2, a3);
    pc_exp(a0, a1);
    pp_map_k1(a0, a1, a2);
    pp_map_k2(a0, a1, a2);
    pp_map_k8(a0, a1, a2);
    pp_map_k12(a0, a1, a2);
    pp_map_k16(a0, a1, a2);
    pp_map_k18(a0, a1, a2);
    pp_map_k24(a0, a1, a2);
    pp_map_k48(a0, a1, a2);
    pp_map_k48(a0, a1, a2, a3);
    pp_map_k54(a0, a1, a2, a3);
    pp_map_oatep_k8(a0, a1, a2);
    pp_map_oatep_k12(a0, a1, a2);
    pp_map_oatep_k16(a0, a1, a2);
    pp_map_oatep_k18(a0, a1, a2);
    pp_map_sim_k1(a0, a1, a2, a3);
    pp_map_sim_k2(a0, a1, a2, a3);
    pp_map_sim_k8(a0, a1, a2, a3);
    pp_map_sim_k12(a0, a1, a2, a3);
    pp_map_sim_k16(a0, a1, a2, a3);
    pp_map_sim_k18(a0, a1, a2, a3);
    pp_map_sim_k24(a0, a1, a2, a3);
    pp_map_sim_k48(a0, a1, a2, a3);
    pp_map_sim_oatep_k8(a0, a1, a2, a3);
    pp_map_sim_oatep_k12(a0, a1, a2, a3);
    pp_map_sim_oatep_k16(a0, a1, a2, a3);
    pp_map_sim_oatep_k18(a0, a1, a2, a3);
    pp_map_sim_tatep_k1(a0, a1, a2, a3);
    pp_map_sim_tatep_k2(a0, a1, a2, a3);
    pp_map_sim_tatep_k12(a0, a1, a2, a3);
    pp_map_sim_tatep_k16(a0, a1, a2, a3);
    pp_map_sim_tatep_k18(a0, a1, a2, a3);
    pp_map_sim_weilp_k1(a0, a1, a2, a3);
    pp_map_sim_weilp_k2(a0, a1, a2, a3);
    pp_map_sim_weilp_k12(a0, a1, a2, a3);
    pp_map_sim_weilp_k16(a0, a1, a2, a3);
    pp_map_sim_weilp_k18(a0, a1, a2, a3);
    pp_map_tatep_k1(a0, a1, a2);
    pp_map_tatep_k2(a0, a1, a2);
    pp_map_tatep_k12(a0, a1, a2);
    pp_map_tatep_k16(a0, a1, a2);
    pp_map_tatep_k18(a0, a1, a2);
    pp_map_weilp_k1(a0, a1, a2);
    pp_map_weilp_k2(a0, a1, a2);
    pp_map_weilp_k12(a0, a1, a2);
    pp_map_weilp_k16(a0, a1, a2);
    pp_map_weilp_k18(a0, a1, a2);
    cp_rsa_gen(a0, a1, a2);
    cp_rsa_gen_basic(a0, a1, a2);
    cp_rsa_gen_quick(a0, a1, a2);
    cp_rsa_enc(a0, a1, a2, a3, a4);
    cp_rsa_dec(a0, a1, a2, a3, a4);
    cp_rsa_dec_basic(a0, a1, a2, a3, a4);
    cp_rsa_dec_quick(a0, a1, a2, a3, a4);
    cp_rsa_sig(a0, a1, a2, a3, a4, a5);
    cp_rsa_sig_basic(a0, a1, a2, a3, a4, a5);
    cp_rsa_sig_quick(a0, a1, a2, a3, a4, a5);
    cp_rsa_ver(a0, a1, a2, a3, a4);
    cp_rsa_ver(a0, a1, a2, a3, a4, a5);
    cp_rabin_gen(a0, a1, a2);
    cp_rabin_enc(a0, a1, a2, a3, a4);
    cp_rabin_dec(a0, a1, a2, a3, a4);
    cp_ecdh_gen(a0, a1);
    cp_ecdh_key(a0, a1, a2, a3);
    cp_ecmqv_gen(a0, a1);
    cp_ecmqv_key(a0, a1, a2, a3, a4, a5, a6);
    cp_sokaka_gen(a0);
    cp_sokaka_gen_prv(a0, a1, a2);
    cp_sokaka_gen_prv(a0, a1, a2, a3);
    cp_sokaka_key(a0, a1, a2);
    cp_sokaka_key(a0, a1, a2, a3, a4);
    cp_sokaka_key(a0, a1, a2, a3, a4, a5, a6);
    cp_ecies_gen(a0, a1);
    cp_ecies_enc(a0, a1, a2, a3, a4, a5);
    cp_ecies_dec(a0, a1, a2, a3, a4, a5);
    cp_ecdsa_gen(a0, a1);
    cp_ecdsa_sig(a0, a1, a2, a3, a4);
    cp_ecdsa_sig(a0, a1, a2, a3, a4, a5);
    cp_ecdsa_ver(a0, a1, a2, a3, a4);
    cp_ecdsa_ver(a0, a1, a2, a3, a4, a5);
    cp_ecss_gen(a0, a1);
    cp_ecss_sig(a0, a1, a2, a3, a4);
    cp_ecss_ver(a0, a1, a2, a3, a4);
    cp_bls_gen(a0, a1);
    cp_bls_sig(a0, a1, a2, a3);
    cp_bls_ver(a0, a1, a2, a3);
    cp_bbs_gen(a0, a1, a2);
    cp_bbs_sig(a0, a1, a2, a3, a4);
    cp_bbs_ver(a0, a1, a2, a3, a4, a5);
    cp_cls_gen(a0, a1, a2, a3);
    cp_cls_sig(a0, a1, a2, a3, a4, a5, a6);
    cp_cls_ver(a0, a1, a2, a3, a4, a5, a6);
    cp_cli_gen(a0, a1, a2, a3, a4, a5);
    cp_cli_sig(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    cp_cli_ver(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    cp_clb_gen(a0, a1, a2, a3, a4, a5, a6);
    cp_clb_sig(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    cp_clb_ver(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    cp_pss_gen(a0, a1, a2, a3, a4);
    cp_pss_sig(a0, a1, a2, a3, a4);
    cp_pss_sig(a0, a1, a2, a3, a4, a5);
    cp_pss_ver(a0, a1, a2, a3, a4, a5);
    cp_pss_ver(a0, a1, a2, a3, a4, a5, a6);
    cp_psb_gen(a0, a1, a2, a3, a4, a5);
    cp_psb_sig(a0, a1, a2, a3, a4, a5);
    cp_psb_sig(a0, a1, a2, a3, a4, a5, a6);
    cp_psb_ver(a0, a1, a2, a3, a4, a5, a6);
    cp_psb_ver(a0, a1, a2, a3, a4, a5, a6, a7);
    cp_mpss_gen(a0, a1, a2, a3, a4);
    cp_mpss_sig(a0, a1, a2, a3, a4, a5, a6);
    cp_mpss_ver(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    cp_mpsb_gen(a0, a1, a2, a3, a4, a5);
    cp_mpsb_sig(a0, a1, a2, a3, a4, a5, a6, a7);
    cp_mpsb_ver(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
    cp_zss_gen(a0, a1, a2);
    cp_zss_sig(a0, a1, a2, a3, a4);
    cp_zss_ver(a0, a1, a2, a3, a4, a5);
    cp_vbnn_gen(a0, a1);
    cp_vbnn_sig(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    cp_vbnn_ver(a0, a1, a2, a3, a4, a5, a6, a7);
    cp_vbnn_gen_prv(a0, a1, a2, a3, a4);
    cp_phpe_gen(a0, a1, a2);
    cp_phpe_enc(a0, a1, a2);
    cp_phpe_enc(a0, a1, a2, a3, a4);
    cp_phpe_dec(a0, a1, a2);
    cp_phpe_dec(a0, a1, a2, a3, a4, a5);
    cp_ghpe_gen(a0, a1, a2);
    cp_ghpe_enc(a0, a1, a2, a3);
    cp_ghpe_dec(a0, a1, a2, a3, a4);
    cp_shpe_gen(a0, a1, a2, a3);
    cp_shpe_enc(a0, a1, a2);
    cp_shpe_enc_prv(a0, a1, a2);
    cp_shpe_dec(a0, a1, a2);
    cp_bdpe_gen(a0, a1, a2, a3);
    cp_bdpe_enc(a0, a1, a2, a3);
    cp_bdpe_dec(a0, a1, a2, a3);
    cp_bgn_gen(a0, a1);
    cp_bgn_enc1(a0, a1, a2);
    cp_bgn_enc2(a0, a1, a2);
    cp_bgn_dec(a0, a1, a2);
    cp_bgn_dec1(a0, a1, a2);
    cp_bgn_dec2(a0, a1, a2);
    cp_ibe_gen(a0, a1);
    cp_ibe_gen_prv(a0, a1, a2);
    cp_ibe_gen_prv(a0, a1, a2, a3);
    cp_ibe_enc(a0, a1, a2, a3, a4, a5);
    cp_ibe_enc(a0, a1, a2, a3, a4, a5, a6);
    cp_ibe_dec(a0, a1, a2, a3, a4);
}

void not_contracted(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8, void *a9, void *a10) {
    bn_add(a0, a1, a2);
    bn_mul(a0, a1, a2);
    fp_mul(a0, a1, a2);
    fp_exp(a0, a1, a2);
    ep_mul(a0, a1, a2);
    g1_mul(a0, a1, a2);
    gt_exp(a0, a1, a2);
    md_map(a0, a1, a2);
}
`
	if err := os.WriteFile(filepath.Join(dir, "app.c"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"core_init#0":              "config",
		"core_clean#0":             "config",
		"ep_param_set#1":           "config",
		"ep_param_set_any#0":       "config",
		"ep_param_set_any_endom#0": "config",
		"ep_param_set_any_kbltz#0": "config",
		"ep_param_set_any_ordin#0": "config",
		"ep_param_set_any_pairf#0": "config",
		"ep_param_set_any_plain#0": "config",
		"ep_param_set_any_super#0": "config",
		"pc_param_set_any#0":       "config",
		"rand_seed#2":              "config",
		"rand_bytes#2":             "operation",
		"md_map_sh224#3":           "operation",
		"md_map_sh256#3":           "operation",
		"md_map_sh384#3":           "operation",
		"md_map_sh512#3":           "operation",
		"md_map_b2s160#3":          "operation",
		"md_map_b2s256#3":          "operation",
		"md_hmac#5":                "operation",
		"md_kdf#4":                 "operation",
		"bc_aes_cbc_enc#7":         "operation",
		"bc_aes_cbc_dec#7":         "operation",
		"ep_map#3":                 "operation",
		"ep2_map#3":                "operation",
		"g1_map#3":                 "operation",
		"g2_map#3":                 "operation",
		"ep_map_dst#5":             "operation",
		"ep2_map_dst#5":            "operation",
		"pc_map#3":                 "operation",
		"pc_map_sim#4":             "operation",
		"pc_exp#2":                 "operation",
		"pp_map_k1#3":              "operation",
		"pp_map_k2#3":              "operation",
		"pp_map_k8#3":              "operation",
		"pp_map_k12#3":             "operation",
		"pp_map_k16#3":             "operation",
		"pp_map_k18#3":             "operation",
		"pp_map_k24#3":             "operation",
		"pp_map_k48#3":             "operation",
		"pp_map_k48#4":             "operation",
		"pp_map_k54#4":             "operation",
		"pp_map_oatep_k8#3":        "operation",
		"pp_map_oatep_k12#3":       "operation",
		"pp_map_oatep_k16#3":       "operation",
		"pp_map_oatep_k18#3":       "operation",
		"pp_map_sim_k1#4":          "operation",
		"pp_map_sim_k2#4":          "operation",
		"pp_map_sim_k8#4":          "operation",
		"pp_map_sim_k12#4":         "operation",
		"pp_map_sim_k16#4":         "operation",
		"pp_map_sim_k18#4":         "operation",
		"pp_map_sim_k24#4":         "operation",
		"pp_map_sim_k48#4":         "operation",
		"pp_map_sim_oatep_k8#4":    "operation",
		"pp_map_sim_oatep_k12#4":   "operation",
		"pp_map_sim_oatep_k16#4":   "operation",
		"pp_map_sim_oatep_k18#4":   "operation",
		"pp_map_sim_tatep_k1#4":    "operation",
		"pp_map_sim_tatep_k2#4":    "operation",
		"pp_map_sim_tatep_k12#4":   "operation",
		"pp_map_sim_tatep_k16#4":   "operation",
		"pp_map_sim_tatep_k18#4":   "operation",
		"pp_map_sim_weilp_k1#4":    "operation",
		"pp_map_sim_weilp_k2#4":    "operation",
		"pp_map_sim_weilp_k12#4":   "operation",
		"pp_map_sim_weilp_k16#4":   "operation",
		"pp_map_sim_weilp_k18#4":   "operation",
		"pp_map_tatep_k1#3":        "operation",
		"pp_map_tatep_k2#3":        "operation",
		"pp_map_tatep_k12#3":       "operation",
		"pp_map_tatep_k16#3":       "operation",
		"pp_map_tatep_k18#3":       "operation",
		"pp_map_weilp_k1#3":        "operation",
		"pp_map_weilp_k2#3":        "operation",
		"pp_map_weilp_k12#3":       "operation",
		"pp_map_weilp_k16#3":       "operation",
		"pp_map_weilp_k18#3":       "operation",
		"cp_rsa_gen#3":             "operation",
		"cp_rsa_gen_basic#3":       "operation",
		"cp_rsa_gen_quick#3":       "operation",
		"cp_rsa_enc#5":             "operation",
		"cp_rsa_dec#5":             "operation",
		"cp_rsa_dec_basic#5":       "operation",
		"cp_rsa_dec_quick#5":       "operation",
		"cp_rsa_sig#6":             "operation",
		"cp_rsa_sig_basic#6":       "operation",
		"cp_rsa_sig_quick#6":       "operation",
		"cp_rsa_ver#5":             "operation",
		"cp_rsa_ver#6":             "operation",
		"cp_rabin_gen#3":           "operation",
		"cp_rabin_enc#5":           "operation",
		"cp_rabin_dec#5":           "operation",
		"cp_ecdh_gen#2":            "operation",
		"cp_ecdh_key#4":            "operation",
		"cp_ecmqv_gen#2":           "operation",
		"cp_ecmqv_key#7":           "operation",
		"cp_sokaka_gen#1":          "operation",
		"cp_sokaka_gen_prv#3":      "operation",
		"cp_sokaka_gen_prv#4":      "operation",
		"cp_sokaka_key#3":          "operation",
		"cp_sokaka_key#5":          "operation",
		"cp_sokaka_key#7":          "operation",
		"cp_ecies_gen#2":           "operation",
		"cp_ecies_enc#6":           "operation",
		"cp_ecies_dec#6":           "operation",
		"cp_ecdsa_gen#2":           "operation",
		"cp_ecdsa_sig#5":           "operation",
		"cp_ecdsa_sig#6":           "operation",
		"cp_ecdsa_ver#5":           "operation",
		"cp_ecdsa_ver#6":           "operation",
		"cp_ecss_gen#2":            "operation",
		"cp_ecss_sig#5":            "operation",
		"cp_ecss_ver#5":            "operation",
		"cp_bls_gen#2":             "operation",
		"cp_bls_sig#4":             "operation",
		"cp_bls_ver#4":             "operation",
		"cp_bbs_gen#3":             "operation",
		"cp_bbs_sig#5":             "operation",
		"cp_bbs_ver#6":             "operation",
		"cp_cls_gen#4":             "operation",
		"cp_cls_sig#7":             "operation",
		"cp_cls_ver#7":             "operation",
		"cp_cli_gen#6":             "operation",
		"cp_cli_sig#11":            "operation",
		"cp_cli_ver#11":            "operation",
		"cp_clb_gen#7":             "operation",
		"cp_clb_sig#11":            "operation",
		"cp_clb_ver#11":            "operation",
		"cp_pss_gen#5":             "operation",
		"cp_pss_sig#5":             "operation",
		"cp_pss_sig#6":             "operation",
		"cp_pss_ver#6":             "operation",
		"cp_pss_ver#7":             "operation",
		"cp_psb_gen#6":             "operation",
		"cp_psb_sig#6":             "operation",
		"cp_psb_sig#7":             "operation",
		"cp_psb_ver#7":             "operation",
		"cp_psb_ver#8":             "operation",
		"cp_mpss_gen#5":            "operation",
		"cp_mpss_sig#7":            "operation",
		"cp_mpss_ver#9":            "operation",
		"cp_mpsb_gen#6":            "operation",
		"cp_mpsb_sig#8":            "operation",
		"cp_mpsb_ver#11":           "operation",
		"cp_zss_gen#3":             "operation",
		"cp_zss_sig#5":             "operation",
		"cp_zss_ver#6":             "operation",
		"cp_vbnn_gen#2":            "operation",
		"cp_vbnn_sig#9":            "operation",
		"cp_vbnn_ver#8":            "operation",
		"cp_vbnn_gen_prv#5":        "operation",
		"cp_phpe_gen#3":            "operation",
		"cp_phpe_enc#3":            "operation",
		"cp_phpe_enc#5":            "operation",
		"cp_phpe_dec#3":            "operation",
		"cp_phpe_dec#6":            "operation",
		"cp_ghpe_gen#3":            "operation",
		"cp_ghpe_enc#4":            "operation",
		"cp_ghpe_dec#5":            "operation",
		"cp_shpe_gen#4":            "operation",
		"cp_shpe_enc#3":            "operation",
		"cp_shpe_enc_prv#3":        "operation",
		"cp_shpe_dec#3":            "operation",
		"cp_bdpe_gen#4":            "operation",
		"cp_bdpe_enc#4":            "operation",
		"cp_bdpe_dec#4":            "operation",
		"cp_bgn_gen#2":             "operation",
		"cp_bgn_enc1#3":            "operation",
		"cp_bgn_enc2#3":            "operation",
		"cp_bgn_dec#3":             "operation",
		"cp_bgn_dec1#3":            "operation",
		"cp_bgn_dec2#3":            "operation",
		"cp_ibe_gen#2":             "operation",
		"cp_ibe_gen_prv#3":         "operation",
		"cp_ibe_gen_prv#4":         "operation",
		"cp_ibe_enc#6":             "operation",
		"cp_ibe_enc#7":             "operation",
		"cp_ibe_dec#5":             "operation",
	}
	negative := map[string]bool{
		"bn_add#3": true, "bn_mul#3": true, "fp_mul#3": true, "fp_exp#3": true,
		"ep_mul#3": true, "g1_mul#3": true, "gt_exp#3": true, "md_map#3": true,
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
				key := bare + "#" + strconv.Itoa(len(call.Arguments))

				if negative[key] {
					if got := kb.ContractsForCFunction(method, len(call.Arguments), true); len(got) != 0 {
						t.Fatalf("%s resolved to %d contract(s), want none", key, len(got))
					}
					seen[key] = true
					continue
				}

				role, ok := want[key]
				if !ok {
					continue
				}
				got := kb.ContractsForCFunction(method, len(call.Arguments), true)
				if len(got) != 1 {
					t.Fatalf("ContractsForCFunction(%q, %d) = %d, want exactly one contract", method, len(call.Arguments), len(got))
				}
				if got[0].Role != role {
					t.Fatalf("%s: role = %q, want %q", key, got[0].Role, role)
				}
				if got[0].SourceLibrary != "relic" {
					t.Fatalf("%s: library = %q, want relic", key, got[0].SourceLibrary)
				}
				seen[key] = true
			}
		}
	}

	for key := range want {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover %q", key)
		}
	}
	for key := range negative {
		if !seen[key] {
			t.Fatalf("parsed calls did not cover negative %q", key)
		}
	}
}

// ep_param_set names the curve every later ECDH, ECDSA, ECIES and pairing call
// runs on, so its argument is operation-determining. The key generators carry
// the modulus size in bits and AES-CBC and HMAC the key length in bytes; md_kdf
// carries the derived key length. Each must sit at the right index with the
// right property and unit, or the finding it supports loses its curve or key size.
func TestRELICContractsCarryParameterRoles(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded("c")
	if err != nil {
		t.Fatalf("LoadEmbedded(c): %v", err)
	}

	type paramRole struct {
		arity, index int
		property     string
		derivation   string
		role         string
	}
	want := map[string]paramRole{
		"ep_param_set#1":     {1, 0, "curve", "argument_value", "operation-determining"},
		"md_hmac#5":          {5, 4, "keySize", "argument_byte_length", "metadata-contributing"},
		"md_kdf#4":           {4, 1, "outputLength", "argument_value", "metadata-contributing"},
		"bc_aes_cbc_enc#7":   {7, 5, "keySize", "argument_byte_length", "metadata-contributing"},
		"bc_aes_cbc_dec#7":   {7, 5, "keySize", "argument_byte_length", "metadata-contributing"},
		"cp_rsa_gen#3":       {3, 2, "keySize", "argument_value", "metadata-contributing"},
		"cp_rsa_gen_basic#3": {3, 2, "keySize", "argument_value", "metadata-contributing"},
		"cp_rsa_gen_quick#3": {3, 2, "keySize", "argument_value", "metadata-contributing"},
		"cp_rabin_gen#3":     {3, 2, "keySize", "argument_value", "metadata-contributing"},
		"cp_phpe_gen#3":      {3, 2, "keySize", "argument_value", "metadata-contributing"},
		"cp_ghpe_gen#3":      {3, 2, "keySize", "argument_value", "metadata-contributing"},
		"cp_shpe_gen#4":      {4, 3, "keySize", "argument_value", "metadata-contributing"},
		"cp_bdpe_gen#4":      {4, 3, "keySize", "argument_value", "metadata-contributing"},
	}

	for key, w := range want {
		method, _, _ := strings.Cut(key, "#")
		got := kb.ContractsFor(method, w.arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", method, w.arity, len(got))
		}
		if len(got[0].Parameters) != 1 {
			t.Fatalf("%s: %d parameter roles, want 1", key, len(got[0].Parameters))
		}
		p := got[0].Parameters[0]
		if p.Index == nil || *p.Index != w.index {
			t.Fatalf("%s: parameter index = %v, want %d", key, p.Index, w.index)
		}
		if p.Role != w.role {
			t.Errorf("%s: parameters[%d].role = %q, want %q", key, w.index, p.Role, w.role)
		}
		if p.Contributes == nil || p.Contributes.Property != w.property || p.Contributes.Derivation != w.derivation {
			t.Errorf("%s: parameters[%d] contributes %#v, want %s via %s", key, w.index, p.Contributes, w.property, w.derivation)
		}
	}
}
