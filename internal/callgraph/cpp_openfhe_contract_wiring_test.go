// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
)

// The openfhe contracts key on the receiver type or namespace the C++ parser
// emits for a call ("Type.method"). This pins that agreement for every
// contracted method at the arity the parser counts, with its lifecycle role,
// and pins the negative half: the listed calls resolve to no contract.
func TestOpenFHEContractsResolveParsedCallIdentities(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	dir := t.TempDir()
	src := `#include "openfhe.h"
#include "binfhecontext.h"

void flows(lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cc, lbcrypto::BinFHEContext& bf, int x) {
    cc->Enable(x);
    cc->EvalBootstrapSetup();
    cc->EvalBootstrapSetup(x);
    cc->EvalBootstrapSetup(x, x);
    cc->EvalBootstrapSetup(x, x, x);
    cc->EvalBootstrapSetup(x, x, x, x);
    cc->EvalBootstrapSetup(x, x, x, x, x);
    cc->EvalBootstrapSetup(x, x, x, x, x, x);
    cc->KeyGen();
    cc->EvalMultKeyGen(x);
    cc->EvalRotateKeyGen(x, x);
    cc->EvalRotateKeyGen(x, x, x);
    cc->EvalAtIndexKeyGen(x, x);
    cc->EvalAtIndexKeyGen(x, x, x);
    cc->EvalSumKeyGen(x);
    cc->EvalSumKeyGen(x, x);
    cc->EvalBootstrapKeyGen(x, x);
    cc->ReKeyGen(x, x);
    cc->Encrypt(x, x);
    cc->Decrypt(x, x, x);
    cc->ReEncrypt(x, x);
    cc->ReEncrypt(x, x, x);
    cc->EvalBootstrap(x);
    cc->EvalBootstrap(x, x);
    cc->EvalBootstrap(x, x, x);
    cc->EvalAdd(x, x);
    cc->EvalSub(x, x);
    cc->EvalMult(x, x);
    cc->EvalRotate(x, x);
    lbcrypto::GenCryptoContext(x);
    lbcrypto::BinFHEContext();
    bf.GenerateBinFHEContext(x);
    bf.GenerateBinFHEContext(x, x);
    bf.GenerateBinFHEContext(x, x, x);
    bf.GenerateBinFHEContext(x, x, x, x);
    bf.GenerateBinFHEContext(x, x, x, x, x);
    bf.GenerateBinFHEContext(x, x, x, x, x, x);
    bf.GenerateBinFHEContext(x, x, x, x, x, x, x, x);
    bf.GenerateBinFHEContext(x, x, x, x, x, x, x, x, x);
    bf.GenerateBinFHEContext(x, x, x, x, x, x, x, x, x, x);
    bf.GenerateBinFHEContext(x, x, x, x, x, x, x, x, x, x, x);
    bf.KeyGen();
    bf.KeyGenN();
    bf.KeyGenPair();
    bf.PubKeyGen(x);
    bf.BTKeyGen(x);
    bf.BTKeyGen(x, x);
    bf.Encrypt(x, x);
    bf.Encrypt(x, x, x);
    bf.Encrypt(x, x, x, x);
    bf.Encrypt(x, x, x, x, x);
    bf.Decrypt(x, x, x);
    bf.Decrypt(x, x, x, x);
    bf.EvalBinGate(x, x);
    bf.EvalBinGate(x, x, x);
    bf.EvalBinGate(x, x, x, x);
    bf.Bootstrap(x);
    bf.Bootstrap(x, x);
    bf.EvalNOT(x);
    bf.EvalSign(x);
    bf.EvalSign(x, x);
    bf.EvalFunc(x, x);
    cc->MakeCKKSPackedPlaintext(x);
    cc->GetRingDimension();
    bf.GetParams();
}
`
	if err := os.WriteFile(filepath.Join(dir, "fhe.cpp"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.Enable#1":              "config",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalBootstrapSetup#0":  "config",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalBootstrapSetup#1":  "config",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalBootstrapSetup#2":  "config",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalBootstrapSetup#3":  "config",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalBootstrapSetup#4":  "config",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalBootstrapSetup#5":  "config",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalBootstrapSetup#6":  "config",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.KeyGen#0":              "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalMultKeyGen#1":      "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalRotateKeyGen#2":    "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalRotateKeyGen#3":    "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalAtIndexKeyGen#2":   "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalAtIndexKeyGen#3":   "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalSumKeyGen#1":       "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalSumKeyGen#2":       "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalBootstrapKeyGen#2": "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.ReKeyGen#2":            "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.Encrypt#2":             "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.Decrypt#3":             "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.ReEncrypt#2":           "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.ReEncrypt#3":           "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalBootstrap#1":       "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalBootstrap#2":       "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalBootstrap#3":       "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalAdd#2":             "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalSub#2":             "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalMult#2":            "operation",
		"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.EvalRotate#2":          "operation",
		"lbcrypto.GenCryptoContext#1":                                       "factory",
		"lbcrypto.BinFHEContext#0":                                          "factory",
		"lbcrypto::BinFHEContext.GenerateBinFHEContext#1":                   "config",
		"lbcrypto::BinFHEContext.GenerateBinFHEContext#2":                   "config",
		"lbcrypto::BinFHEContext.GenerateBinFHEContext#3":                   "config",
		"lbcrypto::BinFHEContext.GenerateBinFHEContext#4":                   "config",
		"lbcrypto::BinFHEContext.GenerateBinFHEContext#5":                   "config",
		"lbcrypto::BinFHEContext.GenerateBinFHEContext#6":                   "config",
		"lbcrypto::BinFHEContext.GenerateBinFHEContext#8":                   "config",
		"lbcrypto::BinFHEContext.GenerateBinFHEContext#9":                   "config",
		"lbcrypto::BinFHEContext.GenerateBinFHEContext#10":                  "config",
		"lbcrypto::BinFHEContext.GenerateBinFHEContext#11":                  "config",
		"lbcrypto::BinFHEContext.KeyGen#0":                                  "operation",
		"lbcrypto::BinFHEContext.KeyGenN#0":                                 "operation",
		"lbcrypto::BinFHEContext.KeyGenPair#0":                              "operation",
		"lbcrypto::BinFHEContext.PubKeyGen#1":                               "operation",
		"lbcrypto::BinFHEContext.BTKeyGen#1":                                "operation",
		"lbcrypto::BinFHEContext.BTKeyGen#2":                                "operation",
		"lbcrypto::BinFHEContext.Encrypt#2":                                 "operation",
		"lbcrypto::BinFHEContext.Encrypt#3":                                 "operation",
		"lbcrypto::BinFHEContext.Encrypt#4":                                 "operation",
		"lbcrypto::BinFHEContext.Encrypt#5":                                 "operation",
		"lbcrypto::BinFHEContext.Decrypt#3":                                 "operation",
		"lbcrypto::BinFHEContext.Decrypt#4":                                 "operation",
		"lbcrypto::BinFHEContext.EvalBinGate#2":                             "operation",
		"lbcrypto::BinFHEContext.EvalBinGate#3":                             "operation",
		"lbcrypto::BinFHEContext.EvalBinGate#4":                             "operation",
		"lbcrypto::BinFHEContext.Bootstrap#1":                               "operation",
		"lbcrypto::BinFHEContext.Bootstrap#2":                               "operation",
		"lbcrypto::BinFHEContext.EvalNOT#1":                                 "operation",
		"lbcrypto::BinFHEContext.EvalSign#1":                                "operation",
		"lbcrypto::BinFHEContext.EvalSign#2":                                "operation",
		"lbcrypto::BinFHEContext.EvalFunc#2":                                "operation",
	}
	negative := map[string]bool{}
	for _, key := range []string{"lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.MakeCKKSPackedPlaintext#1", "lbcrypto::CryptoContext<lbcrypto::DCRTPoly>.GetRingDimension#0", "lbcrypto::BinFHEContext.GetParams#0"} {
		negative[key] = true
	}
	seen := map[string]bool{}

	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				callee := call.Callee
				method := cppContractMethod(&callee)
				if method == "" {
					continue
				}
				arity := len(call.Arguments)
				key := method + "#" + strconv.Itoa(arity)
				got := kb.ContractsFor(method, arity)
				if negative[key] {
					if len(got) != 0 {
						t.Fatalf("%s resolved to %d contract(s), want none", key, len(got))
					}
					seen[key] = true
					continue
				}
				role, expected := want[key]
				if !expected {
					continue
				}
				if len(got) != 1 {
					t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one openfhe contract", method, arity, len(got))
				}
				if got[0].Role != role || got[0].SourceLibrary != "openfhe" {
					t.Fatalf("contract for %q = role %q library %q, want openfhe %s", key, got[0].Role, got[0].SourceLibrary, role)
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

// GenerateBinFHEContext takes the parameter set first in the overloads a call
// site reaches with one to six arguments; the 8-11 argument overload takes raw
// lattice parameters and attributes nothing.
func TestOpenFHEBinFHEParameterSetIsOperationDetermining(t *testing.T) {
	t.Parallel()

	kb, err := contracts.LoadEmbedded(ecosystemCPP)
	if err != nil {
		t.Fatalf("LoadEmbedded(cpp): %v", err)
	}

	const method = "lbcrypto::BinFHEContext.GenerateBinFHEContext"
	for arity := 1; arity <= 11; arity++ {
		if arity == 7 {
			continue
		}
		got := kb.ContractsFor(method, arity)
		if len(got) != 1 {
			t.Fatalf("ContractsFor(%q, %d) = %d, want exactly one", method, arity, len(got))
		}
		params := got[0].Parameters
		if arity >= 8 {
			if len(params) != 0 {
				t.Errorf("arity %d: %d parameter entries, want none", arity, len(params))
			}
			continue
		}
		if len(params) != 1 || params[0].Index == nil || *params[0].Index != 0 ||
			params[0].Role != "operation-determining" || params[0].Contributes == nil ||
			params[0].Contributes.Property != "parameterSet" {
			t.Errorf("arity %d: parameters = %+v, want index 0 operation-determining parameterSet", arity, params)
		}
	}
}
