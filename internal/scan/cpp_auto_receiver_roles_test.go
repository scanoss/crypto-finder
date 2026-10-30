// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// The usual BinFHE consumer: every object is `auto`, typed only by the call
// that produced it. The contracts key on lbcrypto::BinFHEContext, so the calls
// on cc carry their roles only once cc is typed from BinFHEContext()'s return.
const cppOpenFHEBinFHEAutoConsumer = `#include "binfhecontext.h"

int gate() {
    auto cc = lbcrypto::BinFHEContext();
    cc.GenerateBinFHEContext(lbcrypto::STD128);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    auto ct1 = cc.Encrypt(sk, 1);
    auto ct2 = cc.Encrypt(sk, 0);
    auto ctAND = cc.EvalBinGate(lbcrypto::AND, ct1, ct2);
    lbcrypto::LWEPlaintext result;
    cc.Decrypt(sk, ctAND, &result);
    return result;
}
`

func TestCPPAutoReceiverSupportingCallsCarryTheirContractRole(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gate.cpp"), []byte(cppOpenFHEBinFHEAutoConsumer), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem("cpp", callgraph.NewCPPParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "gate.cpp",
			Language: "cpp",
			CryptographicAssets: []entities.CryptographicAsset{cAsset(4, 4, 15, 40, "auto cc = lbcrypto::BinFHEContext();",
				"cpp.openfhe.algorithm.fhe.binfhe-context", map[string]string{"assetType": "algorithm"})},
		}},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	result := &engine.DepScanResult{Report: report, CallGraph: graph, ProjectRoot: dir, Ecosystem: "cpp"}

	got := map[string]string{}
	for _, s := range buildGraphFragmentExport(result).SupportingCalls {
		if s.SupportingCall != nil {
			got[s.SupportingCall.FunctionName] = s.Category
		}
	}
	want := map[string]string{
		"lbcrypto::BinFHEContext.GenerateBinFHEContext": "config",
		"lbcrypto::BinFHEContext.KeyGen":                "operation",
		"lbcrypto::BinFHEContext.BTKeyGen":              "operation",
		"lbcrypto::BinFHEContext.Encrypt":               "operation",
		"lbcrypto::BinFHEContext.EvalBinGate":           "operation",
		"lbcrypto::BinFHEContext.Decrypt":               "operation",
	}
	if !equalStringMaps(got, want) {
		t.Errorf("graph fragment supporting calls = %v, want %v", got, want)
	}

	fromCallgraph := map[string]string{}
	for _, s := range buildCallGraphExportV2(result).SupportingCalls {
		fromCallgraph[s.SupportingCall.FunctionName] = s.Category
	}
	if !equalStringMaps(fromCallgraph, want) {
		t.Errorf("callgraph export supporting calls = %v, want %v", fromCallgraph, want)
	}
}
