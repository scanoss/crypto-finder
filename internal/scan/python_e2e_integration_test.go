// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.

// python_e2e_integration_test.go — T-2.3/T-2.4 scan-layer proof
//
// Proves that Python parity (Batch 1+2+3) produces:
//   - crypto_entry_points (via SynthesizeRuleCryptoEntryPoints + scan export)
//   - supporting_calls (via BuildGraphFragmentExport for a detection report)
//   - fluent chain resolution fires (chain link callees rewritten via contract KB)
//
// This is the INTEGRATION PROOF verdict for Batch 3.

package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// buildPythonModuleFragment builds a graph fragment for a Python source file
// using the Python builder + PythonContractTypeResolver. Mirrors buildModuleFragment
// (which is Java-only) for Python. report may be nil for zero-finding modules.
func buildPythonModuleFragment(t *testing.T, file, src string, report *entities.InterimReport) graphfrag.GraphFragmentExport {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser())
	resolver := callgraph.NewPythonContractTypeResolverFromEmbedded()
	b.SetTypeResolver(resolver)

	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "mypkg"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	if report == nil {
		report = &entities.InterimReport{}
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	return BuildGraphFragmentExport(&engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		ProjectRoot: dir,
		RootModule:  "mypkg",
		Ecosystem:   "python",
	})
}

// pythonCipherReport builds an InterimReport that simulates what the scanner
// would produce for a pyca Cipher fluent chain. The finding's api matches the
// pyca Cipher constructor FQN emitted by the Python parser.
//
// The Cipher source used in the test:
//
//	from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
//	def encrypt(key, iv, data):
//	    result = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(data)
//
// The parser emits:
//
//	FunctionID{Package:"cryptography.hazmat.primitives.ciphers", Type:"Cipher", Name:"<init>"}
//
// The dotted FQN for a constructor is Package.Type (e.g., for rule api purposes).
func makePythonCipherFinding(filePath string, line int) *entities.InterimReport {
	r := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: filePath,
			Language: "python",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: line,
				EndLine:   line,
				Match:     "Cipher(algorithms.AES(key), modes.CBC(iv))",
				Rules:     []entities.RuleInfo{{ID: "python.pyca.cipher.aes"}},
				Metadata: map[string]string{
					"api":                "cryptography.hazmat.primitives.ciphers.Cipher.<init>",
					"assetType":          "algorithm",
					"algorithmFamily":    "AES",
					"algorithmPrimitive": "blockcipher",
					"operation":          "encrypt",
				},
			}},
		}},
	}
	return r
}

// TestPythonE2E_BuildGraphFragmentExport_ProducesFunctions asserts that the Python
// builder correctly populates the exported fragment with function nodes.
// This is a basic smoke test for the scan-layer Python path.
func TestPythonE2E_BuildGraphFragmentExport_ProducesFunctions(t *testing.T) {
	t.Parallel()

	src := `from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt(key, iv, data):
    result = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(data)
    return result
`
	export := buildPythonModuleFragment(t, "cipher.py", src, nil)
	if len(export.Functions) == 0 {
		t.Fatal("expected non-empty Functions in Python graph fragment export")
	}

	// Check that the encrypt function appears.
	found := false
	for _, fn := range export.Functions {
		if fn.Name == "encrypt" || fn.Name == "encrypt#0" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("encrypt function not found in fragment export; functions: %v", export.Functions)
	}
}

// TestPythonE2E_BuildGraphFragmentExport_ProducesSupportingCalls asserts that a
// Python fluent-chain callgraph with a detection finding produces SupportingCalls
// in the exported fragment. This proves the full pipeline:
//   callgraph build → type resolution → chain resolution → export → supporting calls
func TestPythonE2E_BuildGraphFragmentExport_ProducesSupportingCalls(t *testing.T) {
	t.Parallel()

	// encrypt() is on line 4. The Cipher call is on line 4.
	src := `from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt(key, iv, data):
    result = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(data)
    return result
`
	report := makePythonCipherFinding("cipher.py", 4)
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	export := buildPythonModuleFragment(t, "cipher.py", src, report)

	// The export must have the crypto annotation.
	if len(export.CryptoAnnotations) == 0 {
		t.Fatal("T-2.4: expected non-empty CryptoAnnotations in Python fragment export")
	}

	// SupportingCalls are the lifecycle calls attached to the crypto annotation.
	// With the Cipher fluent chain resolved via the contract KB, the chain links
	// (encryptor, update) should appear as supporting calls.
	if len(export.SupportingCalls) == 0 {
		// This is a diagnostic — show what we got.
		t.Logf("CryptoAnnotations: %+v", export.CryptoAnnotations)
		t.Logf("SupportingCalls: %v (len=%d)", export.SupportingCalls, len(export.SupportingCalls))
		t.Error("T-2.4: expected non-empty SupportingCalls for Python Cipher chain in fragment export")
	}
}

// TestPythonE2E_SynthesizeRuleCryptoEntryPoints_Python verifies that Python FQN
// api fields from rules produce synthetic crypto entry points when the callgraph
// contains a matching Python function definition. This is the T-2.3-d proof at
// the engine level.
func TestPythonE2E_SynthesizeRuleCryptoEntryPoints_Python(t *testing.T) {
	t.Parallel()

	// The Python parser emits:
	//   FunctionID{Package:"cryptography.hazmat.primitives.ciphers", Type:"Cipher", Name:"<init>"}
	// The synthesis join matches api = "cryptography.hazmat.primitives.ciphers.Cipher.<init>"
	// against the FunctionDecl's dotted FQN.
	src := `from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Cipher:
    def __init__(self, algorithm, mode):
        self.algorithm = algorithm
        self.mode = mode
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cipher.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser())
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "cryptography.hazmat.primitives.ciphers"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	// Write a synthetic rule with the Cipher constructor api.
	ruleDir := t.TempDir()
	ruleBody := "" +
		"rules:\n" +
		"  - id: python.pyca.cipher.cbc\n" +
		"    metadata:\n" +
		"      crypto:\n" +
		"        assetType: algorithm\n" +
		"        algorithmPrimitive: blockcipher\n" +
		"        algorithmFamily: AES\n" +
		"        operation: encrypt\n" +
		"        api: cryptography.hazmat.primitives.ciphers.Cipher.<init>\n"
	rulePath := filepath.Join(ruleDir, "rule.yaml")
	if err := os.WriteFile(rulePath, []byte(ruleBody), 0o600); err != nil {
		t.Fatal(err)
	}

	report := &entities.InterimReport{}
	n := engine.SynthesizeRuleCryptoEntryPoints(report, graph, []string{rulePath})
	if n == 0 {
		// Diagnostic: show what FQNs are in the graph.
		var fqns []string
		for k := range graph.Functions {
			fqns = append(fqns, k)
		}
		t.Errorf("T-2.3-d: expected >=1 synthesized entry point for Python Cipher.<init>, got 0; graph FQNs: %v", fqns)
	}
}
