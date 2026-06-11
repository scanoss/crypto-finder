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
//
//	callgraph build → type resolution → chain resolution → export → supporting calls
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
	n := engine.SynthesizeRuleCryptoEntryPoints(report, graph, []string{rulePath}, "python")
	if n == 0 {
		// Diagnostic: show what FQNs are in the graph.
		fqns := make([]string, 0, len(graph.Functions))
		for k := range graph.Functions {
			fqns = append(fqns, k)
		}
		t.Errorf("T-2.3-d: expected >=1 synthesized entry point for Python Cipher.<init>, got 0; graph FQNs: %v", fqns)
	}
}

// TestPythonE2E_Paramiko_RSAKey_Generate_Synthesis proves that mining paramiko's own source
// for paramiko.rsakey.RSAKey.generate produces a synthesized crypto entry point.
// This closes the Batch 4 gap (risk #1): paramiko rules existed but synthesis was never
// explicitly asserted for a paramiko terminal method.
//
// The paramiko KB declares `paramiko.rsakey.RSAKey.generate` → RSAKey. When mining
// paramiko's own source, the Python parser emits a FunctionDecl for `generate` with
// Package="paramiko.rsakey" and Type="RSAKey". The synthesis join matches the rule api
// "paramiko.rsakey.RSAKey.generate" and emits a crypto entry point.
func TestPythonE2E_Paramiko_RSAKey_Generate_Synthesis(t *testing.T) {
	t.Parallel()

	// Stub: mining paramiko/rsakey.py — RSAKey is a class with a generate classmethod.
	// The Python parser emits:
	//   FunctionDecl{ID: {Package:"paramiko.rsakey", Type:"RSAKey", Name:"generate"}}
	// dotted FQN → "paramiko.rsakey.RSAKey.generate" (3 dots, passes isQualifiedMethodSymbol gate).
	src := `"""Paramiko RSA key stub (for synthesis test)."""

class RSAKey:
    @classmethod
    def generate(cls, bits=2048, progress_func=None):
        """Generate a new RSA private key."""
        pass

    def sign_ssh_data(self, data):
        """Sign data with this RSA key."""
        pass
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rsakey.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser())
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "paramiko.rsakey"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	// Rule: paramiko RSAKey.generate with the FQN that matches the parser output.
	ruleDir := t.TempDir()
	ruleBody := "rules:\n" +
		"  - id: python.paramiko.algorithm.signature.rsa\n" +
		"    metadata:\n" +
		"      crypto:\n" +
		"        assetType: algorithm\n" +
		"        algorithmPrimitive: signature\n" +
		"        algorithmFamily: RSASSA-PKCS1\n" +
		"        operation: keygen\n" +
		"        api: paramiko.rsakey.RSAKey.generate\n"
	rulePath := filepath.Join(ruleDir, "rule.yaml")
	if err := os.WriteFile(rulePath, []byte(ruleBody), 0o600); err != nil {
		t.Fatal(err)
	}

	report := &entities.InterimReport{}
	n := engine.SynthesizeRuleCryptoEntryPoints(report, graph, []string{rulePath}, "python")
	if n == 0 {
		fqns := make([]string, 0, len(graph.Functions))
		for k := range graph.Functions {
			fqns = append(fqns, k)
		}
		t.Errorf("Paramiko synthesis: expected >=1 synthesized entry point for paramiko.rsakey.RSAKey.generate, got 0; graph FQNs: %v", fqns)
	}
}

// TestPythonE2E_Cryptodome_AESNew_Synthesis verifies that `Cryptodome.*` namespace
// (pycryptodomex) synthesizes entry points identically to `Crypto.*` (pycryptodome).
// This is the e2e acceptance test for TASK C (Cryptodome.* alias KB coverage).
func TestPythonE2E_Cryptodome_AESNew_Synthesis(t *testing.T) {
	t.Parallel()

	// Source mirrors the pycryptodome test but with Cryptodome.Cipher.AES import path.
	// The Python parser emits: FunctionDecl{ID: {Package:"Cryptodome.Cipher.AES", Name:"new"}}
	// functionFQN → "Cryptodome.Cipher.AES.new" which matches the pycryptodomex KB entry.
	src := `"""AES cipher module (pycryptodomex-style stub for testing)."""

def new(key, mode, **kwargs):
    """Create a new AES cipher object (Cryptodome namespace)."""
    pass
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "aes.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser())
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "Cryptodome.Cipher.AES"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	// Rule with the Cryptodome AES.new FQN form.
	ruleDir := t.TempDir()
	ruleBody := "rules:\n" +
		"  - id: python.pycryptodome.algorithm.ae.aes-gcm.cryptodome\n" +
		"    metadata:\n" +
		"      crypto:\n" +
		"        assetType: algorithm\n" +
		"        algorithmPrimitive: ae\n" +
		"        algorithmFamily: AES\n" +
		"        operation: encrypt\n" +
		"        api: Cryptodome.Cipher.AES.new\n"
	rulePath := filepath.Join(ruleDir, "rule.yaml")
	if err := os.WriteFile(rulePath, []byte(ruleBody), 0o600); err != nil {
		t.Fatal(err)
	}

	report := &entities.InterimReport{}
	n := engine.SynthesizeRuleCryptoEntryPoints(report, graph, []string{rulePath}, "python")
	if n == 0 {
		fqns := make([]string, 0, len(graph.Functions))
		for k := range graph.Functions {
			fqns = append(fqns, k)
		}
		t.Errorf("Cryptodome alias: expected >=1 synthesized entry point for Cryptodome.Cipher.AES.new, got 0; graph FQNs: %v", fqns)
	}
}

// TestPythonE2E_Pycryptodome_AESNew_FQNFix verifies that after the from-import parser fix,
// `from Crypto.Cipher import AES; AES.new(key, mode)` emits FQN "Crypto.Cipher.AES.new"
// which matches the pycryptodome KB entry and a rule with api="Crypto.Cipher.AES.new"
// produces a synthesized crypto entry point.
//
// This is the acceptance test for the Batch 4 pycryptodome FQN bug fix (#1708).
func TestPythonE2E_Pycryptodome_AESNew_FQNFix(t *testing.T) {
	t.Parallel()

	// Source: mining pycryptodome's own Crypto.Cipher.AES module — `new` is a
	// module-level factory function (not a class method). The parser emits:
	//   FunctionDecl{ID: {Package:"Crypto.Cipher.AES", Name:"new"}}
	// functionFQN → "Crypto.Cipher.AES.new" which matches the rule api exactly.
	src := `"""AES cipher module (pycryptodome-style stub for testing)."""

def new(key, mode, **kwargs):
    """Create a new AES cipher object."""
    pass
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "aes.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser())
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "Crypto.Cipher.AES"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	// Rule with the pycryptodome AES.new FQN form.
	ruleDir := t.TempDir()
	ruleBody := "rules:\n" +
		"  - id: python.pycryptodome.algorithm.ae.aes-gcm\n" +
		"    metadata:\n" +
		"      crypto:\n" +
		"        assetType: algorithm\n" +
		"        algorithmPrimitive: ae\n" +
		"        algorithmFamily: AES\n" +
		"        operation: encrypt\n" +
		"        api: Crypto.Cipher.AES.new\n"
	rulePath := filepath.Join(ruleDir, "rule.yaml")
	if err := os.WriteFile(rulePath, []byte(ruleBody), 0o600); err != nil {
		t.Fatal(err)
	}

	report := &entities.InterimReport{}
	n := engine.SynthesizeRuleCryptoEntryPoints(report, graph, []string{rulePath}, "python")
	if n == 0 {
		fqns := make([]string, 0, len(graph.Functions))
		for k := range graph.Functions {
			fqns = append(fqns, k)
		}
		t.Errorf("Pycryptodome FQN fix: expected >=1 synthesized entry point for Crypto.Cipher.AES.new, got 0; graph FQNs: %v", fqns)
	}
}

// TestPythonE2E_Bcrypt_Hashpw_Synthesis proves that mining bcrypt's own source
// produces a synthesized crypto entry point for bcrypt.hashpw (1-dot api).
//
// Before the Batch 6 gate change (isQualifiedMethodSymbol now accepts 1-dot under
// "python"), bcrypt.hashpw had only 1 dot and was BLOCKED by the >= 2-dot gate —
// bcrypt was detection-only. After the change it SYNTHESIZES when mined.
//
// Safety property: synthesis only fires because "hashpw" is actually declared in
// the scanned source (indexGraphDeclarations finds it). A consumer scan of code
// that only calls bcrypt.hashpw (call sites, no definition) will NOT synthesize.
func TestPythonE2E_Bcrypt_Hashpw_Synthesis(t *testing.T) {
	t.Parallel()

	// Stub: mining bcrypt/__init__.py — hashpw is a module-level function.
	// The Python parser emits:
	//   FunctionDecl{ID: {Package:"bcrypt", Name:"hashpw"}}
	// functionFQN → "bcrypt.hashpw" (1 dot; passes new >= 1-dot Python gate).
	src := `"""bcrypt stub for synthesis test."""

def hashpw(password, salt):
    """Hash the supplied password with bcrypt."""
    pass

def checkpw(password, hashed_password):
    """Check that a plaintext password matches a hashed password."""
    pass

def gensalt(rounds=12, prefix=b"2b"):
    """Generate a random salt for bcrypt."""
    pass
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "__init__.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser())
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "bcrypt"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	ruleDir := t.TempDir()
	ruleBody := "rules:\n" +
		"  - id: python.bcrypt.algorithm.kdf.bcrypt\n" +
		"    metadata:\n" +
		"      crypto:\n" +
		"        assetType: algorithm\n" +
		"        algorithmPrimitive: kdf\n" +
		"        algorithmFamily: bcrypt\n" +
		"        operation: keyderive\n" +
		"        api: bcrypt.hashpw\n"
	rulePath := filepath.Join(ruleDir, "rule.yaml")
	if err := os.WriteFile(rulePath, []byte(ruleBody), 0o600); err != nil {
		t.Fatal(err)
	}

	report := &entities.InterimReport{}
	n := engine.SynthesizeRuleCryptoEntryPoints(report, graph, []string{rulePath}, "python")
	if n == 0 {
		fqns := make([]string, 0, len(graph.Functions))
		for k := range graph.Functions {
			fqns = append(fqns, k)
		}
		t.Errorf("bcrypt synthesis (1-dot Python gate): expected >=1 synthesized entry point for bcrypt.hashpw, got 0; graph FQNs: %v", fqns)
	} else {
		api := report.Findings[0].CryptographicAssets[0].Metadata["api"]
		if api != "bcrypt.hashpw" {
			t.Errorf("synthesized api = %q, want bcrypt.hashpw", api)
		}
	}
}

// TestPythonE2E_PyJWT_Encode_Synthesis proves that mining PyJWT's own source
// produces a synthesized crypto entry point for jwt.encode (1-dot api).
//
// Same gate story as bcrypt: jwt.encode was blocked by the >= 2-dot gate.
// After the Batch 6 change it synthesizes under "python" ecosystem.
func TestPythonE2E_PyJWT_Encode_Synthesis(t *testing.T) {
	t.Parallel()

	// Stub: mining jwt/api.py — encode is a module-level function in the jwt package.
	// The Python parser emits: FunctionDecl{ID: {Package:"jwt", Name:"encode"}}
	// functionFQN → "jwt.encode" (1 dot; passes new >= 1-dot Python gate).
	src := `"""PyJWT stub for synthesis test."""

def encode(payload, key, algorithm="HS256", headers=None, json_encoder=None):
    """Encode a JWT token."""
    pass

def decode(jwt_token, key, algorithms=None, options=None, audience=None, issuer=None):
    """Decode a JWT token."""
    pass
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "api.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser())
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "jwt"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	ruleDir := t.TempDir()
	ruleBody := "rules:\n" +
		"  - id: python.pyjwt.algorithm.mac.jwt\n" +
		"    metadata:\n" +
		"      crypto:\n" +
		"        assetType: algorithm\n" +
		"        algorithmPrimitive: mac\n" +
		"        algorithmFamily: HMAC\n" +
		"        operation: tag\n" +
		"        api: jwt.encode\n"
	rulePath := filepath.Join(ruleDir, "rule.yaml")
	if err := os.WriteFile(rulePath, []byte(ruleBody), 0o600); err != nil {
		t.Fatal(err)
	}

	report := &entities.InterimReport{}
	n := engine.SynthesizeRuleCryptoEntryPoints(report, graph, []string{rulePath}, "python")
	if n == 0 {
		fqns := make([]string, 0, len(graph.Functions))
		for k := range graph.Functions {
			fqns = append(fqns, k)
		}
		t.Errorf("PyJWT synthesis (1-dot Python gate): expected >=1 synthesized entry point for jwt.encode, got 0; graph FQNs: %v", fqns)
	} else {
		api := report.Findings[0].CryptographicAssets[0].Metadata["api"]
		if api != "jwt.encode" {
			t.Errorf("synthesized api = %q, want jwt.encode", api)
		}
	}
}

// TestPythonE2E_Bcrypt_ConsumerScan_NoSynthesis verifies the safety property from
// decision #1715: synthesis does NOT fire in a consumer scan (code that CALLS
// bcrypt.hashpw but does not DEFINE it). The lowered gate does not over-synthesize.
func TestPythonE2E_Bcrypt_ConsumerScan_NoSynthesis(t *testing.T) {
	t.Parallel()

	// A consumer file: calls bcrypt.hashpw but doesn't define it.
	// The parser will emit a CALL edge, not a FunctionDecl for hashpw.
	// indexGraphDeclarations will find no "bcrypt.hashpw" definition.
	src := `"""Consumer code that uses bcrypt — NOT the bcrypt library itself."""
import bcrypt

def register_user(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "auth.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	b := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser())
	graph, err := b.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "myapp.auth"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	ruleDir := t.TempDir()
	ruleBody := "rules:\n" +
		"  - id: python.bcrypt.algorithm.kdf.bcrypt\n" +
		"    metadata:\n" +
		"      crypto:\n" +
		"        assetType: algorithm\n" +
		"        algorithmPrimitive: kdf\n" +
		"        algorithmFamily: bcrypt\n" +
		"        operation: keyderive\n" +
		"        api: bcrypt.hashpw\n"
	rulePath := filepath.Join(ruleDir, "rule.yaml")
	if err := os.WriteFile(rulePath, []byte(ruleBody), 0o600); err != nil {
		t.Fatal(err)
	}

	report := &entities.InterimReport{}
	n := engine.SynthesizeRuleCryptoEntryPoints(report, graph, []string{rulePath}, "python")
	if n != 0 {
		t.Errorf("safety property violated: bcrypt consumer scan synthesized %d entry points, want 0 (hashpw not defined here)", n)
	}
}
