// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

const (
	javaRSALiteral = `package demo;
import java.security.KeyPairGenerator;
public class K {
    void f() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
    }
}
`
	javaRSAConst = `package demo;
import java.security.KeyPairGenerator;
public class K {
    private static final int BITS = 4096;
    void f() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(BITS);
    }
}
`
	javaRSASpec = `package demo;
import java.security.KeyPairGenerator;
import java.security.spec.RSAKeyGenParameterSpec;
public class K {
    void f() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
    }
}
`
	pythonRSAKeyword = `from cryptography.hazmat.primitives.asymmetric import rsa

def f():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
`
	pythonRSAConstant = `from cryptography.hazmat.primitives.asymmetric import rsa

KEY_SIZE = 3072

def f():
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
`
	goRSALiteral = `package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func f() {
	rsa.GenerateKey(rand.Reader, 2048)
}

func main() { f() }
`
	cRSAGenerateKeyEx = `#include <openssl/rsa.h>

void f(RSA *rsa, BIGNUM *e) {
    RSA_generate_key_ex(rsa, 2048, e, NULL);
}
`
	cWolfAesSetKey = `#include <wolfssl/wolfcrypt/aes.h>

void f(Aes *aes, const byte *key, const byte *iv) {
    wc_AesSetKey(aes, key, 16, iv, AES_ENCRYPTION);
}
`
	cWolfCurve25519 = `#include <wolfssl/wolfcrypt/curve25519.h>

void f(WC_RNG *rng, curve25519_key *k) {
    wc_curve25519_make_key(rng, 32, k);
}
`
	cSodiumGenerichash = `#include <sodium.h>

void f(unsigned char *o, const unsigned char *in, const unsigned char *k) {
    crypto_generichash(o, 32, in, 10, k, 32);
}
`
	cWolfEccMakeKey = `#include <wolfssl/wolfcrypt/ecc.h>

void f(WC_RNG *rng, ecc_key *k) {
    wc_ecc_make_key(rng, 66, k);
}
`
	goFipsPBKDF2 = `package main

import (
	"crypto/sha256"

	"github.com/golang-fips/openssl/v2"
)

func f(pw, salt []byte) {
	openssl.PBKDF2(pw, salt, 1000, 32, sha256.New)
}

func main() { f(nil, nil) }
`
	cRSAKeygenBits = `#include <openssl/evp.h>

void f(EVP_PKEY_CTX *ctx) {
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072);
}
`
)

// TestTerminalKeyLength_ReachableThroughFindingSupportingCallIDs pins that a
// finding whose rule-matched call is itself the key-size call carries exact
// bits under the shape consumers already read: the finding graph's
// supporting_call_ids joined to supporting_calls[].supporting_call.resolved_key_length.
func TestTerminalKeyLength_ReachableThroughFindingSupportingCallIDs(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ecosystem string
		file      string
		source    string
		line      int
		match     string
		api       string
		wantFunc  string
		wantIndex int
		wantBits  int
		// declared is the rule's static keyLength; conflictBits is the value
		// the rule disagreed with, empty when the two agree.
		declared      string
		wantConflict  bool
		wantDeclaredB int
	}{
		{name: "java literal", ecosystem: "java", file: "K.java", source: javaRSALiteral, line: 6, match: "g.initialize(2048)", api: "java.security.KeyPairGenerator.initialize", wantFunc: "java.security.KeyPairGenerator.initialize", wantBits: 2048},
		{name: "java static final", ecosystem: "java", file: "K.java", source: javaRSAConst, line: 7, match: "g.initialize(BITS)", api: "java.security.KeyPairGenerator.initialize", wantFunc: "java.security.KeyPairGenerator.initialize", wantBits: 4096},
		{name: "java spec constructor", ecosystem: "java", file: "K.java", source: javaRSASpec, line: 7, match: "new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)", api: "java.security.spec.RSAKeyGenParameterSpec.<init>", wantFunc: "java.security.spec.RSAKeyGenParameterSpec.<init>", wantBits: 3072},
		{name: "python keyword literal", ecosystem: "python", file: "k.py", source: pythonRSAKeyword, line: 4, match: "rsa.generate_private_key(public_exponent=65537, key_size=2048)", api: "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key", wantFunc: "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key", wantIndex: 1, wantBits: 2048},
		{name: "python module constant", ecosystem: "python", file: "k.py", source: pythonRSAConstant, line: 6, match: "rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)", api: "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key", wantFunc: "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key", wantIndex: 1, wantBits: 3072},
		{name: "go literal", ecosystem: "go", file: "k.go", source: goRSALiteral, line: 9, match: "rsa.GenerateKey(rand.Reader, 2048)", api: "crypto/rsa.GenerateKey", wantFunc: "crypto/rsa.GenerateKey", wantIndex: 1, wantBits: 2048},
		{name: "c RSA_generate_key_ex", ecosystem: "c", file: "k.c", source: cRSAGenerateKeyEx, line: 4, match: "RSA_generate_key_ex(rsa, 2048, e, NULL);", api: "RSA_generate_key_ex", wantFunc: "RSA_generate_key_ex", wantIndex: 1, wantBits: 2048},
		{name: "c EVP_PKEY_CTX_set_rsa_keygen_bits", ecosystem: "c", file: "k.c", source: cRSAKeygenBits, line: 4, match: "EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072);", api: "EVP_PKEY_CTX_set_rsa_keygen_bits", wantFunc: "EVP_PKEY_CTX_set_rsa_keygen_bits", wantIndex: 1, wantBits: 3072},
		{name: "c byte-count key length is reported in bits (wc_AesSetKey 16 bytes)", ecosystem: "c", file: "k.c", source: cWolfAesSetKey, line: 4, match: "wc_AesSetKey(aes, key, 16, iv, AES_ENCRYPTION);", api: "wc_AesSetKey", wantFunc: "wc_AesSetKey", wantIndex: 2, wantBits: 128},
		{name: "c byte-count key length is reported in bits (curve25519 32 bytes)", ecosystem: "c", file: "k.c", source: cWolfCurve25519, line: 4, match: "wc_curve25519_make_key(rng, 32, k);", api: "wc_curve25519_make_key", wantFunc: "wc_curve25519_make_key", wantIndex: 1, wantBits: 256},
		{name: "c byte-count key length is reported in bits (crypto_generichash keylen 32)", ecosystem: "c", file: "k.c", source: cSodiumGenerichash, line: 4, match: "crypto_generichash(o, 32, in, 10, k, 32);", api: "crypto_generichash", wantFunc: "crypto_generichash", wantIndex: 5, wantBits: 256},
		{name: "go byte-count key length is reported in bits (PBKDF2 keyLen 32)", ecosystem: "go", file: "k.go", source: goFipsPBKDF2, line: 10, match: "openssl.PBKDF2(pw, salt, 1000, 32, sha256.New)", api: "github.com/golang-fips/openssl/v2.PBKDF2", wantFunc: "github.com/golang-fips/openssl/v2.PBKDF2", wantIndex: 3, wantBits: 256},
		{name: "rule agrees", ecosystem: "java", file: "K.java", source: javaRSALiteral, line: 6, match: "g.initialize(2048)", api: "java.security.KeyPairGenerator.initialize", wantFunc: "java.security.KeyPairGenerator.initialize", wantBits: 2048, declared: "2048"},
		{name: "rule conflict keeps both values", ecosystem: "python", file: "k.py", source: pythonRSAKeyword, line: 4, match: "rsa.generate_private_key(public_exponent=65537, key_size=2048)", api: "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key", wantFunc: "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key", wantIndex: 1, wantBits: 2048, declared: "1024", wantConflict: true, wantDeclaredB: 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.source), 0o600); err != nil {
				t.Fatal(err)
			}
			packageDir := callgraph.PackageDir{Dir: dir}
			if tc.ecosystem != "c" {
				packageDir.ImportPath = "ladder"
			}
			graph, err := callgraph.NewBuilderForEcosystem(tc.ecosystem, callgraph.NewParserForEcosystem(tc.ecosystem)).
				BuildFromDirectories([]callgraph.PackageDir{packageDir}, nil)
			if err != nil {
				t.Fatalf("BuildFromDirectories: %v", err)
			}
			startCol := 1 + strings.Index(strings.Split(tc.source, "\n")[tc.line-1], tc.match[:strings.IndexAny(tc.match+"(", "(")])
			metadata := map[string]string{"api": tc.api}
			if tc.declared != "" {
				metadata["keyLength"] = tc.declared
			}
			report := &entities.InterimReport{
				Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"},
				Findings: []entities.Finding{{
					FilePath: tc.file,
					Language: tc.ecosystem,
					CryptographicAssets: []entities.CryptographicAsset{{
						StartLine: tc.line, EndLine: tc.line, StartCol: startCol, EndCol: startCol + len(tc.match), Match: tc.match,
						Rules:    []entities.RuleInfo{{ID: "test.rsa.keygen"}},
						Metadata: metadata,
					}},
				}},
			}
			engine.EnsureFindingSources(report)
			engine.AssignFindingIDs(report)
			findingID := report.Findings[0].CryptographicAssets[0].FindingID
			result := &engine.DepScanResult{Report: report, CallGraph: graph, ProjectRoot: dir, Ecosystem: tc.ecosystem}

			live := buildCallGraphExportV2(result)
			fragmentBytes, err := json.Marshal(buildGraphFragmentExport(result))
			if err != nil {
				t.Fatal(err)
			}
			component := graphfrag.ComponentKey{Purl: "pkg:generic/terminal-key-length", Version: "1.0.0"}
			fragment, err := graphfrag.DecodeFragment(component, fragmentBytes)
			if err != nil {
				t.Fatalf("DecodeFragment: %v", err)
			}
			stitched, err := graphfrag.Stitch(component, graphfrag.DependencyGraph{component: nil}, map[graphfrag.ComponentKey]graphfrag.Fragment{component: fragment})
			if err != nil {
				t.Fatalf("Stitch: %v", err)
			}
			stitchedExport := stitched.ToCallgraphExport(component, graphfrag.ScanMeta{Ecosystem: tc.ecosystem})

			for name, got := range map[string]*graphfrag.ResolvedKeyLength{
				"live":     keyLengthViaSupportingCallIDs(t, live.FindingGraphs, live.SupportingCalls, findingID, tc.wantFunc),
				"stitched": keyLengthViaStitchedSupportingCallIDs(t, stitchedExport, findingID, tc.wantFunc),
			} {
				if got == nil || got.Bits == nil || *got.Bits != tc.wantBits {
					t.Fatalf("%s: resolved_key_length = %#v, want %d bits", name, got, tc.wantBits)
				}
				if got.Provenance != keyLengthProvenanceConstant || got.SourceCall.ParameterIndex != tc.wantIndex || got.SourceCall.Line != tc.line {
					t.Fatalf("%s: provenance/source = %#v, want constant at parameter %d line %d", name, got, tc.wantIndex, tc.line)
				}
				if got.RuleConflict != tc.wantConflict {
					t.Fatalf("%s: rule_conflict = %v, want %v", name, got.RuleConflict, tc.wantConflict)
				}
				if tc.wantConflict && (got.RuleDeclaredBits == nil || *got.RuleDeclaredBits != tc.wantDeclaredB) {
					t.Fatalf("%s: rule_declared_bits = %v, want %d (rule value kept, never overwritten)", name, got.RuleDeclaredBits, tc.wantDeclaredB)
				}
				if !tc.wantConflict && got.RuleDeclaredBits != nil {
					t.Fatalf("%s: rule_declared_bits = %d, want absent when rule and call graph agree", name, *got.RuleDeclaredBits)
				}
			}
			assertNoTerminalKeyLength(t, live, findingID)
		})
	}
}

// TestTerminalKeyLength_NonKeySizeTerminalAddsNoSupportingCall guards against
// echoing every terminal call as a supporting call: a terminal with no keySize
// contribution must keep its previous supporting-call list.
func TestTerminalKeyLength_NonKeySizeTerminalAddsNoSupportingCall(t *testing.T) {
	const source = `from cryptography.hazmat.primitives.asymmetric import ec

def f():
    return ec.generate_private_key(ec.SECP384R1())
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "k.py"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	report := &entities.InterimReport{
		Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "k.py", Language: "python",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 4, EndLine: 4, Match: "ec.generate_private_key(ec.SECP384R1())",
				Rules:    []entities.RuleInfo{{ID: "test.ec.keygen"}},
				Metadata: map[string]string{"api": "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key"},
			}},
		}},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	live := buildCallGraphExportV2(&engine.DepScanResult{Report: report, CallGraph: graph, ProjectRoot: dir, Ecosystem: "python"})
	if len(live.SupportingCalls) != 0 {
		t.Fatalf("supporting calls = %d, want none for a terminal that fixes no key size", len(live.SupportingCalls))
	}
}

// TestTerminalKeyLength_UnclearUnitStaysAbsent pins that a keySize role whose
// unit the audit could not establish (wolfSSL ECC key size, which is a byte
// count that misstates P-521) reports nothing rather than a guessed size.
func TestTerminalKeyLength_UnclearUnitStaysAbsent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "k.c"), []byte(cWolfEccMakeKey), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem("c", callgraph.NewCParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	report := &entities.InterimReport{
		Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "k.c", Language: "c",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 4, EndLine: 4, StartCol: 5, EndCol: 33, Match: "wc_ecc_make_key(rng, 66, k);",
				Rules:    []entities.RuleInfo{{ID: "test.ecc.keygen"}},
				Metadata: map[string]string{"api": "wc_ecc_make_key"},
			}},
		}},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	live := buildCallGraphExportV2(&engine.DepScanResult{Report: report, CallGraph: graph, ProjectRoot: dir, Ecosystem: "c"})
	for i := range live.SupportingCalls {
		if call := live.SupportingCalls[i].SupportingCall; call != nil && call.ResolvedKeyLength != nil {
			t.Fatalf("resolved_key_length = %#v, want absent for a key size of unclear unit", call.ResolvedKeyLength)
		}
	}
}

func keyLengthViaSupportingCallIDs(t *testing.T, graphs []callGraphExportFinding, supporting []callGraphSupportingCall, findingID, function string) *graphfrag.ResolvedKeyLength {
	t.Helper()
	for i := range graphs {
		if graphs[i].FindingID != findingID {
			continue
		}
		for _, id := range graphs[i].SupportingCallIDs {
			for j := range supporting {
				if supporting[j].SupportingID == id && supporting[j].SupportingCall != nil && supporting[j].SupportingCall.FunctionName == function {
					return supporting[j].SupportingCall.ResolvedKeyLength
				}
			}
		}
	}
	return nil
}

func keyLengthViaStitchedSupportingCallIDs(t *testing.T, export graphfrag.CallgraphExport, findingID, function string) *graphfrag.ResolvedKeyLength {
	t.Helper()
	for i := range export.FindingGraphs {
		if export.FindingGraphs[i].FindingID != findingID {
			continue
		}
		for _, id := range export.FindingGraphs[i].SupportingCallIDs {
			for j := range export.SupportingCalls {
				call := export.SupportingCalls[j].SupportingCall
				if export.SupportingCalls[j].SupportingID == id && call != nil && call.FunctionName == function {
					return call.ResolvedKeyLength
				}
			}
		}
	}
	return nil
}
