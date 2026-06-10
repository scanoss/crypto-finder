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

// buildModuleFragmentFor is the ecosystem-agnostic core of the e2e mine harness.
// It parses one module's source with the supplied parser and ecosystem, runs
// BuildGraphFragmentExport with the supplied detection report, and decodes the
// result the way the mining service does. report may be nil for a zero-crypto
// module. key is used only for error messages and the returned Fragment's
// Component field.
func buildModuleFragmentFor(
	t *testing.T,
	key graphfrag.ComponentKey,
	importPath, file, src string,
	report *entities.InterimReport,
	parser callgraph.Parser,
	ecosystem string,
) graphfrag.Fragment {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem(ecosystem, parser).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: importPath}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories(%s): %v", key.Purl, err)
	}
	if report == nil {
		report = &entities.InterimReport{}
	}
	export := BuildGraphFragmentExport(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: importPath, Ecosystem: ecosystem,
	})
	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal export(%s): %v", key.Purl, err)
	}
	frag, err := graphfrag.DecodeFragment(key, raw)
	if err != nil {
		t.Fatalf("DecodeFragment(%s): %v", key.Purl, err)
	}
	return frag
}

// buildModuleFragment parses one module's Java source with the real call-graph
// builder (the same path a standalone mine uses), runs BuildGraphFragmentExport
// with the supplied detection report, and decodes the result the way the mining
// service does. report may be nil for a zero-crypto module.
//
// This is a Java-specific convenience wrapper around buildModuleFragmentFor.
// Python callers should use buildModuleFragmentFor directly with
// callgraph.NewPythonParser() and ecosystem "python".
func buildModuleFragment(t *testing.T, key graphfrag.ComponentKey, importPath, file, src string, report *entities.InterimReport) graphfrag.Fragment {
	t.Helper()
	return buildModuleFragmentFor(t, key, importPath, file, src, report, callgraph.NewJavaParser(), "java")
}

// TestE2EHarness_Python_Parameterization verifies that buildModuleFragmentFor
// works with the Python parser and ecosystem, producing a non-empty Fragment.
// This is the acceptance test for T-4.1 (harness parameterization).
func TestE2EHarness_Python_Parameterization(t *testing.T) {
	t.Parallel()

	// A minimal Python source with a single function.
	src := `from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt(key, iv, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()
`
	key := graphfrag.ComponentKey{Purl: "pkg:pypi/cryptography", Version: "43.0.0"}
	frag := buildModuleFragmentFor(t, key, "cryptography.hazmat.primitives.ciphers", "cipher.py", src, nil,
		callgraph.NewPythonParser(), "python")

	// The fragment must have at least the encrypt function.
	if len(frag.Functions) == 0 {
		t.Fatal("T-4.1: expected non-empty Functions from Python harness")
	}

	// Verify the Java path is unchanged: existing Java test still calls buildModuleFragment.
	javaKey := graphfrag.ComponentKey{Purl: "pkg:maven/com.test/test", Version: "1.0"}
	javaSrc := `package com.test;
class Hello {
    void greet() {}
}
`
	javaFrag := buildModuleFragment(t, javaKey, "com.test:test", "Hello.java", javaSrc, nil)
	if len(javaFrag.Functions) == 0 {
		t.Fatal("T-4.1: expected non-empty Functions from Java harness (regression check)")
	}
}

// TestStitch_RealParse_ZeroCryptoBridgeReachesTransitiveCrypto is the end-to-end
// guard for the cross-component reachability contract on REAL parser output
// (not hand-authored fragment JSON): three modules — app A, a crypto-free bridge
// B, and crypto leaf C — are each mined in isolation, then stitched. The chain
// must thread A -> B -> C and reach C's finding. This catches regressions the
// hand-authored stitch unit tests cannot: if a parser/inference change makes a
// caller's external_call target_key stop matching the callee's function key
// across module boundaries, the chain silently breaks here.
func TestStitch_RealParse_ZeroCryptoBridgeReachesTransitiveCrypto(t *testing.T) {
	t.Parallel()

	appSrc := `package com.app;
import com.bridge.Bridge;
class App {
    Bridge bridge;
    void execute() {
        bridge.run();
    }
}
`
	bridgeSrc := `package com.bridge;
import com.crypto.CryptoLeaf;
class Bridge {
    CryptoLeaf leaf;
    void run() {
        leaf.generate();
    }
}
`
	// C: the BC EC-keygen call is on line 8 (gen.generateKeyPair()).
	cryptoSrc := `package com.crypto;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
class CryptoLeaf {
    void generate() {
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.generateKeyPair();
    }
}
`
	cReport := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "CryptoLeaf.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 6,
				EndLine:   6,
				Match:     "gen.generateKeyPair()",
				Rules:     []entities.RuleInfo{{ID: "java.bouncycastle.keygen.ec"}},
				Metadata:  map[string]string{"api": "org.bouncycastle.crypto.generators.ECKeyPairGenerator.generateKeyPair", "assetType": "algorithm", "algorithmFamily": "ECDH"},
				OID:       "1.2.840.10045.2.1",
			}},
		}},
	}
	engine.EnsureFindingSources(cReport)
	engine.AssignFindingIDs(cReport)

	a := graphfrag.ComponentKey{Purl: "pkg:maven/com.app/a", Version: "1.0"}
	b := graphfrag.ComponentKey{Purl: "pkg:maven/com.bridge/b", Version: "1.0"}
	c := graphfrag.ComponentKey{Purl: "pkg:maven/com.crypto/c", Version: "1.0"}

	frags := map[graphfrag.ComponentKey]graphfrag.Fragment{
		a: buildModuleFragment(t, a, "com.app:a", "App.java", appSrc, nil),
		b: buildModuleFragment(t, b, "com.bridge:b", "Bridge.java", bridgeSrc, nil),
		c: buildModuleFragment(t, c, "com.crypto:c", "CryptoLeaf.java", cryptoSrc, cReport),
	}

	// Contract precondition: the bridge has no crypto of its own.
	if n := len(frags[b].CryptoOperations); n != 0 {
		t.Fatalf("bridge B must have 0 crypto operations, got %d", n)
	}

	res, err := graphfrag.Stitch(a, graphfrag.DependencyGraph{a: {b}, b: {c}}, frags)
	if err != nil {
		t.Fatalf("Stitch: %v", err)
	}

	var reached bool
	for _, ch := range res.Chains {
		if !strings.Contains(ch.RuleID, "bouncycastle.keygen.ec") {
			continue
		}
		var hasA, hasB, hasC bool
		for _, fr := range ch.Frames {
			switch {
			case strings.HasPrefix(fr.Signature, "com.app"):
				hasA = true
			case strings.HasPrefix(fr.Signature, "com.bridge"):
				hasB = true
			case strings.HasPrefix(fr.Signature, "com.crypto"):
				hasC = true
			}
		}
		if hasA && hasB && hasC {
			reached = true
		} else {
			t.Errorf("keygen chain does not span A->B->C: hasA=%v hasB=%v hasC=%v frames=%+v", hasA, hasB, hasC, ch.Frames)
		}
	}
	if !reached {
		t.Fatalf("no A->B->C chain reached C's crypto finding; chains=%+v", res.Chains)
	}
}
