// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// sameLineCase is one finding on a line that also starts a nested function.
// line is the finding's line in source; match is the finding's matched text.
type sameLineCase struct {
	name      string
	ecosystem string
	file      string
	source    string
	line      int
	match     string
	api       string
	wantFunc  string // supporting call name carrying the size
	wantBits  int
	wantOwner string // simple name of the function the chain must start in
}

func (tc sameLineCase) run(t *testing.T) {
	t.Helper()
	exports := terminalExports(t, tc.ecosystem, tc.file, tc.source, tc.line, tc.match, tc.api, "")

	var graph *callGraphExportFinding
	for i := range exports.live.FindingGraphs {
		if exports.live.FindingGraphs[i].FindingID == exports.findingID {
			graph = &exports.live.FindingGraphs[i]
		}
	}
	if graph == nil {
		t.Fatal("no finding graph")
	}
	if graph.UnresolvedReason != "" {
		t.Fatalf("unresolved_reason = %q, want the call attributed to its enclosing function", graph.UnresolvedReason)
	}
	if graph.MatchedOperation == nil || graph.MatchedOperation.Symbol != tc.wantFunc {
		t.Fatalf("matched_operation = %#v, want symbol %s", graph.MatchedOperation, tc.wantFunc)
	}
	if len(graph.CallChains) == 0 {
		t.Fatal("no call chain")
	}
	for _, chain := range graph.CallChains {
		last := chain[len(chain)-1]
		if last.CryptoCall == nil || last.CryptoCall.FunctionName != tc.wantFunc {
			t.Fatalf("chain ends in %#v, want crypto_call %s", last.CryptoCall, tc.wantFunc)
		}
		if strings.Contains(last.FunctionKey, "<anonymous>") {
			t.Fatalf("chain ends in the callback %s, want the enclosing function", last.FunctionKey)
		}
		if !strings.Contains(last.FunctionKey, tc.wantOwner) {
			t.Fatalf("chain ends in %s, want a frame in %s", last.FunctionKey, tc.wantOwner)
		}
	}
	for name, got := range map[string]*graphfrag.ResolvedKeyLength{
		"live":     keyLengthViaSupportingCallIDs(t, exports.live.FindingGraphs, exports.live.SupportingCalls, exports.findingID, tc.wantFunc),
		"stitched": keyLengthViaStitchedSupportingCallIDs(t, exports.stitched, exports.findingID, tc.wantFunc),
	} {
		if got == nil || got.Bits == nil || *got.Bits != tc.wantBits {
			t.Fatalf("%s: resolved_key_length = %#v, want %d bits", name, got, tc.wantBits)
		}
	}
}

const (
	jsCallbackHeader = "const crypto = require('crypto');\n"

	jsEmptyBody = jsCallbackHeader + `function emptyBody() {
  crypto.generateKeyPair('rsa', { modulusLength: 2048 }, (err, pub, priv) => {});
}
`
	jsSameLineBody = jsCallbackHeader + `function sameLineBody() {
  crypto.generateKeyPair('rsa', { modulusLength: 2048 }, (err, pub, priv) => { use(pub); });
}
`
	jsFuncExpr = jsCallbackHeader + `function funcExpr() {
  crypto.generateKeyPair('rsa', { modulusLength: 2048 }, function (err, pub) {
    use(pub);
  });
}
`
	tsArrow = `import * as crypto from 'node:crypto';
export function makeKey(): void {
  crypto.generateKeyPair('rsa', { modulusLength: 3072 }, (err: Error | null, pub: crypto.KeyObject) => { use(pub); });
}
`
	goFuncLiteral = `package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func f(use func(*rsa.PrivateKey)) {
	use(func() *rsa.PrivateKey { k, _ := rsa.GenerateKey(rand.Reader, 2048); return k }())
}
`
	javaAnonymousClass = `import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public class K {
    void f() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048, new SecureRandom() { public void nextBytes(byte[] b) { } });
    }
}
`
	javaLambda = `import java.security.KeyPairGenerator;
import java.util.function.Consumer;

public class K {
    void f(Consumer<String> sink) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        Runnable r = () -> { sink.accept("x"); }; g.initialize(2048);
    }
}
`
	pythonLambda = `from cryptography.hazmat.primitives.asymmetric import rsa

def f(use):
    use(lambda: 1, rsa.generate_private_key(public_exponent=65537, key_size=2048))
`
)

// TestColumnAwareContainment_SameLineCallback pins the fix for a finding on a
// line where a nested function also starts: the finding belongs to the function
// that encloses the call, not to the callback that begins later on its line.
// The graph keeps its crypto call, its chain ends in it, and the key size
// stays reachable through supporting_call_ids.
func TestColumnAwareContainment_SameLineCallback(t *testing.T) {
	const nodeAPI = "crypto.generateKeyPair"
	for _, tc := range []sameLineCase{
		{name: "js arrow with an empty body", ecosystem: "node", file: "k.js", source: jsEmptyBody, line: 3, match: "crypto.generateKeyPair('rsa', { modulusLength: 2048 }, (err, pub, priv) => {})", api: nodeAPI, wantFunc: nodeAPI, wantBits: 2048, wantOwner: "emptyBody"},
		{name: "js arrow with a same-line body", ecosystem: "node", file: "k.js", source: jsSameLineBody, line: 3, match: "crypto.generateKeyPair('rsa', { modulusLength: 2048 }, (err, pub, priv) => { use(pub); })", api: nodeAPI, wantFunc: nodeAPI, wantBits: 2048, wantOwner: "sameLineBody"},
		{name: "js function expression", ecosystem: "node", file: "k.js", source: jsFuncExpr, line: 3, match: "crypto.generateKeyPair('rsa', { modulusLength: 2048 }, function (err, pub) {", api: nodeAPI, wantFunc: nodeAPI, wantBits: 2048, wantOwner: "funcExpr"},
		{name: "ts arrow", ecosystem: "node", file: "k.ts", source: tsArrow, line: 3, match: "crypto.generateKeyPair('rsa', { modulusLength: 3072 }, (err: Error | null, pub: crypto.KeyObject) => { use(pub); })", api: nodeAPI, wantFunc: "node:crypto.generateKeyPair", wantBits: 3072, wantOwner: "makeKey"},
		{name: "java anonymous class method", ecosystem: "java", file: "K.java", source: javaAnonymousClass, line: 7, match: "g.initialize(2048, new SecureRandom() { public void nextBytes(byte[] b) { } })", api: "java.security.KeyPairGenerator.initialize", wantFunc: "java.security.KeyPairGenerator.initialize", wantBits: 2048, wantOwner: "f"},
		{name: "java lambda", ecosystem: "java", file: "K.java", source: javaLambda, line: 7, match: "g.initialize(2048)", api: "java.security.KeyPairGenerator.initialize", wantFunc: "java.security.KeyPairGenerator.initialize", wantBits: 2048, wantOwner: "f"},
		{name: "go func literal", ecosystem: "go", file: "k.go", source: goFuncLiteral, line: 9, match: "rsa.GenerateKey(rand.Reader, 2048)", api: "crypto/rsa.GenerateKey", wantFunc: "crypto/rsa.GenerateKey", wantBits: 2048, wantOwner: "f"},
		{name: "python lambda", ecosystem: "python", file: "k.py", source: pythonLambda, line: 4, match: "rsa.generate_private_key(public_exponent=65537, key_size=2048)", api: "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key", wantFunc: "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key", wantBits: 2048, wantOwner: "f"},
	} {
		t.Run(tc.name, tc.run)
	}
}

const (
	jsNamedCallback = jsCallbackHeader + `function onKey(err, pub) { use(pub); }
function named() {
  crypto.generateKeyPair('rsa', { modulusLength: 2048 }, onKey);
}
`
)

// TestColumnAwareContainment_UnchangedShapes guards the shapes that already
// worked: a named callback. A callback on a later line is covered by the index test.
func TestColumnAwareContainment_UnchangedShapes(t *testing.T) {
	const nodeAPI = "crypto.generateKeyPair"
	for _, tc := range []sameLineCase{
		{name: "named callback", ecosystem: "node", file: "k.js", source: jsNamedCallback, line: 4, match: "crypto.generateKeyPair('rsa', { modulusLength: 2048 }, onKey)", api: nodeAPI, wantFunc: nodeAPI, wantBits: 2048, wantOwner: "named"},
	} {
		t.Run(tc.name, tc.run)
	}
}

// TestColumnAwareContainment_Index pins the containment rule itself: the
// innermost function whose span holds the start position wins, a function that
// starts later on the finding's line does not hold it, and a finding without a
// column keeps the line-only answer.
func TestColumnAwareContainment_Index(t *testing.T) {
	outer := &callgraph.FunctionDecl{ID: callgraph.FunctionID{Name: "outer"}, StartLine: 1, StartCol: 1, EndLine: 5, EndCol: 2}
	arrow := &callgraph.FunctionDecl{ID: callgraph.FunctionID{Name: "arrow"}, StartLine: 2, StartCol: 40, EndLine: 2, EndCol: 60}
	inner := &callgraph.FunctionDecl{ID: callgraph.FunctionID{Name: "inner"}, StartLine: 2, StartCol: 45, EndLine: 2, EndCol: 55}
	later := &callgraph.FunctionDecl{ID: callgraph.FunctionID{Name: "later"}, StartLine: 4, StartCol: 3, EndLine: 4, EndCol: 20}
	noCols := &callgraph.FunctionDecl{ID: callgraph.FunctionID{Name: "noCols"}, StartLine: 7, EndLine: 9}
	idx := &functionFileIndex{byFile: map[string][]*callgraph.FunctionDecl{"f": {outer, arrow, inner, later, noCols}}}

	for _, tc := range []struct {
		name      string
		line, col int
		want      *callgraph.FunctionDecl
	}{
		{"before the arrow on its line", 2, 3, outer},
		{"inside the arrow", 2, 41, arrow},
		{"inside the nested function", 2, 46, inner},
		{"at the arrow's exclusive end", 2, 60, outer},
		{"no column keeps the innermost by line", 2, 0, inner},
		{"function without columns is judged by line", 8, 1, noCols},
		{"callback on a later line", 3, 5, outer},
		{"outside every span", 6, 1, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := idx.containing("f", tc.line, tc.col); got != tc.want {
				t.Fatalf("containing(%d, %d) = %v, want %v", tc.line, tc.col, got, tc.want)
			}
		})
	}
}

const javaModifierStart = `import javax.crypto.Cipher;

public class K {
    public byte[] encrypt(byte[] in) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        return c.doFinal(in);
    }
}
`

// TestColumnAwareContainment_MatchStartingAtModifier pins that a finding whose
// match begins at the `public` modifier of a method, left of the return type,
// keeps its containing function and its occurrence key. The span of a Java
// method starts at its first modifier on the signature line, not at the type.
func TestColumnAwareContainment_MatchStartingAtModifier(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "K.java"), []byte(javaModifierStart), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilderForEcosystem("java", callgraph.NewParserForEcosystem("java")).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "ladder"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	signature := "    public byte[] encrypt(byte[] in) throws Exception {"
	report := &entities.InterimReport{
		Tool: entities.ToolInfo{Name: "crypto-finder", Version: "test"},
		Findings: []entities.Finding{{
			FilePath: "K.java", Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 4, EndLine: 6, StartCol: 5, EndCol: 6, Match: signature,
				Rules:    []entities.RuleInfo{{ID: "test.aes.cbc"}},
				Metadata: map[string]string{"api": "javax.crypto.Cipher.getInstance"},
			}},
		}},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)
	result := &engine.DepScanResult{Report: report, CallGraph: graph, ProjectRoot: dir, Ecosystem: "java"}
	live := buildCallGraphExportV2(result)
	if len(live.FindingGraphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(live.FindingGraphs))
	}
	if got := live.FindingGraphs[0].UnresolvedReason; got == "no_containing_function" {
		t.Fatalf("unresolved_reason = %q, want the method that holds the match", got)
	}
	// Measured on origin/main, which resolves containment by line.
	const wantKey = "v1:94515a0dd9bf1b59"
	if got := report.Findings[0].CryptographicAssets[0].OccurrenceKey; got != wantKey {
		t.Fatalf("occurrence_key = %q, want %q", got, wantKey)
	}
}
