// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/oid"
	"github.com/scanoss/crypto-finder/internal/output"
)

const javaSignatureRules = `rules:
  - id: java.sig.sha256ecdsa
    message: SHA256withECDSA
    severity: INFO
    pattern: Signature.getInstance("SHA256withECDSA")
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: SHA256withECDSA
        operation: sign
        parameterCondition: param[0]==SHA256withECDSA
        api: java.security.Signature.getInstance
`

// runtimeSourceCase is a generic anchor at the line of file that holds match,
// and what the conditioned pass leaves of it.
type runtimeSourceCase struct {
	name, file, match string
	// wantRules are the per-value assets; wantSource the anchor's
	// algorithmSource, "" when the anchor is dropped or carries none.
	wantRules  []string
	wantAnchor bool
	wantSource string
}

func assertRuntimeSourceCase(t *testing.T, tt runtimeSourceCase, report *entities.InterimReport, anchorID string) {
	t.Helper()
	got, anchor := specializedRules(report, anchorID)
	if !slices.Equal(got, tt.wantRules) || anchor != tt.wantAnchor {
		t.Fatalf("specialized rules = %v, generic anchor = %v; want %v, %v", got, anchor, tt.wantRules, tt.wantAnchor)
	}
	for i := range report.Findings[0].CryptographicAssets {
		asset := &report.Findings[0].CryptographicAssets[i]
		source, ok := asset.Metadata[algorithmSourceMetadataKey]
		switch {
		case asset.Rules[0].ID != anchorID && ok:
			t.Fatalf("specialized %s carries algorithmSource %q", asset.Rules[0].ID, source)
		case asset.Rules[0].ID == anchorID && source != tt.wantSource:
			t.Fatalf("anchor algorithmSource = %q (set %v), want %q", source, ok, tt.wantSource)
		}
	}
}

func materializeRuntimeCase(t *testing.T, graph *callgraph.CallGraph, ecosystem, dir, rules string, tt runtimeSourceCase, anchorID, language, api string) *entities.InterimReport {
	t.Helper()
	report := namedValueAnchor(t, dir, tt.file, tt.match, anchorID, language, api)
	MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: ecosystem, ProjectRoot: dir}, []string{rules})
	return report
}

var javaRuntimeSourceTree = map[string]string{
	"app/cfg/Keys.java": "package app.cfg;\npublic final class Keys {\n    public static final String PROP = \"sig.alg\";\n}\n",
	"app/Signer.java": `package app;
import java.security.Signature;
public class Signer {
    public Signature sign(String alg) throws Exception {
        Signature.getInstance(alg );
        return Signature.getInstance(alg);
    }
}
`,
	"app/Main.java": `package app;
public class Main {
    public static void main(String[] args) throws Exception {
        new Signer().sign("SHA256withECDSA");
        new Signer().sign(System.getenv("SIG_ALG"));
        new Signer().sign(args[1]);
    }
}
`,
	"app/Direct.java": `package app;
import java.security.Signature;
import java.util.Properties;
import app.cfg.Keys;
public class Direct {
    private final Properties props = new Properties();
    void env() throws Exception {
        Signature.getInstance(System.getenv("SIG_ALG"));
    }
    void local() throws Exception {
        String alg = System.getenv("LOCAL_ALG");
        Signature.getInstance(alg);
    }
    void withDefault() throws Exception {
        Signature.getInstance(System.getProperty("sig.default", "SHA256withECDSA"));
    }
    void config() throws Exception {
        Signature.getInstance(props.getProperty(Keys.PROP));
    }
    void unknownName(String name) throws Exception {
        Signature.getInstance(System.getenv(name));
    }
    void literal() throws Exception {
        Signature.getInstance("SHA256withECDSA");
    }
}
`,
}

// A Java signature whose algorithm is read from the environment, a property
// or a program argument keeps its generic anchor, which names that input; a
// caller passing a literal still specializes.
func TestMaterializeConditionedFindings_JavaRuntimeSources(t *testing.T) {
	t.Parallel()

	tests := []runtimeSourceCase{
		{"environment variable at the call", "app/Direct.java", `Signature.getInstance(System.getenv("SIG_ALG"))`, nil, true, "env:SIG_ALG"},
		{"local bound to the environment", "app/Direct.java", "Signature.getInstance(alg)", nil, true, "env:LOCAL_ALG"},
		{"a property default is not the algorithm", "app/Direct.java", `Signature.getInstance(System.getProperty("sig.default", "SHA256withECDSA"))`, nil, true, "property:sig.default"},
		{"properties key from a constant of another file", "app/Direct.java", "Signature.getInstance(props.getProperty(Keys.PROP))", nil, true, "property:sig.alg"},
		{"unknown name reports no source", "app/Direct.java", "Signature.getInstance(System.getenv(name))", nil, true, ""},
		{"literal resolves", "app/Direct.java", `Signature.getInstance("SHA256withECDSA")`, []string{"java.sig.sha256ecdsa"}, false, ""},
		{"parameter fed by a literal, the environment and argv", "app/Signer.java", "Signature.getInstance(alg)", []string{"java.sig.sha256ecdsa"}, true, "argv:1,env:SIG_ALG"},
	}
	dir := writeSourceTree(t, javaRuntimeSourceTree)
	graph, err := callgraph.NewBuilderForEcosystem("java", callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	rules := writeConditionedRules(t, javaSignatureRules)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := materializeRuntimeCase(t, graph, "java", dir, rules, tt, "java.sig.dynamic", "java", "java.security.Signature.getInstance")
			assertRuntimeSourceCase(t, tt, report, "java.sig.dynamic")
		})
	}
}

// An anchor whose own rule names an algorithm is resolved: its runtime
// routes add no algorithmSource.
func TestMaterializeConditionedFindings_NamedAnchorGetsNoRuntimeSource(t *testing.T) {
	t.Parallel()

	dir := writeSourceTree(t, javaRuntimeSourceTree)
	graph, err := callgraph.NewBuilderForEcosystem("java", callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	report := namedValueAnchor(t, dir, "app/Direct.java", `Signature.getInstance(System.getenv("SIG_ALG"))`, "java.sig.ecdsa", "java", "java.security.Signature.getInstance")
	report.Findings[0].CryptographicAssets[0].Metadata["algorithmFamily"] = "ECDSA"
	MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: "java", ProjectRoot: dir}, []string{writeConditionedRules(t, javaSignatureRules)})
	for i := range report.Findings[0].CryptographicAssets {
		asset := &report.Findings[0].CryptographicAssets[i]
		if source, ok := asset.Metadata[algorithmSourceMetadataKey]; ok {
			t.Fatalf("%s carries algorithmSource %q", asset.Rules[0].ID, source)
		}
	}
}

// A Python digest whose algorithm comes from os.environ, os.getenv or
// sys.argv names that input; a literal default of os.environ.get does not
// specialize.
func TestMaterializeConditionedFindings_PythonRuntimeSources(t *testing.T) {
	t.Parallel()

	tests := []runtimeSourceCase{
		{"environ subscript", "app/direct.py", `hashlib.new(os.environ["HASH_ALG"])`, nil, true, "env:HASH_ALG"},
		{"getenv default is not the algorithm", "app/direct.py", `hashlib.new(os.environ.get("HASH_ALG", "sha256"))`, nil, true, "env:HASH_ALG"},
		{"a variable named like the algorithm is not it", "app/direct.py", `hashlib.new(os.getenv("sha256"))`, nil, true, "env:sha256"},
		{"local bound to argv", "app/direct.py", "hashlib.new(alg)", nil, true, "argv:1"},
		{"helper fed by a literal and getenv from another module", "app/hasher.py", "hashlib.new(alg, data)", []string{"py.hash.sha256"}, true, "env:DIGEST"},
	}
	dir := writeSourceTree(t, map[string]string{
		"app/__init__.py": "",
		"app/cfg.py":      "DIGEST_KEY = \"DIGEST\"\n",
		"app/hasher.py":   "import hashlib\n\ndef digest(alg, data):\n    return hashlib.new(alg, data).hexdigest()\n",
		"app/direct.py": `import hashlib
import os
import sys

def environ_subscript():
    return hashlib.new(os.environ["HASH_ALG"])

def environ_get():
    return hashlib.new(os.environ.get("HASH_ALG", "sha256"))

def named_like_algorithm():
    return hashlib.new(os.getenv("sha256"))

def argv_local():
    alg = sys.argv[1]
    return hashlib.new(alg)
`,
		"app/main.py": `import os
from app.cfg import DIGEST_KEY
from app.hasher import digest

def fixed(data):
    return digest("sha256", data)

def configured(data):
    return digest(os.getenv(DIGEST_KEY), data)
`,
	})
	graph, err := callgraph.NewBuilderForEcosystem("python", callgraph.NewPythonParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	rules := writeConditionedRules(t, pythonDigestRules)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := materializeRuntimeCase(t, graph, "python", dir, rules, tt, "py.hash.dynamic", "python", "hashlib.new")
			assertRuntimeSourceCase(t, tt, report, "py.hash.dynamic")
		})
	}
}

// A JavaScript digest whose algorithm comes from process.env or process.argv
// names that input, at the call and through a helper another module calls.
func TestMaterializeConditionedFindings_NodeRuntimeSources(t *testing.T) {
	t.Parallel()

	tests := []runtimeSourceCase{
		{"env member", "src/direct.mjs", "crypto.createHash(process.env.HASH_ALG)", nil, true, "env:HASH_ALG"},
		{"env subscript with a constant key", "src/direct.mjs", "crypto.createHash(process.env[KEY])", nil, true, "env:FROM_KEY"},
		{"argv", "src/direct.mjs", "crypto.createHash(process.argv[2])", nil, true, "argv:2"},
		{"helper fed by a literal and the environment", "src/hasher.mjs", "crypto.createHash(alg)", []string{"js.hash.sha256"}, true, "env:DIGEST"},
		{"a local named process is not the global", "src/shadow.mjs", "crypto.createHash(process.env.HASH_ALG)", nil, true, ""},
	}
	dir := writeSourceTree(t, map[string]string{
		"src/direct.mjs": `import crypto from "crypto";
const KEY = "FROM_KEY";
export const a = () => crypto.createHash(process.env.HASH_ALG);
export const b = () => crypto.createHash(process.env[KEY]);
export const c = () => crypto.createHash(process.argv[2]);
`,
		"src/hasher.mjs": "import crypto from \"crypto\";\nexport function hash(alg, data) { return crypto.createHash(alg).update(data).digest(); }\n",
		"src/main.mjs":   "import { hash } from \"./hasher.mjs\";\nexport const fixed = (d) => hash(\"sha256\", d);\nexport const configured = (d) => hash(process.env.DIGEST, d);\n",
		"src/shadow.mjs": "import crypto from \"crypto\";\nexport function run(process) { return crypto.createHash(process.env.HASH_ALG); }\n",
	})
	graph, err := callgraph.NewBuilderForEcosystem("node", callgraph.NewNodeParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	rules := writeConditionedRules(t, nodeDigestRules)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := materializeRuntimeCase(t, graph, "node", dir, rules, tt, "js.hash.dynamic", "javascript", "crypto.createHash")
			assertRuntimeSourceCase(t, tt, report, "js.hash.dynamic")
		})
	}
}

// The interim report written for a scan carries algorithmSource in the
// anchor's metadata, and still matches the interim report schema.
func TestRuntimeSourceReportMatchesSchema(t *testing.T) {
	t.Parallel()

	dir := writeSourceTree(t, javaRuntimeSourceTree)
	graph, err := callgraph.NewBuilderForEcosystem("java", callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	tt := runtimeSourceCase{file: "app/Signer.java", match: "Signature.getInstance(alg)"}
	report := materializeRuntimeCase(t, graph, "java", dir, writeConditionedRules(t, javaSignatureRules), tt, "java.sig.dynamic", "java", "java.security.Signature.getInstance")
	report.Version = entities.InterimFormatVersion
	report.Tool.Name, report.Tool.Version = "crypto-finder", "test"
	prepared, err := oid.NewDefaultResolver().PrepareReport(report)
	if err != nil {
		t.Fatalf("prepare report: %v", err)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := output.NewJSONWriter().WriteResolved(prepared.ReportClone(), path); err != nil {
		t.Fatalf("write report: %v", err)
	}
	assertJSONMatchesSchema(t, filepath.Join("..", "..", "schemas", "interim-report-schema.json"), path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var written struct {
		Findings []struct {
			Assets []struct {
				Metadata map[string]string `json:"metadata"`
			} `json:"cryptographic_assets"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, asset := range written.Findings[0].Assets {
		if source := asset.Metadata["algorithmSource"]; source != "" {
			sources = append(sources, source)
		}
	}
	if !slices.Equal(sources, []string{"argv:1,env:SIG_ALG"}) {
		t.Fatalf("written algorithmSource values = %v, want [argv:1,env:SIG_ALG]", sources)
	}
}

// Two anchors fed by the same parameter both name its inputs: the second
// walk is served from the first one's cache.
func TestMaterializeConditionedFindings_RuntimeSourcesSurviveTheWalkCache(t *testing.T) {
	t.Parallel()

	dir := writeSourceTree(t, javaRuntimeSourceTree)
	graph, err := callgraph.NewBuilderForEcosystem("java", callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	report := namedValueAnchor(t, dir, "app/Signer.java", "Signature.getInstance(alg )", "java.sig.dynamic", "java", "java.security.Signature.getInstance")
	second := namedValueAnchor(t, dir, "app/Signer.java", "Signature.getInstance(alg)", "java.sig.dynamic", "java", "java.security.Signature.getInstance")
	report.Findings[0].CryptographicAssets = append(report.Findings[0].CryptographicAssets, second.Findings[0].CryptographicAssets...)
	MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: "java", ProjectRoot: dir}, []string{writeConditionedRules(t, javaSignatureRules)})
	var sources []string
	for i := range report.Findings[0].CryptographicAssets {
		asset := &report.Findings[0].CryptographicAssets[i]
		if asset.Rules[0].ID == "java.sig.dynamic" {
			sources = append(sources, asset.Metadata[algorithmSourceMetadataKey])
		}
	}
	if !slices.Equal(sources, []string{"argv:1,env:SIG_ALG", "argv:1,env:SIG_ALG"}) {
		t.Fatalf("anchor algorithmSource values = %q, want both argv:1,env:SIG_ALG", sources)
	}
}
