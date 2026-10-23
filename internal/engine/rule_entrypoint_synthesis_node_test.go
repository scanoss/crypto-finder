// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// writeNodeRules writes one rule per api, each carrying its own operation.
func writeNodeRules(t *testing.T, apis map[string]string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("rules:\n")
	for api, op := range apis {
		b.WriteString("  - id: test." + op + "\n" +
			"    metadata:\n" +
			"      crypto:\n" +
			"        assetType: algorithm\n" +
			"        algorithmPrimitive: signature\n" +
			"        algorithmName: ECDSA\n" +
			"        operation: " + op + "\n" +
			"        api: \"" + api + "\"\n")
	}
	p := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeNodeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func syntheticAssets(report *entities.InterimReport) map[string]*entities.CryptographicAsset {
	out := make(map[string]*entities.CryptographicAsset)
	for i := range report.Findings {
		for j := range report.Findings[i].CryptographicAssets {
			a := &report.Findings[i].CryptographicAssets[j]
			if isSyntheticEntryPointAsset(a) {
				out[report.Findings[i].FilePath+" "+a.Metadata["api"]] = a
			}
		}
	}
	return out
}

// A Node library exports a curve built by a factory: each api is anchored where
// the factory defines it, once, from one build, each with its own identity.
func TestSynthesizeNodeFactoryExport(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNodeFiles(t, root, map[string]string{
		"package.json": `{"name": "@acme/curves", "exports": {"./ec": {"types": "./ec.d.ts", "import": "./esm/ec.js", "require": "./ec.js"}}}`,
		"esm/ec.js":    "import { make } from './utils.js';\nexport const ec = make('secp256k1');\n",
		"esm/utils.js": "export function make(name) {\n  return { sign(m, k) {}, verify(s, m, p) {} };\n}\n",
		"ec.js":        "\"use strict\";\nexports.ec = void 0;\nexports.ec = (0, utils_1.make)('secp256k1');\n",
		"src/ec.ts":    "export const ec = make('secp256k1');\n",
	})
	rules := writeNodeRules(t, map[string]string{
		"@acme/curves/ec.ec.sign":   "sign",
		"@acme/curves/ec.ec.verify": "verify",
	})
	result := &DepScanResult{
		Report:      &entities.InterimReport{},
		CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem:   ecosystemNode,
		ProjectRoot: root,
	}

	if got := SynthesizeRuleCryptoEntryPointsForResult(result, []string{rules}); got != 2 {
		t.Fatalf("synthesized = %d, want 2 (one per api, from the import build only)", got)
	}
	AssignFindingIDs(result.Report)

	assets := syntheticAssets(result.Report)
	sign, verify := assets["esm/utils.js @acme/curves/ec.ec.sign"], assets["esm/utils.js @acme/curves/ec.ec.verify"]
	if sign == nil || verify == nil {
		t.Fatalf("assets = %v, want sign and verify where the factory defines them, esm/utils.js", assets)
	}
	if sign.StartLine != 2 || sign.Metadata["operation"] != "sign" || verify.Metadata["operation"] != "verify" {
		t.Errorf("sign at line %d with %q, verify with %q", sign.StartLine, sign.Metadata["operation"], verify.Metadata["operation"])
	}
	if sign.FindingID == verify.FindingID {
		t.Errorf("sign and verify share finding id %s", sign.FindingID)
	}
	if lang := result.Report.Findings[0].Language; lang != "javascript" {
		t.Errorf("language = %q, want javascript", lang)
	}
}

// A rule covers every release; an api whose member this release does not have
// is not surfaced even though its export exists.
func TestSynthesizeNodeSkipsMembersTheReleaseLacks(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNodeFiles(t, root, map[string]string{
		"package.json": `{"name": "@acme/curves", "exports": {"./ec": "./ec.js"}}`,
		"ec.js":        "export const ec = make();\nfunction make() { return { sign() {} }; }\n",
	})
	result := &DepScanResult{
		Report:      &entities.InterimReport{},
		CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem:   ecosystemNode,
		ProjectRoot: root,
	}
	rules := writeNodeRules(t, map[string]string{
		"@acme/curves/ec.ec.sign":         "sign",
		"@acme/curves/ec.ec.utils.keygen": "keygen",
	})

	if got := SynthesizeRuleCryptoEntryPointsForResult(result, []string{rules}); got != 1 {
		t.Fatalf("synthesized = %d, want 1 (sign only)", got)
	}
	if a := syntheticAssets(result.Report)["ec.js @acme/curves/ec.ec.sign"]; a == nil {
		t.Errorf("assets = %v, want only ec.sign", syntheticAssets(result.Report))
	}
}

// A member counts only if the export has it: not another export's member, a
// comment, a type declaration or a test.
func TestSynthesizeNodeMemberMustBelongToTheExport(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNodeFiles(t, root, map[string]string{
		"package.json":    `{"name": "acme", "main": "index.js"}`,
		"index.js":        "// pairing-friendly curve\nexports.ec = make();\nfunction make(){ return { sign(){} }; }\nexports.other = { verify(){} };\nexports.bn = weierstrass();\n",
		"index.d.ts":      "export declare const ec: { sign(): void; keygen(): void };\n",
		"test/ec.test.js": "ec.recover();\n",
	})
	result := &DepScanResult{
		Report:      &entities.InterimReport{},
		CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem:   ecosystemNode,
		ProjectRoot: root,
	}
	rules := writeNodeRules(t, map[string]string{
		"acme.ec.sign": "sign", "acme.ec.verify": "verify", "acme.ec.keygen": "keygen",
		"acme.ec.recover": "other", "acme.bn.pairing": "other",
	})

	if got := SynthesizeRuleCryptoEntryPointsForResult(result, []string{rules}); got != 1 {
		t.Fatalf("synthesized = %d (%v), want acme.ec.sign only", got, syntheticAssets(result.Report))
	}
}

// A package that re-exports its modules wholesale surfaces each api in the
// module that defines it; another package's re-export is not followed.
func TestSynthesizeNodeFollowsStarReExports(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNodeFiles(t, root, map[string]string{
		"package.json":      `{"name": "acme", "main": "dist/index.js"}`,
		"dist/index.js":     "tslib_1.__exportStar(require(\"./signature\"), exports);\n__exportStar(require(\"other\"), exports);\n",
		"dist/signature.js": "function ecsign() {}\nexports.ecsign = ecsign;\n",
	})
	result := &DepScanResult{
		Report:      &entities.InterimReport{},
		CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem:   ecosystemNode,
		ProjectRoot: root,
	}

	if got := SynthesizeRuleCryptoEntryPointsForResult(result, []string{writeNodeRules(t, map[string]string{"acme.ecsign": "sign"})}); got != 1 {
		t.Fatalf("synthesized = %d, want 1", got)
	}
	if a := syntheticAssets(result.Report)["dist/signature.js acme.ecsign"]; a == nil || a.StartLine != 1 {
		t.Errorf("assets = %v, want acme.ecsign at its definition, dist/signature.js:1", syntheticAssets(result.Report))
	}
}

// An index that re-exports many modules reaches all of them; the bound is on
// the depth of the re-export chain, not on how many modules one index lists.
func TestSynthesizeNodeFollowsEveryStarOfAnIndex(t *testing.T) {
	t.Parallel()

	files := map[string]string{"package.json": `{"name": "acme", "main": "index.js"}`}
	var index strings.Builder
	for i := 0; i < 12; i++ {
		name := fmt.Sprintf("m%d", i)
		index.WriteString("export * from './" + name + ".js';\n")
		files[name+".js"] = "export const " + name + " = 1;\n"
	}
	files["index.js"] = index.String()
	files["m11.js"] = "export function sign() {}\n"
	root := t.TempDir()
	writeNodeFiles(t, root, files)
	result := &DepScanResult{
		Report:      &entities.InterimReport{},
		CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem:   ecosystemNode,
		ProjectRoot: root,
	}

	if got := SynthesizeRuleCryptoEntryPointsForResult(result, []string{writeNodeRules(t, map[string]string{"acme.sign": "sign"})}); got != 1 {
		t.Fatalf("synthesized = %d, want 1 (sign is re-exported by the 12th star)", got)
	}
}

// A module re-exported under a name surfaces its apis under that name, at the
// function that defines them.
func TestSynthesizeNodeFollowsNamespaceReExports(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNodeFiles(t, root, map[string]string{
		"package.json":       `{"name": "acme", "exports": {".": {"node": {"import": "./main.js", "require": "./build/main.cjs"}}}}`,
		"main.js":            "export * as plonk from \"./src/plonk.js\";\n",
		"src/plonk.js":       "export { default as prove } from \"./plonk_prove.js\";\n",
		"src/plonk_prove.js": "export default async function prove() {}\n",
	})
	result := &DepScanResult{
		Report:      &entities.InterimReport{},
		CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem:   ecosystemNode,
		ProjectRoot: root,
	}

	if got := SynthesizeRuleCryptoEntryPointsForResult(result, []string{writeNodeRules(t, map[string]string{"acme.plonk.prove": "sign"})}); got != 1 {
		t.Fatalf("synthesized = %d, want 1", got)
	}
	if a := syntheticAssets(result.Report)["src/plonk_prove.js acme.plonk.prove"]; a == nil || a.StartLine != 1 {
		t.Errorf("assets = %v, want acme.plonk.prove where it is defined, src/plonk_prove.js:1", syntheticAssets(result.Report))
	}
}

// A package that exports the result of calling its factory, picking a build in
// a try, surfaces the methods the factory returns.
func TestSynthesizeNodeFactoryPackage(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNodeFiles(t, root, map[string]string{
		"package.json": `{"name": "acme", "main": "./index.js"}`,
		"index.js":     "try {\n  module.exports = require('./bindings')\n} catch (err) {\n  module.exports = require('./fallback')\n}\n",
		"bindings.js":  "module.exports = require('./lib')(require('./native'))\n",
		"fallback.js":  "module.exports = require('./lib')(require('./lib/js'))\n",
		"lib/index.js": "module.exports = (impl) => {\n  return {\n    ecdsaSign (msg, key) {},\n    ecdh: (pub, key) => {},\n  }\n}\n",
	})
	result := &DepScanResult{
		Report:      &entities.InterimReport{},
		CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem:   ecosystemNode,
		ProjectRoot: root,
	}
	rules := writeNodeRules(t, map[string]string{"acme.ecdsaSign": "sign", "acme.ecdh": "keyagree"})

	if got := SynthesizeRuleCryptoEntryPointsForResult(result, []string{rules}); got != 2 {
		t.Fatalf("synthesized = %d, want 2", got)
	}
	if a := syntheticAssets(result.Report)["lib/index.js acme.ecdsaSign"]; a == nil || a.StartLine != 3 {
		t.Errorf("assets = %v, want acme.ecdsaSign at lib/index.js:3", syntheticAssets(result.Report))
	}
}

// A module that exports its hash function as itself is the api of its specifier.
func TestSynthesizeNodeModuleExportedAsItself(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNodeFiles(t, root, map[string]string{
		"package.json":        `{"name": "hash.js", "main": "lib/hash.js"}`,
		"lib/hash.js":         "exports.sha256 = require('./hash/sha/256');\n",
		"lib/hash/sha/256.js": "function SHA256() {}\nmodule.exports = SHA256;\n",
	})
	result := &DepScanResult{
		Report:      &entities.InterimReport{},
		CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem:   ecosystemNode,
		ProjectRoot: root,
	}

	if got := SynthesizeRuleCryptoEntryPointsForResult(result, []string{writeNodeRules(t, map[string]string{"hash.js/lib/hash/sha/256": "digest"})}); got != 1 {
		t.Fatalf("synthesized = %d, want 1", got)
	}
	if a := syntheticAssets(result.Report)["lib/hash/sha/256.js hash.js/lib/hash/sha/256"]; a == nil || a.StartLine != 1 {
		t.Errorf("assets = %v, want the module api at its function, lib/hash/sha/256.js:1", syntheticAssets(result.Report))
	}
}

// A constructor api resolves to the exported class, where it is defined.
func TestSynthesizeNodeExportedClassConstructor(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNodeFiles(t, root, map[string]string{
		"package.json": `{"name": "acme", "main": "index.js"}`,
		"index.js":     "module.exports = {\n  CryptographyKey: require('./lib/key'),\n};\n",
		"lib/key.js":   "module.exports = class CryptographyKey {};\n",
	})
	result := &DepScanResult{
		Report:      &entities.InterimReport{},
		CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem:   ecosystemNode,
		ProjectRoot: root,
	}

	if got := SynthesizeRuleCryptoEntryPointsForResult(result, []string{writeNodeRules(t, map[string]string{"acme.CryptographyKey.<init>": "keygen"})}); got != 1 {
		t.Fatalf("synthesized = %d, want 1", got)
	}
	if a := syntheticAssets(result.Report)["lib/key.js acme.CryptographyKey.<init>"]; a == nil || a.StartLine != 1 {
		t.Errorf("assets = %v, want the class at lib/key.js:1", syntheticAssets(result.Report))
	}
}

// An api is anchored at the function that defines it: its own assignment
// through an exports alias, a class's constructor, and the call graph's
// declaration in the TypeScript source a built file comes from.
func TestSynthesizeNodeAnchorsAtTheDefinition(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNodeFiles(t, root, map[string]string{
		"package.json":        `{"name": "acme", "exports": {".": "./index.js", "./ciphers": "./dist/src/ciphers.js"}}`,
		"index.js":            "var nacl = exports;\nnacl.box = function(){};\nnacl.box.before = function(){};\nexports.Key = class Key {\n  constructor(k) {}\n};\nnacl.box.after = nacl.box.before;\n",
		"dist/src/ciphers.js": "export function create() {}\n",
		"src/ciphers.ts":      "// header\nexport function create(): void {}\n",
	})
	src := filepath.Join(root, "src", "ciphers.ts")
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		"create": {ID: callgraph.FunctionID{Package: "acme/src/ciphers", Name: "create"}, FilePath: src, StartLine: 2, EndLine: 2},
	}}
	result := &DepScanResult{Report: &entities.InterimReport{}, CallGraph: graph, Ecosystem: ecosystemNode, ProjectRoot: root}
	rules := writeNodeRules(t, map[string]string{"acme.box.before": "keygen", "acme.box.after": "keygen", "acme.Key.<init>": "keygen", "acme/ciphers.create": "encrypt"})

	SynthesizeRuleCryptoEntryPointsForResult(result, []string{rules})
	assets := syntheticAssets(result.Report)
	for key, line := range map[string]int{"index.js acme.box.before": 3, "index.js acme.box.after": 3, "index.js acme.Key.<init>": 5, "src/ciphers.ts acme/ciphers.create": 2} {
		if a := assets[key]; a == nil || a.StartLine != line {
			t.Errorf("%s: want line %d; assets = %v", key, line, assets)
		}
	}
}

// A build's export that aliases another function is anchored at that function
// in the TypeScript source the call graph indexes.
func TestSynthesizeNodeAnchorsAliasInTypeScriptSource(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNodeFiles(t, root, map[string]string{
		"package.json":        `{"name": "acme", "exports": {".": "./dist/esm/account.js"}}`,
		"dist/esm/account.js": "export const pubToAddress = function (pubKey) {};\nexport const publicToAddress = pubToAddress;\n",
		"src/account.ts":      "// header\nexport const pubToAddress = function (pubKey: Uint8Array) {};\nexport const publicToAddress = pubToAddress;\n",
	})
	src := filepath.Join(root, "src", "account.ts")
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		"pubToAddress": {ID: callgraph.FunctionID{Package: "acme/src/account", Name: "pubToAddress"}, FilePath: src, StartLine: 2, EndLine: 2},
	}}
	result := &DepScanResult{Report: &entities.InterimReport{}, CallGraph: graph, Ecosystem: ecosystemNode, ProjectRoot: root}

	SynthesizeRuleCryptoEntryPointsForResult(result, []string{writeNodeRules(t, map[string]string{"acme.publicToAddress": "other"})})
	if a := syntheticAssets(result.Report)["src/account.ts acme.publicToAddress"]; a == nil || a.StartLine != 2 {
		t.Errorf("assets = %v, want acme.publicToAddress at src/account.ts:2", syntheticAssets(result.Report))
	}
}

// A constructor api names a class or constructor function, not a constant.
func TestSynthesizeNodeConstructorOnlyOnClasses(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNodeFiles(t, root, map[string]string{
		"package.json": `{"name": "acme", "main": "index.js"}`,
		"index.js":     "exports.VERSION = '1.0';\nexports.Key = class Key {};\nfunction Signer() {}\nexports.Signer = Signer;\n",
	})
	result := &DepScanResult{
		Report:      &entities.InterimReport{},
		CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem:   ecosystemNode,
		ProjectRoot: root,
	}
	rules := writeNodeRules(t, map[string]string{"acme.VERSION.<init>": "keygen", "acme.Key.<init>": "keygen", "acme.Signer.<init>": "sign"})

	SynthesizeRuleCryptoEntryPointsForResult(result, []string{rules})
	got := map[string]bool{}
	for _, a := range syntheticAssets(result.Report) {
		got[a.Metadata["api"]] = true
	}
	if !got["acme.Key.<init>"] || !got["acme.Signer.<init>"] || got["acme.VERSION.<init>"] {
		t.Errorf("surfaced %v, want the Key and Signer constructors only", got)
	}
}

// Specifiers resolve as Node resolves them: "./*" reaches subdirectories, a
// subpath mapped to null is not importable, the package root is its main, an
// ESM wrapper falls through to the build it wraps, and deep imports use real paths.
func TestSynthesizeNodeResolvesSpecifiersLikeNode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		files   map[string]string
		surface []string
		absent  []string
	}{
		{"nested pattern and null", map[string]string{
			"package.json":       `{"name": "acme", "exports": {"./*": "./dist/*.js", "./internal/*": null}}`,
			"dist/a/b.js":        "export function sign() {}\n",
			"dist/internal/x.js": "export function verify() {}\n",
		}, []string{"acme/a/b.sign"}, []string{"acme/internal/x.verify"}},
		{"main over other index files", map[string]string{
			"package.json":  `{"name": "acme", "main": "src/main.js"}`,
			"dist/index.js": "exports.sign = function(){};\n",
			"src/main.js":   "exports.verify = function(){};\n",
		}, []string{"acme.verify"}, []string{"acme.sign"}},
		{"esm wrapper over cjs", map[string]string{
			"package.json": `{"name": "acme", "exports": {".": {"import": "./wrapper.mjs", "require": "./index.js"}}}`,
			"wrapper.mjs":  "import mod from './index.js';\nexport const { sign } = mod;\n",
			"index.js":     "exports.sign = function(){};\n",
		}, []string{"acme.sign"}, nil},
		{"deep import by real path", map[string]string{
			"package.json": `{"name": "acme.js", "main": "lib/index.js"}`,
			"lib/index.js": "exports.a = 1;\n",
			"lib/foo.js":   "exports.sign = function(){};\n",
		}, []string{"acme.js/lib/foo.sign"}, []string{"acme.js/foo.sign", "acme/lib/foo.sign"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeNodeFiles(t, root, tc.files)
			result := &DepScanResult{
				Report:      &entities.InterimReport{},
				CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
				Ecosystem:   ecosystemNode,
				ProjectRoot: root,
			}
			apis := map[string]string{}
			for _, a := range append(append([]string{}, tc.surface...), tc.absent...) {
				apis[a] = "sign"
			}
			SynthesizeRuleCryptoEntryPointsForResult(result, []string{writeNodeRules(t, apis)})
			got := map[string]bool{}
			for _, a := range syntheticAssets(result.Report) {
				got[a.Metadata["api"]] = true
			}
			for _, a := range tc.surface {
				if !got[a] {
					t.Errorf("%s not surfaced; got %v", a, got)
				}
			}
			for _, a := range tc.absent {
				if got[a] {
					t.Errorf("%s surfaced", a)
				}
			}
		})
	}
}

// Node resolves main without its extension and as a directory index, and
// falls back to index.js, not to the first index file of a build directory.
func TestNodeMainFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeNodeFiles(t, root, map[string]string{"bcrypt.js": "", "lib/index.js": "", "index.js": "", "dist/index.js": ""})
	for _, tc := range []struct{ main, want string }{
		{"bcrypt", "bcrypt.js"},
		{"./lib", "lib/index.js"},
		{"lib/index.js", "lib/index.js"},
		{"", "index.js"},
		{"missing.js", "index.js"},
	} {
		if got := nodeMainFile(root, tc.main); got != tc.want {
			t.Errorf("nodeMainFile(%q) = %q, want %q", tc.main, got, tc.want)
		}
	}
}

// An unscoped package without an exports map is importable by its main file.
func TestSynthesizeNodeMainExportWithoutExportsMap(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNodeFiles(t, root, map[string]string{
		"package.json": `{"name": "acme", "main": "lib/index.js"}`,
		"lib/index.js": "function sign() {}\nexports.sign = sign;\n",
	})
	result := &DepScanResult{
		Report:      &entities.InterimReport{},
		CallGraph:   &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}},
		Ecosystem:   ecosystemNode,
		ProjectRoot: root,
	}

	if got := SynthesizeRuleCryptoEntryPointsForResult(result, []string{writeNodeRules(t, map[string]string{"acme.sign": "sign"})}); got != 1 {
		t.Fatalf("synthesized = %d, want 1", got)
	}
	if a := syntheticAssets(result.Report)["lib/index.js acme.sign"]; a == nil || a.StartLine != 1 {
		t.Errorf("assets = %v, want acme.sign at its definition, lib/index.js:1", syntheticAssets(result.Report))
	}
}

// Ids are assigned more than once per scan; a second pass keeps them.
func TestAssignFindingIDsTwiceKeepsSharedLineIDs(t *testing.T) {
	t.Parallel()

	asset := func(api string) entities.CryptographicAsset {
		return entities.CryptographicAsset{
			StartLine: 2,
			Rules:     []entities.RuleInfo{{ID: SyntheticEntryPointRuleID}},
			Metadata:  map[string]string{"api": api},
		}
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath:            "ec.js",
		CryptographicAssets: []entities.CryptographicAsset{asset("acme.ec.sign"), asset("acme.ec.verify")},
	}}}

	AssignFindingIDs(report)
	first := []string{report.Findings[0].CryptographicAssets[0].FindingID, report.Findings[0].CryptographicAssets[1].FindingID}
	AssignFindingIDs(report)

	for i, a := range report.Findings[0].CryptographicAssets {
		if a.FindingID != first[i] || a.ConditionedValue != "api:"+a.Metadata["api"] {
			t.Errorf("%s: id %s -> %s, conditioned value %q", a.Metadata["api"], first[i], a.FindingID, a.ConditionedValue)
		}
	}
}

// Apis on their own lines, the Java and Python case, keep the id they always had.
func TestMarkSyntheticVariantsKeepsIDsOfAPIsOnTheirOwnLines(t *testing.T) {
	t.Parallel()

	asset := func(line int, api string) entities.CryptographicAsset {
		return entities.CryptographicAsset{
			StartLine: line,
			Rules:     []entities.RuleInfo{{ID: SyntheticEntryPointRuleID}},
			Metadata:  map[string]string{"api": api},
		}
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath:            "src/main/java/com/example/Builder.java",
		CryptographicAssets: []entities.CryptographicAsset{asset(10, "com.example.Builder.withBcrypt"), asset(20, "com.example.Builder.withScrypt")},
	}}}

	AssignFindingIDs(report)

	for _, a := range report.Findings[0].CryptographicAssets {
		if a.ConditionedValue != "" {
			t.Errorf("%s: conditioned value = %q, want none", a.Metadata["api"], a.ConditionedValue)
		}
		want := generateFindingID("src/main/java/com/example/Builder.java", a.StartLine, a.Rules, "")
		if a.FindingID != want {
			t.Errorf("%s: id = %s, want the unchanged %s", a.Metadata["api"], a.FindingID, want)
		}
	}
}
