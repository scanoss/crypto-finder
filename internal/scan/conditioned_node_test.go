// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"slices"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
)

const nodeDigestRules = `rules:
  - id: js.hash.sha256
    message: sha256
    severity: INFO
    pattern: crypto.createHash("sha256")
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: SHA-256
        operation: digest
        parameterCondition: param[0]==sha256
        api: crypto.createHash
  - id: js.hash.md5
    message: md5
    severity: INFO
    pattern: crypto.createHash("md5")
    metadata:
      crypto:
        assetType: algorithm
        algorithmName: MD5
        operation: digest
        parameterCondition: param[0]==md5
        api: crypto.createHash
`

// A JavaScript or TypeScript digest whose algorithm is an imported constant,
// an enum-like member, or a parameter of a helper its callers in other
// modules fill with one of those, specializes from the value; a value the
// parser cannot pin keeps the generic anchor.
func TestMaterializeConditionedFindings_NodeNamedValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, file, match string
		wantRules         []string
		wantAnchor        bool
	}{
		{"imported ESM constant", "src/direct.mjs", "crypto.createHash(ALG)", []string{"js.hash.sha256"}, false},
		{"frozen object member", "src/direct.mjs", "crypto.createHash(Alg.MD)", []string{"js.hash.md5"}, false},
		{"CommonJS constant", "src/legacy.cjs", "crypto.createHash(cfg.ALG)", []string{"js.hash.sha256"}, false},
		{"TypeScript enum member", "src/typed.ts", "crypto.createHash(Digest.MD)", []string{"js.hash.md5"}, false},
		{"helper fed by constant and enum members", "src/hasher.mjs", "crypto.createHash(alg)", []string{"js.hash.md5", "js.hash.sha256"}, false},
		// hash(...parts, "md5") fills alg from parts when it holds two items:
		// the literal after a spread is no caller's value.
		{"spread caller keeps the anchor", "src/spread.mjs", "crypto.createHash(alg)", []string{"js.hash.sha256"}, true},
		{"rebound local keeps the anchor", "src/rebound.mjs", "crypto.createHash(alg)", nil, true},
	}
	dir := writeSourceTree(t, map[string]string{
		"src/cfg.mjs": `export const ALG = "sha256";
export const Alg = Object.freeze({ SHA: "sha256", MD: "md5" });
export class Holder {
  constructor(alg) { this.alg = alg; }
  getAlg() { return this.alg; }
}
`,
		"src/cfg.cjs":    "module.exports = { ALG: \"sha256\" };\n",
		"src/digest.ts":  "export enum Digest { SHA = \"sha256\", MD = \"md5\" }\n",
		"src/direct.mjs": "import crypto from \"crypto\";\nimport { ALG, Alg, Holder } from \"./cfg.mjs\";\nexport const a = () => crypto.createHash(ALG);\nexport const b = () => crypto.createHash(Alg.MD);\n",
		"src/legacy.cjs": "const crypto = require(\"crypto\");\nconst cfg = require(\"./cfg.cjs\");\nexports.run = function () { return crypto.createHash(cfg.ALG); };\n",
		"src/typed.ts":   "import * as crypto from \"crypto\";\nimport { Digest } from \"./digest\";\nexport function run(): void { crypto.createHash(Digest.MD); }\n",
		"src/hasher.mjs": "import crypto from \"crypto\";\nexport function hash(alg, data) { return crypto.createHash(alg).update(data).digest(); }\n",
		"src/main.mjs": `import { hash } from "./hasher.mjs";
import { ALG, Alg, Holder } from "./cfg.mjs";
import { Digest } from "./digest";
export function constant(d) { return hash(ALG, d); }
export function member(d) { return hash(Alg.MD, d); }
export function tsEnum(d) { return hash(Digest.MD, d); }
`,
		"src/spread.mjs":  "import crypto from \"crypto\";\nexport function hash(data, alg) { return crypto.createHash(alg).update(data).digest(); }\nexport function fixed(d) { return hash(d, \"sha256\"); }\nexport function spread(parts) { return hash(...parts, \"md5\"); }\n",
		"src/rebound.mjs": "import crypto from \"crypto\";\nexport function run(weak) {\n  let alg = \"sha256\";\n  if (weak) { alg = \"md5\"; }\n  return crypto.createHash(alg);\n}\n",
	})
	graph, err := callgraph.NewBuilderForEcosystem("node", callgraph.NewNodeParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	rules := writeConditionedRules(t, nodeDigestRules)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := namedValueAnchor(t, dir, tt.file, tt.match, "js.hash.dynamic", "javascript", "crypto.createHash")
			MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: graph, Ecosystem: "node", ProjectRoot: dir}, []string{rules})
			got, anchor := specializedRules(report, "js.hash.dynamic")
			if !slices.Equal(got, tt.wantRules) || anchor != tt.wantAnchor {
				t.Fatalf("specialized rules = %v, generic anchor = %v; want %v, %v", got, anchor, tt.wantRules, tt.wantAnchor)
			}
		})
	}
}
