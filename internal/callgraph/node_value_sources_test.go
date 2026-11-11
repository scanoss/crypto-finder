// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseInlineNodeProject(t *testing.T, files map[string]string) *CallGraph {
	t.Helper()
	dir := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := NewBuilderForEcosystem("node", NewNodeParser()).BuildFromDirectories([]PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

// nodeResolvedArgument follows the argument at index of the call to method
// inside function down its one-source chain: the literal it reaches, the
// parameter it names as "param <name> <index>", or "" when it has none.
func nodeResolvedArgument(t *testing.T, graph *CallGraph, file, function, method string, index int) string {
	t.Helper()
	for _, fn := range graph.Functions {
		if fn.ID.Name != function || !strings.HasSuffix(filepath.ToSlash(fn.FilePath), "/"+file) {
			continue
		}
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if call.Callee.Name != method {
				continue
			}
			if index >= len(call.ArgumentSources) {
				t.Fatalf("%s call in %s has %d argument sources for %d arguments", method, function, len(call.ArgumentSources), len(call.Arguments))
			}
			return describeNodeSourceChain(call.ArgumentSources[index])
		}
		t.Fatalf("%s has no %s call", function, method)
	}
	t.Fatalf("function %s not found in %s", function, file)
	return ""
}

func describeNodeSourceChain(sources []SourceNode) string {
	for len(sources) == 1 {
		switch node := sources[0]; node.Type {
		case sourceNodeValue:
			return node.Value
		case sourceNodeParameter:
			return fmt.Sprintf("param %s %d", node.Name, node.ParameterIndex)
		}
		sources = sources[0].SourceNodes
	}
	return ""
}

var nodeValueProject = map[string]string{
	"src/cfg.mjs": `export const ALG = "sha256";
export const COPY = ALG;
export let LIVE = "md5";
const LOCAL = 'sha384';
export { LOCAL as RENAMED };
export const Alg = Object.freeze({ SHA: "sha256", MD: 'md5' });
export const Plain = { SHA: "sha512" };
export const Mutated = { SHA: "sha512" };
Mutated.SHA = "md5";
const Base = { SHA: "sha1" };
export const Spread = { ...Base, SHA: "sha1" };
export class Holder {
  constructor(alg) { this.alg = alg; }
  getAlg() { return this.alg; }
}
export class Mutable {
  constructor(alg) { this.alg = alg; }
  setAlg(alg) { this.alg = alg; }
  getAlg() { return this.alg; }
}
export class Private {
  #alg;
  constructor(alg) { this.#alg = alg; }
  getAlg() { return this.#alg; }
}
export class Computed {
  constructor(alg) { this.alg = alg; }
  getAlg() { return this.alg.toLowerCase(); }
}
export class Sub extends Holder {
  constructor(alg) { super(alg); this.alg = alg; }
  getAlg() { return this.alg; }
}
export class Assigned {
  constructor(alg) { this.alg = alg; Object.assign(this, defaults); }
  getAlg() { return this.alg; }
}
export class Patched {
  constructor(alg) { this.alg = alg; }
  getAlg() { return this.alg; }
}
Patched.prototype.getAlg = function () { return "md5"; };
export class Statics {
  constructor(alg) { this.alg = alg; }
  getAlg() { return this.alg; }
  static getAlg() { return "md5"; }
}
`,
	"src/cjs.cjs": `const ALG = "sha256";
const Alg = Object.freeze({ SHA: "sha384" });
module.exports = { ALG, Alg, DIRECT: "sha512" };
`,
	"src/each.cjs": `exports.ALG = "sha256";
exports.TWICE = "sha256";
exports.TWICE = "md5";
`,
	"src/main.mjs": `import crypto from "crypto";
import { ALG, ALG as ALIAS, COPY, LIVE, RENAMED, Alg, Plain, Mutated, Spread, Holder, Mutable, Private, Computed, Sub, Assigned, Patched, Statics } from "./cfg.mjs";
import * as cfg from "./cfg.mjs";
import { ALG as PKG } from "some-package";
const { ALG: CJS_ALG, Alg: CjsAlg, DIRECT } = require("./cjs.cjs");
const cjs = require("./cjs.cjs");
const each = require("./each.cjs");
const SAME = "sha256";
let rebound = "sha256";
rebound = "md5";
const Local = Object.freeze({ SHA: "sha256" });
const Escaped = { SHA: "sha256" };
mutate(Escaped);

export function literal() { return crypto.createHash("sha256"); }
export function template() { return crypto.createHash(` + "`sha256`" + `); }
export function substituted(x) { return crypto.createHash(` + "`sha${x}`" + `); }
export function sameFileConst() { return crypto.createHash(SAME); }
export function localConst() { const a = "sha256"; return crypto.createHash(a); }
export function reboundLet() { return crypto.createHash(rebound); }
export function shadowed() { const SAME = pick(); return crypto.createHash(SAME); }
export function parameter(data, alg) { return crypto.createHash(alg); }
export function reassignedParameter(alg) { alg = alg || "md5"; return crypto.createHash(alg); }
export function defaultParameter(alg = "md5") { return crypto.createHash(alg); }
export function destructured({ alg }) { return crypto.createHash(alg); }
export function restParameter(...algs) { return crypto.createHash(algs); }
export function closure(alg) { return () => crypto.createHash(alg); }
export function imported() { return crypto.createHash(ALG); }
export function aliased() { return crypto.createHash(ALIAS); }
export function chained() { return crypto.createHash(COPY); }
export function exportedLet() { return crypto.createHash(LIVE); }
export function renamed() { return crypto.createHash(RENAMED); }
export function namespace() { return crypto.createHash(cfg.ALG); }
export function frozenMember() { return crypto.createHash(Alg.SHA); }
export function namespaceMember() { return crypto.createHash(cfg.Alg.MD); }
export function plainMember() { return crypto.createHash(Plain.SHA); }
export function mutatedMember() { return crypto.createHash(Mutated.SHA); }
export function spreadMember() { return crypto.createHash(Spread.SHA); }
export function localFrozen() { return crypto.createHash(Local.SHA); }
export function escapedObject() { return crypto.createHash(Escaped.SHA); }
export function packageImport() { return crypto.createHash(PKG); }
export function cjsDestructured() { return crypto.createHash(CJS_ALG); }
export function cjsMember() { return crypto.createHash(cjs.ALG); }
export function cjsEnum() { return crypto.createHash(CjsAlg.SHA); }
export function cjsDirect() { return crypto.createHash(DIRECT); }
export function cjsExports() { return crypto.createHash(each.ALG); }
export function cjsTwice() { return crypto.createHash(each.TWICE); }
export function getter() { return crypto.createHash(new Holder("sha256").getAlg()); }
export function getterLocal() { const h = new Holder("sha256"); return crypto.createHash(h.getAlg()); }
export function getterImportedArg() { return crypto.createHash(new Holder(ALG).getAlg()); }
export function getterParameter(alg) { return crypto.createHash(new Holder(alg).getAlg()); }
export function getterMutable() { return crypto.createHash(new Mutable("sha256").getAlg()); }
export function getterPrivate() { return crypto.createHash(new Private("sha256").getAlg()); }
export function getterComputed() { return crypto.createHash(new Computed("sha256").getAlg()); }
export function getterWrittenLocal() { const h = new Holder("sha256"); h.alg = "md5"; return crypto.createHash(h.getAlg()); }
export function getterReboundLocal(weak) { let h = new Holder("sha256"); if (weak) { h = new Holder("md5"); } return crypto.createHash(h.getAlg()); }
export function getterSubclass() { return crypto.createHash(new Sub("sha256").getAlg()); }
export function getterAssigned() { return crypto.createHash(new Assigned("sha256").getAlg()); }
export function getterPatched() { return crypto.createHash(new Patched("sha256").getAlg()); }
export function getterStatic() { return crypto.createHash(new Statics("sha256").getAlg()); }
export function getterSpread(args) { return crypto.createHash(new Holder(...args).getAlg()); }
`,
	"src/more.js": `const crypto = require("crypto");
const { Alg } = require("./cjs.cjs");
Alg.SHA = "md5";

function importerMutates() { return crypto.createHash(Alg.SHA); }
function varBefore() { const r = crypto.createHash(v); var v = "sha256"; return r; }
function varAfter() { var v = "sha256"; return crypto.createHash(v); }
function varInBlock(c) { if (c) { var v = "sha256"; } return crypto.createHash(v); }
function argumentsAlias(alg) { arguments[0] = "md5"; return crypto.createHash(alg); }
function blockConst(c) { if (c) { const a = "md5"; } return crypto.createHash(a); }
function innerShadow(alg) { { const alg = "md5"; } return crypto.createHash(alg); }
`,
	"src/dynamic.js": `const crypto = require("crypto");
const ALG = "sha256";
eval("var ALG = 'md5'");
function dynamic() { return crypto.createHash(ALG); }
`,
	"src/merged.ts": `import { createHash } from "crypto";
enum Merged { SHA = "sha256" }
enum Merged { MD = "md5" }
export function merged(): void { createHash(Merged.SHA); }
`,
	"src/enums.ts": `export enum Alg { SHA = "sha256", MD = 'md5', BITS = 256, AUTO }
export const enum Fast { SHA = "sha384" }
enum Merged { SHA = "sha256" }
enum Merged { MD = "md5" }
export class Holder {
  constructor(private readonly unused: string, alg: string) { this.alg = alg; }
  alg: string;
  getAlg(): string { return this.alg; }
}
`,
	"src/use.ts": `import { createHash } from "crypto";
import { Alg, Fast, Holder } from "./enums";
enum Local { SHA = "sha512" }

export function tsEnum(): void { createHash(Alg.SHA); }
export function tsConstEnum(): void { createHash(Fast.SHA); }
export function tsNumeric(): void { createHash(Alg.BITS); }
export function tsAuto(): void { createHash(Alg.AUTO); }
export function tsLocal(): void { createHash(Local.SHA); }
export function tsGetter(): void { createHash(new Holder("x", "sha256").getAlg()); }
export function tsTyped(alg: string): void { createHash(alg); }
export function tsThisParam(this: Window, alg: string): void { createHash(alg); }
export function tsAsConst(): void { const a = "sha256" as const; createHash(a); }
`,
}

func TestNodeValueSources(t *testing.T) {
	t.Parallel()
	graph := parseInlineNodeProject(t, nodeValueProject)
	tests := []struct {
		file, function, method string
		index                  int
		want                   string
	}{
		{"main.mjs", "literal", "createHash", 0, `"sha256"`},
		{"main.mjs", "template", "createHash", 0, `"sha256"`},
		{"main.mjs", "substituted", "createHash", 0, ""},
		{"main.mjs", "sameFileConst", "createHash", 0, `"sha256"`},
		{"main.mjs", "localConst", "createHash", 0, `"sha256"`},
		{"main.mjs", "reboundLet", "createHash", 0, ""},
		{"main.mjs", "shadowed", "createHash", 0, ""},
		{"main.mjs", "parameter", "createHash", 0, "param alg 1"},
		{"main.mjs", "reassignedParameter", "createHash", 0, ""},
		{"main.mjs", "defaultParameter", "createHash", 0, ""},
		{"main.mjs", "destructured", "createHash", 0, ""},
		{"main.mjs", "restParameter", "createHash", 0, ""},
		{"main.mjs", "imported", "createHash", 0, `"sha256"`},
		{"main.mjs", "aliased", "createHash", 0, `"sha256"`},
		{"main.mjs", "chained", "createHash", 0, `"sha256"`},
		{"main.mjs", "exportedLet", "createHash", 0, ""},
		{"main.mjs", "renamed", "createHash", 0, `"sha384"`},
		{"main.mjs", "namespace", "createHash", 0, `"sha256"`},
		{"main.mjs", "frozenMember", "createHash", 0, `"sha256"`},
		{"main.mjs", "namespaceMember", "createHash", 0, `"md5"`},
		{"main.mjs", "plainMember", "createHash", 0, `"sha512"`},
		{"main.mjs", "mutatedMember", "createHash", 0, ""},
		{"main.mjs", "spreadMember", "createHash", 0, ""},
		{"main.mjs", "localFrozen", "createHash", 0, `"sha256"`},
		{"main.mjs", "escapedObject", "createHash", 0, ""},
		{"main.mjs", "packageImport", "createHash", 0, ""},
		{"main.mjs", "cjsDestructured", "createHash", 0, `"sha256"`},
		{"main.mjs", "cjsMember", "createHash", 0, `"sha256"`},
		{"main.mjs", "cjsEnum", "createHash", 0, `"sha384"`},
		{"main.mjs", "cjsDirect", "createHash", 0, `"sha512"`},
		{"main.mjs", "cjsExports", "createHash", 0, `"sha256"`},
		{"main.mjs", "cjsTwice", "createHash", 0, ""},
		{"more.js", "importerMutates", "createHash", 0, ""},
		{"more.js", "varBefore", "createHash", 0, ""},
		{"more.js", "varAfter", "createHash", 0, `"sha256"`},
		{"more.js", "varInBlock", "createHash", 0, ""},
		{"more.js", "argumentsAlias", "createHash", 0, ""},
		{"more.js", "blockConst", "createHash", 0, ""},
		{"more.js", "innerShadow", "createHash", 0, "param alg 0"},
		{"dynamic.js", "dynamic", "createHash", 0, ""},
		{"merged.ts", "merged", "createHash", 0, ""},
		{"use.ts", "tsEnum", "createHash", 0, `"sha256"`},
		{"use.ts", "tsConstEnum", "createHash", 0, `"sha384"`},
		{"use.ts", "tsNumeric", "createHash", 0, ""},
		{"use.ts", "tsAuto", "createHash", 0, ""},
		{"use.ts", "tsLocal", "createHash", 0, `"sha512"`},
		{"use.ts", "tsTyped", "createHash", 0, "param alg 0"},
		{"use.ts", "tsThisParam", "createHash", 0, ""},
		{"use.ts", "tsAsConst", "createHash", 0, `"sha256"`},
	}
	for _, tt := range tests {
		t.Run(tt.function, func(t *testing.T) {
			if got := nodeResolvedArgument(t, graph, "src/"+tt.file, tt.function, tt.method, tt.index); got != tt.want {
				t.Fatalf("createHash argument resolves to %q, want %q", got, tt.want)
			}
		})
	}
}

// A closure reading a parameter of the function around it emits no
// PARAMETER: the callers the scan follows are those of the closure.
func TestNodeValueSources_ClosureParameter(t *testing.T) {
	t.Parallel()
	graph := parseInlineNodeProject(t, nodeValueProject)
	for _, fn := range graph.Functions {
		if !strings.HasPrefix(fn.ID.Name, "<anonymous>") || !strings.HasSuffix(filepath.ToSlash(fn.FilePath), "/src/main.mjs") {
			continue
		}
		for _, call := range fn.Calls {
			if call.Callee.Name == "createHash" {
				if len(call.ArgumentSources) != 1 {
					t.Fatalf("closure call has argument sources %+v, want one entry", call.ArgumentSources)
				}
				if got := describeNodeSourceChain(call.ArgumentSources[0]); got != "" {
					t.Fatalf("closure argument resolves to %q, want nothing", got)
				}
				return
			}
		}
	}
	t.Fatal("closure createHash call not found")
}
