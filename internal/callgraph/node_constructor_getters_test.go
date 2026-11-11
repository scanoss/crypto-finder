// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import "testing"

// A getter folds only while no code but the one constructor assignment can
// write the field: not another writer in the class body or the declaring
// file, and not code the object reaches through `this` or a receiver local.
func TestNodeConstructorGetter_OtherWriters(t *testing.T) {
	t.Parallel()
	graph := parseInlineNodeProject(t, map[string]string{
		"src/holder.mjs": `export class Holder {
  constructor(alg) { this.alg = alg; }
  getAlg() { return this.alg; }
  describe() { return "holder"; }
}
`,
		// Any write of alg through another reference drops every class of
		// this file, so the writers live apart from Holder.
		"src/writers.mjs": `export class ArrowWriter {
  constructor(alg) { this.alg = alg; }
  getAlg() { return this.alg; }
  weaken = () => { this.alg = "md5"; };
}
export class StaticWriter {
  constructor(alg) { this.alg = alg; }
  getAlg() { return this.alg; }
  static downgrade(h) { h.alg = "md5"; }
}
export class StaticBlock {
  static { const fallback = new StaticBlock("sha1"); fallback.alg = "md5"; }
  constructor(alg) { this.alg = alg; }
  getAlg() { return this.alg; }
}
export class Registered {
  constructor(alg) { this.alg = alg; registry.push(this); }
  getAlg() { return this.alg; }
}
export class Fluent {
  constructor(alg) { this.alg = alg; }
  getAlg() { return this.alg; }
  self() { return this; }
}
const registry = [];
`,
		"src/weak.mjs": `export class Weak {
  constructor(alg) { this.alg = alg; }
  getAlg() { return this.alg; }
}
export function weaken(w) { w["alg"] = "md5"; }
`,
		"src/main.mjs": `import crypto from "crypto";
import { Holder } from "./holder.mjs";
import { ArrowWriter, StaticWriter, StaticBlock, Registered, Fluent } from "./writers.mjs";
import { Weak } from "./weak.mjs";
function configure(h) { h.alg = "md5"; }
export function methodsOnly() { const h = new Holder("sha256"); h.describe(); return crypto.createHash(h.getAlg()); }
export function inPlace() { return crypto.createHash(new Holder("sha256").getAlg()); }
export function arrowWriter() { return crypto.createHash(new ArrowWriter("sha256").getAlg()); }
export function staticWriter() { return crypto.createHash(new StaticWriter("sha256").getAlg()); }
export function staticBlock() { return crypto.createHash(new StaticBlock("sha256").getAlg()); }
export function registered() { return crypto.createHash(new Registered("sha256").getAlg()); }
export function fluent() { return crypto.createHash(new Fluent("sha256").getAlg()); }
export function fileWriter() { return crypto.createHash(new Weak("sha256").getAlg()); }
export function helper() { const h = new Holder("sha256"); configure(h); return crypto.createHash(h.getAlg()); }
export function alias() { const h = new Holder("sha256"); const g = h; g.alg = "md5"; return crypto.createHash(h.getAlg()); }
export function returned() { const h = new Holder("sha256"); crypto.createHash(h.getAlg()); return h; }
export function stored(list) { const h = new Holder("sha256"); list.push(h); return crypto.createHash(h.getAlg()); }
export function captured(hooks) { const h = new Holder("sha256"); hooks.push(() => h.describe()); return crypto.createHash(h.getAlg()); }
export function boundMethod(hooks) { const h = new Holder("sha256"); hooks.push(h.describe); return crypto.createHash(h.getAlg()); }
`,
	})
	tests := []struct{ function, want string }{
		{"methodsOnly", `"sha256"`},
		{"inPlace", `"sha256"`},
		{"arrowWriter", ""},
		{"staticWriter", ""},
		{"staticBlock", ""},
		{"registered", ""},
		{"fluent", ""},
		{"fileWriter", ""},
		{"helper", ""},
		{"alias", ""},
		{"returned", ""},
		{"stored", ""},
		{"captured", ""},
		{"boundMethod", ""},
	}
	for _, tt := range tests {
		t.Run(tt.function, func(t *testing.T) {
			t.Parallel()
			if got := nodeResolvedArgument(t, graph, "src/main.mjs", tt.function, "createHash", 0); got != tt.want {
				t.Fatalf("createHash argument resolves to %q, want %q", got, tt.want)
			}
		})
	}
}
