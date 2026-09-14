// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestNodeParser_GrammarMatrixBindsAContainingFunction pins the set of
// JavaScript constructs that can sit between a crypto call and its containing
// function. One file per construct, each carrying the SAME call, so only the
// construct varies: a row that stops binding a function names exactly which
// construct the parser stopped walking.
//
// Every probe's function name is unique, and the test asserts it. Identities are
// keyed per module, so two probes sharing a name would collapse onto one
// identity and the matrix would measure fewer constructs than it lists.
func TestNodeParser_GrammarMatrixBindsAContainingFunction(t *testing.T) {
	t.Parallel()

	const call = `crypto.createHash("sha256").update(d).digest("hex")`

	cases := []struct{ name, src string }{
		{"plain_function", `export function m00(d){ return ` + call + `; }`},
		{"namespace_import_call", `export function m01(d){ return c01.createHash("sha256").update(d).digest("hex"); }`},
		{"await_expression", `export async function m02(d){ return await ` + call + `; }`},
		{"optional_chain", `export function m03(d){ return crypto?.createHash("sha256").update(d).digest("hex"); }`},
		{"class_declaration_method", `export class C05 { m05(d){ return ` + call + `; } }`},
		{"class_field_initialiser", `export class C06 { m06 = crypto.createHash("sha256"); }`},
		{"assignment_expression", `export function m07(d){ let h; h = crypto.createHash("sha256"); return h.digest("hex"); }`},
		{"augmented_assignment", `export function m08(d){ let s = ""; s += ` + call + `; return s; }`},
		{"catch_clause", `export function m09(d){ try { throw 0; } catch (e) { return ` + call + `; } }`},
		{"for_in_statement", `export function m10(o){ for (const k in o) { return crypto.createHash("sha256").update(k).digest("hex"); } }`},
		{"labeled_statement", `export function m11(d){ outer: { return ` + call + `; } }`},
		{"spread_element", `export function m12(d){ return [...[` + call + `]]; }`},
		{"template_string", "export function m13(d){ return `${" + call + "}`; }"},
		{"yield_expression", `export function* m14(d){ yield ` + call + `; }`},
		{"object_literal_value", `export function m15(d){ return { h: ` + call + ` }; }`},
		{"array_pattern", `export function m16(d){ const [a] = [crypto.createHash("sha256")]; return a.update(d).digest("hex"); }`},
		{"assignment_pattern", `export function m17(d, h = crypto.createHash("sha256")){ return h.update(d).digest("hex"); }`},
		{"rest_pattern", `export function m18(...args){ return crypto.createHash("sha256").update(args[0]).digest("hex"); }`},
		{"export_specifier", `function m19(d){ return ` + call + `; }
export { m19 };`},
		{"arrow_function", `export const m20 = (d) => ` + call + `;`},
		{"object_literal_method", `export const o21 = { m21(d){ return ` + call + `; } };`},
		{"class_expression_method", `export const C22 = class { m22(d){ return ` + call + `; } };`},
		// The 23rd probe. Its gap is at the RULE layer: no rule matches a computed
		// member access, so the call is never reported at all. The parser still binds
		// its containing function, and this row asserts that, which is what separates
		// the rule-layer gap from a parser one.
		{"computed_member_access", `export function m23(d){ return crypto["createHash"]("sha256").update(d).digest("hex"); }`},
	}

	seen := map[string]string{}
	dir := t.TempDir()
	for _, tc := range cases {
		head := "import crypto from \"node:crypto\";\n"
		if tc.name == "namespace_import_call" {
			head = "import * as c01 from \"node:crypto\";\n"
		}
		file := filepath.Join(dir, tc.name+".js")
		if err := os.WriteFile(file, []byte(head+tc.src+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	analyses, err := NewNodeParser().ParseDirectory(dir, "matrix")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	if len(analyses) != len(cases) {
		t.Fatalf("analyses = %d, want %d", len(analyses), len(cases))
	}

	byFile := map[string][]FunctionDecl{}
	for _, a := range analyses {
		byFile[filepath.Base(a.FilePath)] = a.Functions
		for _, fn := range a.Functions {
			key := fmt.Sprintf("%s|%s|%s", fn.ID.Package, fn.ID.Type, fn.ID.Name)
			if prev, dup := seen[key]; dup {
				t.Errorf("identity %q shared by %s and %s: the matrix must keep every name unique, "+
					"or it silently measures fewer constructs than it lists", key, prev, fn.FilePath)
			}
			seen[key] = fn.FilePath
		}
	}

	for _, tc := range cases {
		if got := byFile[tc.name+".js"]; len(got) == 0 {
			t.Errorf("%s: no containing function bound; the crypto call would be reported with no reachability", tc.name)
		}
	}
}
