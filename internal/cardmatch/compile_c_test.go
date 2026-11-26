// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package cardmatch

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// cRuleYAML writes rules of languages [c, cpp], one per id, each body
// indented under its id.
func cRuleYAML(rules map[string]string) string {
	var b strings.Builder
	b.WriteString("rules:\n")
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		fmt.Fprintf(&b, "- id: %s\n  languages: [c, cpp]\n  metadata: {crypto: {assetType: algorithm, api: $FUNC}}\n", id)
		for _, line := range strings.Split(strings.TrimSpace(rules[id]), "\n") {
			b.WriteString("  " + line + "\n")
		}
	}
	return b.String()
}

func exportC(t *testing.T, rules map[string]string) map[string]ExportedRule {
	t.Helper()
	out, err := ExportRules(writeRules(t, cRuleYAML(rules)))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]ExportedRule{}
	for _, r := range out {
		byID[r.ID] = r
	}
	return byID
}

// Each shape of the closed set compiles to its site entries: the method
// bucket and arity on the shared fields, the rest in "c".
func TestCompileCShapes(t *testing.T) {
	for _, tc := range []struct {
		name, rule string
		want       []string
	}{
		{
			name: "named call guarded by an include of any form, focused on an argument",
			rule: `
patterns:
- pattern-inside: |
    #include "$H"
    ...
- metavariable-regex: {metavariable: $H, regex: '^<?acme/kdf\.h>?$'}
- pattern: acme_kdf_derive($CTX, $MD, ...)
- metavariable-regex: {metavariable: $MD, regex: '^ACME_MD_\w+$'}
- focus-metavariable: $MD`,
			want: []string{`{"method": "acme_kdf_derive", "min_arity": 2, "max_arity": null, "c": {"call": {"kind": "call", "callee": {"kind": "ident", "name": "acme_kdf_derive"}, "args": [{"kind": "metavar", "var": "$CTX"}, {"kind": "metavar", "var": "$MD"}, {"kind": "ellipsis"}]}, "inside": [{"place": "before", "include": {"form": "any", "var": "$H"}}], "where": [{"metavar": "$H", "regex": "^<?acme/kdf\\.h>?$"}, {"metavar": "$MD", "regex": "^ACME_MD_\\w+$"}], "focus": "$MD"}, "taint": false}`},
		},
		{
			name: "metavariable callee under either of two system includes",
			rule: `
patterns:
- pattern-either:
  - pattern-inside: |
      #include <acme/a.h>
      ...
  - pattern-inside: |
      #include "acme/b.h"
      ...
- pattern: $FUNC(...)
- metavariable-regex: {metavariable: $FUNC, regex: '^acme_(?<op>seal|open)$'}`,
			want: []string{
				`{"method": null, "min_arity": 0, "max_arity": null, "c": {"call": {"kind": "call", "callee": {"kind": "metavar", "var": "$FUNC"}, "args": [{"kind": "ellipsis"}]}, "inside": [{"place": "before", "include": {"form": "system", "header": "acme/a.h"}}], "where": [{"metavar": "$FUNC", "regex": "^acme_(?P<op>seal|open)$"}]}, "taint": false}`,
				`{"method": null, "min_arity": 0, "max_arity": null, "c": {"call": {"kind": "call", "callee": {"kind": "metavar", "var": "$FUNC"}, "args": [{"kind": "ellipsis"}]}, "inside": [{"place": "before", "include": {"form": "quote", "header": "acme/b.h"}}], "where": [{"metavar": "$FUNC", "regex": "^acme_(?P<op>seal|open)$"}]}, "taint": false}`,
			},
		},
		{
			name: "argument shapes: address, nested call, literals, or-chain, deep",
			rule: `pattern: acme_open(&$K, acme_md($M), NULL, 0x10, "gcm", ACME_A | $FL, <... $X ...>)`,
			want: []string{`{"method": "acme_open", "min_arity": 7, "max_arity": 7, "c": {"call": {"kind": "call", "callee": {"kind": "ident", "name": "acme_open"}, "args": [{"kind": "unary", "op": "&", "sub": {"kind": "metavar", "var": "$K"}}, {"kind": "call", "callee": {"kind": "ident", "name": "acme_md"}, "args": [{"kind": "metavar", "var": "$M"}]}, {"kind": "ident", "name": "NULL"}, {"kind": "int", "text": "0x10"}, {"kind": "string", "text": "gcm"}, {"kind": "binary", "op": "|", "args": [{"kind": "ident", "name": "ACME_A"}, {"kind": "metavar", "var": "$FL"}]}, {"kind": "deep", "sub": {"kind": "metavar", "var": "$X"}}]}}, "taint": false}`},
		},
		{
			name: "pattern-not and pattern-not-inside of calls",
			rule: `
patterns:
- pattern: acme_hash($ALG, ...)
- pattern-not: acme_hash(ACME_NONE, ...)
- pattern-not-inside: acme_hmac(...)`,
			want: []string{`{"method": "acme_hash", "min_arity": 1, "max_arity": null, "c": {"call": {"kind": "call", "callee": {"kind": "ident", "name": "acme_hash"}, "args": [{"kind": "metavar", "var": "$ALG"}, {"kind": "ellipsis"}]}, "not_inside": [{"place": "around", "call": {"kind": "call", "callee": {"kind": "ident", "name": "acme_hmac"}, "args": [{"kind": "ellipsis"}]}}], "not": [{"call": {"kind": "call", "callee": {"kind": "ident", "name": "acme_hash"}, "args": [{"kind": "ident", "name": "ACME_NONE"}, {"kind": "ellipsis"}]}}]}, "taint": false}`},
		},
		{
			name: "bare metavariable inside a call context",
			rule: `
patterns:
- pattern-inside: $F(...)
- metavariable-regex: {metavariable: $F, regex: '^acme_\w+$'}
- pattern: $ALG
- metavariable-regex: {metavariable: $ALG, regex: '^ACME_ALG_GCM$'}
- focus-metavariable: $ALG`,
			want: []string{`{"method": null, "min_arity": 0, "max_arity": null, "c": {"expr": {"kind": "metavar", "var": "$ALG"}, "inside": [{"place": "around", "call": {"kind": "call", "callee": {"kind": "metavar", "var": "$F"}, "args": [{"kind": "ellipsis"}]}}], "where": [{"metavar": "$F", "regex": "^acme_\\w+$"}, {"metavar": "$ALG", "regex": "^ACME_ALG_GCM$"}], "focus": "$ALG"}, "taint": false}`},
		},
		{
			name: "store to a field, under a declaration, a statement call and a function",
			rule: `
patterns:
- pattern-inside: |
    ACME_JOB $J;
    ...
- pattern-inside: |
    acme_job_init(&$J);
    ...
- pattern-not-inside: |
    static void acme_selftest(...) { ... }
- pattern: $J.mode = $V
- focus-metavariable: $V`,
			want: []string{`{"method": null, "min_arity": 0, "max_arity": null, "c": {"store": {"kind": "assign", "op": "=", "args": [{"kind": "member", "name": "mode", "op": ".", "sub": {"kind": "metavar", "var": "$J"}}, {"kind": "metavar", "var": "$V"}]}, "inside": [{"place": "before", "decl": {"type": ["ACME_JOB"], "name": "$J"}}, {"place": "before", "call": {"kind": "call", "callee": {"kind": "ident", "name": "acme_job_init"}, "args": [{"kind": "unary", "op": "&", "sub": {"kind": "metavar", "var": "$J"}}]}}], "not_inside": [{"place": "around", "func": {"type": "void", "name": "acme_selftest"}}], "focus": "$V"}, "taint": false}`},
		},
		{
			name: "statement call; an alternative that does not bind the focus is dropped",
			rule: `
patterns:
- pattern-inside: |
    $T $SUITES[] = {..., $S, ...};
    ...
- pattern-either:
  - pattern: acme_set($C, $SUITES);
  - pattern: acme_clear()
- focus-metavariable: $C`,
			want: []string{`{"method": "acme_set", "min_arity": 2, "max_arity": 2, "c": {"call": {"kind": "call", "callee": {"kind": "ident", "name": "acme_set"}, "args": [{"kind": "metavar", "var": "$C"}, {"kind": "metavar", "var": "$SUITES"}]}, "stmt": true, "inside": [{"place": "before", "decl": {"type": ["$T"], "name": "$SUITES", "array": true, "init": {"kind": "init", "args": [{"kind": "ellipsis"}, {"kind": "metavar", "var": "$S"}, {"kind": "ellipsis"}]}}}], "focus": "$C"}, "taint": false}`},
		},
		{
			name: "taint: a regex value source, a call source, a name beside a source",
			rule: `
mode: taint
pattern-sources:
- patterns:
  - pattern: $ALG
  - metavariable-regex: {metavariable: $ALG, regex: '^ACME_ALG_(?<bits>\d+)$'}
- pattern: acme_md_sha256()
- patterns:
  - pattern-either:
    - pattern: ACME_GROUP_A
    - pattern: ACME_GROUP_B
  - pattern: $G
pattern-sinks:
- patterns:
  - pattern: acme_init($CTX, $ALGO, ...)
  - focus-metavariable: $ALGO`,
			want: []string{`{"method": "acme_init", "min_arity": 2, "max_arity": null, "c": {"call": {"kind": "call", "callee": {"kind": "ident", "name": "acme_init"}, "args": [{"kind": "metavar", "var": "$CTX"}, {"kind": "metavar", "var": "$ALGO"}, {"kind": "ellipsis"}]}, "focus": "$ALGO", "taint": {"sources": [{"expr": {"kind": "metavar", "var": "$ALG"}, "where": [{"metavar": "$ALG", "regex": "^ACME_ALG_(?P<bits>\\d+)$"}]}, {"expr": {"kind": "call", "callee": {"kind": "ident", "name": "acme_md_sha256"}}}, {"expr": {"kind": "ident", "name": "ACME_GROUP_A"}, "bind": "$G"}, {"expr": {"kind": "ident", "name": "ACME_GROUP_B"}, "bind": "$G"}]}}, "taint": true}`},
		},
		{
			name: "string literal with a regex on its content and a pattern-regex",
			rule: `
patterns:
- pattern: '"$ALGO"'
- metavariable-regex: {metavariable: $ALGO, regex: '^(?<v>ACME-(?<bits>128|256))$'}
- pattern-regex: '"(?:ACME-128|ACME-256)"'`,
			want: []string{`{"method": null, "min_arity": 0, "max_arity": null, "c": {"str": {"kind": "strvar", "var": "$ALGO"}, "str_regex": ["\"(?:ACME-128|ACME-256)\""], "where": [{"metavar": "$ALGO", "regex": "^(?P<v>ACME-(?P<bits>128|256))$"}]}, "taint": false}`},
		},
		{
			name: "include directive regex",
			rule: `
pattern-either:
- pattern-regex: '#include\s+["<].*acme/.*[>"]'`,
			want: []string{`{"method": null, "min_arity": 0, "max_arity": null, "c": {"regex": "#include\\s+[\"<].*acme/.*[>\"]"}, "taint": false}`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := exportC(t, map[string]string{"acme.rule": tc.rule})["acme.rule"]
			if r.Status != "compiled" {
				t.Fatalf("status %s (%s)", r.Status, r.Reason)
			}
			unescape := strings.NewReplacer(`\u003c`, "<", `\u003e`, ">", `\u0026`, "&")
			got := siteTexts(r)
			for i := range got {
				got[i] = unescape.Replace(got[i])
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("sites\n got %v\nwant %v", got, tc.want)
			}
		})
	}
}

// A clause outside the closed set, in any branch, skips the whole rule with
// one reason of the closed set.
func TestCompileCSkips(t *testing.T) {
	rules := map[string]string{
		"taint sanitizer":    "mode: taint\npattern-sources: [{pattern: acme_src()}]\npattern-sanitizers: [{pattern: acme_clean(...)}]\npattern-sinks: [{pattern: acme_sink(...)}]",
		"taint source":       "mode: taint\npattern-sources: [{pattern: $A + $B}]\npattern-sinks: [{pattern: acme_sink(...)}]",
		"taint sink":         "mode: taint\npattern-sources: [{pattern: acme_src()}]\npattern-sinks: [{patterns: [{pattern-inside: acme_f(...)}, {pattern: $X}]}]",
		"free regex":         "pattern-regex: 'acme_[a-z]+'",
		"regex in a conj":    "patterns:\n- pattern: acme_f(...)\n- pattern-regex: '#include <acme.h>'",
		"string literal":     "patterns:\n- pattern-inside: acme_f(...)\n- pattern: '\"$S\"'\n- metavariable-regex: {metavariable: $S, regex: '^acme'}",
		"unbounded regex":    "patterns:\n- pattern: '\"$S\"'\n- pattern-regex: '\"acme.*\"'",
		"assignment":         "pattern: $X = $V",
		"statement":          "pattern: $X = acme_f();",
		"one bad branch":     "pattern-either:\n- pattern: acme_f(...)\n- pattern: $X + 1",
		"two positives":      "patterns:\n- pattern: acme_f(...)\n- pattern: acme_g(...)",
		"unbound regex":      "patterns:\n- pattern: acme_f(...)\n- metavariable-regex: {metavariable: $X, regex: x}",
		"bad regex":          "patterns:\n- pattern: acme_f($X)\n- metavariable-regex: {metavariable: $X, regex: '(?<'}",
		"or operand regex":   "patterns:\n- pattern: acme_f(A | $X)\n- metavariable-regex: {metavariable: $X, regex: x}",
		"sequence":           "patterns:\n- pattern-inside: |\n    $C = NULL;\n    ...\n- pattern: acme_use($C)",
		"declaration":        "patterns:\n- pattern-inside: |\n    ACME_CTX $C, $D;\n    ...\n- pattern: acme_use(&$C)",
		"function":           "patterns:\n- pattern-not-inside: |\n    int acme_selftest(...) { ... acme_x(); ... }\n- pattern: acme_use(...)",
		"include no range":   "patterns:\n- pattern-inside: '#include <acme.h>'\n- pattern: acme_use(...)",
		"bare expression":    "patterns:\n- pattern: $X\n- metavariable-regex: {metavariable: $X, regex: '^ACME'}",
		"member call":        "pattern: $C->seal(...)",
		"metavariable-pat":   "patterns:\n- pattern: acme_f($X)\n- metavariable-pattern: {metavariable: $X, pattern: ACME_K}",
		"unbound focus":      "patterns:\n- pattern: acme_f(...)\n- focus-metavariable: $Y",
		"inside only":        "patterns:\n- pattern-inside: acme_f(...)",
		"not of an include":  "patterns:\n- pattern: acme_f(...)\n- pattern-not: |\n    #include <acme.h>\n    ...",
		"unreadable pattern": "pattern: acme_f(",
	}
	want := map[string]cSkip{
		"taint sanitizer": skipCTaintSanitizers, "taint source": skipCTaintSource, "taint sink": skipCTaintSink, "free regex": skipCPatternRegex, "regex in a conj": skipCPatternRegex,
		"string literal": skipCString, "unbounded regex": skipCPatternRegex, "assignment": skipCStatement, "statement": skipCStatement,
		"one bad branch": skipCExpr, "two positives": skipCPositives, "unbound regex": skipCUnbound,
		"bad regex": skipCRegex, "or operand regex": skipCOrOperand, "sequence": skipCSequence,
		"declaration": skipCDeclaration, "function": skipCFunction, "include no range": skipCContext,
		"bare expression": skipCBareExpr, "member call": skipCExpr, "metavariable-pat": skipCClause,
		"unbound focus": skipCFocus, "inside only": skipCNoPositive, "not of an include": skipCStatement,
		"unreadable pattern": skipCSyntax,
	}
	byID := map[string]string{}
	for name, rule := range rules {
		byID[strings.ReplaceAll(name, " ", "-")] = rule
	}
	got := exportC(t, byID)
	for name, reason := range want {
		r := got[strings.ReplaceAll(name, " ", "-")]
		if r.Status != "skipped" || r.Reason != string(reason) || len(r.Sites) != 0 {
			t.Errorf("%s: %s %q with %d sites, want skipped %q", name, r.Status, r.Reason, len(r.Sites), reason)
		}
	}
	if len(want) != len(rules) {
		t.Errorf("%d rules, %d expectations", len(rules), len(want))
	}
}

// cards-export keeps one record per rule, compiled + skipped = rules, every
// skip reason is in the closed set, and no C entry is lossy.
func TestExportCCountsAndStrictness(t *testing.T) {
	rules := map[string]string{
		"a": "pattern: acme_f(...)",
		"b": "pattern-either:\n- pattern: acme_f(...)\n- pattern: acme_g($X)",
		"c": "pattern-regex: x",
		"d": "patterns:\n- pattern: acme_f(...)\n- pattern: acme_g(...)",
		"e": "patterns:\n- pattern: acme_seal($K, ...)\n- pattern-not: acme_seal(NULL, ...)",
	}
	out, err := ExportRules(writeRules(t, cRuleYAML(rules)))
	if err != nil {
		t.Fatal(err)
	}
	var compiled, skipped, sites int
	seen := map[string]bool{}
	for _, r := range out {
		if seen[r.ID] {
			t.Errorf("rule %s has two records", r.ID)
		}
		seen[r.ID] = true
		switch r.Status {
		case "compiled":
			compiled++
			sites += len(r.Sites)
		case "skipped":
			skipped++
			if !slices.Contains(cSkipReasons, cSkip(r.Reason)) {
				t.Errorf("rule %s: reason %q is not in the closed set", r.ID, r.Reason)
			}
		}
		if len(r.DroppedClauses) != 0 {
			t.Errorf("rule %s dropped %v", r.ID, r.DroppedClauses)
		}
		for _, s := range r.Sites {
			if strings.Contains(string(s), `"lossy"`) || !strings.Contains(string(s), `"c": {`) {
				t.Errorf("rule %s site %s", r.ID, s)
			}
		}
	}
	if len(out) != 5 || compiled != 3 || skipped != 2 || compiled+skipped != len(out) || sites != 4 {
		t.Errorf("%d rules: %d compiled (%d sites) + %d skipped, want 5: 3 (4) + 2", len(out), compiled, sites, skipped)
	}
}

// A compiled C entry, written as a v3 site card, loads back into the same
// pattern: site cards carry the C form unchanged.
func TestCSiteCardRoundTrip(t *testing.T) {
	rule := "patterns:\n- pattern-inside: |\n    #include \"$H\"\n    ...\n- pattern: acme_seal(&$K, ...)\n- metavariable-regex: {metavariable: $H, regex: '^acme'}"
	r := exportC(t, map[string]string{"acme.seal": rule})["acme.seal"]
	if len(r.Sites) != 1 {
		t.Fatalf("sites = %d", len(r.Sites))
	}
	cards := "format: scanoss-cards/3\nrules:\n  acme.seal: {severity: INFO, message: m, crypto: {assetType: algorithm}}\ncards:\n- rule: acme.seal\n  site: " + string(r.Sites[0]) + "\n"
	dir := writeCards(t, map[string]string{"acme/rules.cards": cards})
	a, err := Load("", dir, filepath.Join(dir, "no-rules"))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileIndex(writeRules(t, cRuleYAML(map[string]string{"acme.seal": rule})))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.index.Entries) != 1 || a.index.Entries[0].C == nil {
		t.Fatalf("site card entries = %+v", a.index.Entries)
	}
	got, want := mustJSON(t, a.index.Entries[0].C), mustJSON(t, compiled.Entries[0].C)
	if got != want || !strings.Contains(got, `"form":"any"`) {
		t.Errorf("site card pattern\n got %s\nwant %s", got, want)
	}
}

// The reader drops parentheses, flattens `|` chains and keeps each
// expression's span in the text read.
func TestReadCExpr(t *testing.T) {
	for _, tc := range []struct {
		text, kind string
		spans      []string // the text of every subexpression, outer first
	}{
		{`acme_run(ACME_HMAC(ACME_SHA256), &x, (int) ACME_GCM)`, CExprCall, []string{
			`acme_run(ACME_HMAC(ACME_SHA256), &x, (int) ACME_GCM)`, `acme_run`, `ACME_HMAC(ACME_SHA256)`, `ACME_HMAC`, `ACME_SHA256`,
			`&x`, `x`, `(int) ACME_GCM`, `ACME_GCM`,
		}},
		// A call through a parenthesized callee starts where OpenGrep starts it,
		// at the callee without its parenthesis.
		{`(*fp)(5)`, CExprCall, []string{`*fp)(5)`, `*fp`, `fp`, `5`}},
		{`f(a | (b | c), ctx->k[1], "x" "y")`, CExprCall, []string{
			`f(a | (b | c), ctx->k[1], "x" "y")`, `f`, `a | (b | c`, `a`, `b`, `c`, `ctx->k[1]`, `ctx->k`, `ctx`, `1`, `"x" "y"`, `"x"`, `"y"`,
		}},
		{"f(a,\n  /* note */ b)", CExprCall, []string{"f(a,\n  /* note */ b)", `f`, `a`, `b`}},
	} {
		e, ok := readCExpr(tc.text, false)
		if !ok || e.Kind != tc.kind {
			t.Errorf("%q: read %v %+v", tc.text, ok, e)
			continue
		}
		var spans []string
		cWalk(e, func(x *CExpr) bool {
			spans = append(spans, tc.text[x.Start:x.End])
			return false
		})
		if !slices.Equal(spans, tc.spans) {
			t.Errorf("%q spans\n got %q\nwant %q", tc.text, spans, tc.spans)
		}
	}
	for _, bad := range []string{"f(\n#ifdef X\n a\n#endif\n)", "f(a", "$X(a)", "f(...)"} {
		if _, ok := readCExpr(bad, false); ok {
			t.Errorf("%q read as source", bad)
		}
	}
}

// A pattern-regex beside a string literal compiles only when it has no
// repetition, anchor or lookaround: its match in a literal is then its
// match in the file.
func TestCBoundedRegex(t *testing.T) {
	for rx, want := range map[string]bool{
		`"(?:ACME-128|ACME-256)"`: true, `(?<v>X25519|X448)MLKEM(?:768|1024)`: true, `"acme[-_]?\d"`: true,
		`"acme.*"`: false, `acme+`: false, `^acme`: false, `acme$`: false, `\bacme`: false, `acme(?=x)`: false,
		`acme(?<!x)`: false, `a{2}`: false, `[*+{]`: true, `\*`: true,
	} {
		if got := cBoundedRegex(rx); got != want {
			t.Errorf("cBoundedRegex(%s) = %v, want %v", rx, got, want)
		}
	}
}

// cIntValue reads an integer literal in any base and suffix.
func TestCIntValue(t *testing.T) {
	for text, want := range map[string]uint64{"128": 128, "0x80": 128, "0200": 128, "128UL": 128, "0b10000000": 128, "0": 0} {
		if v, ok := cIntValue(text); !ok || v != want {
			t.Errorf("%s = %d %v, want %d", text, v, ok, want)
		}
	}
	for _, text := range []string{"1.5", "0x", "09", "1e3"} {
		if _, ok := cIntValue(text); ok {
			t.Errorf("%s read as an integer", text)
		}
	}
}
