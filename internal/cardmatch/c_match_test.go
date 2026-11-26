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
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

const cTestFile = "src/acme.c"

// cSrcFrag is a C fragment over one file, one source line per element (line
// 1 first). Every line starting with #include is listed as a directive; every
// call of a name in calls is a call site with the span reach gives it (the
// call expression), on the line and at the occurrence written.
type cSrcCall struct {
	line int
	text string // the call as written on the line (its first line when it spans lines)
	// endLine and endText end a call that spans lines.
	endLine int
	endText string
}

func cSrcFrag(src []string, calls ...cSrcCall) *FragmentJSON {
	frag := &FragmentJSON{
		SchemaVersion: "graph-fragment-1.26",
		Functions:     []FunctionJSON{{Key: "main", FilePath: cTestFile}},
		SourceLines:   map[string]map[int]string{cTestFile: {}},
		Imports:       map[string][]graphfrag.GraphFragmentImport{},
	}
	frag.ScanMetadata.Ecosystem = "c"
	for i, l := range src {
		frag.SourceLines[cTestFile][i+1] = l
		if t := strings.TrimLeft(l, " "); strings.HasPrefix(t, "#include") {
			path := strings.TrimSpace(strings.TrimPrefix(t, "#include"))
			frag.Imports[cTestFile] = append(frag.Imports[cTestFile], graphfrag.GraphFragmentImport{
				Line: i + 1, Module: strings.Trim(path, `<>"`), StartCol: len(l) - len(t) + 1, EndCol: len(l) + 1, EndLine: i + 1, Text: t,
			})
		}
	}
	for _, c := range calls {
		line, endLine := c.line, c.endLine
		col := strings.Index(src[line-1], c.text) + 1
		end := col + len(c.text)
		if endLine > 0 {
			end = strings.Index(src[endLine-1], c.endText) + len(c.endText) + 1
		}
		name, _, _ := strings.Cut(c.text, "(")
		frag.ExternalCalls = append(frag.ExternalCalls, ExternalJSON{
			CallerKey: "main", MethodName: name, Line: &line, EndLine: endLine, StartCol: &col, EndCol: &end, Resolution: "exact",
		})
	}
	return frag
}

func cMatchRules(t *testing.T, rules map[string]string, frag *FragmentJSON) ([]*Finding, CMatchStats) {
	t.Helper()
	assets, err := Load("", "", writeRules(t, cRuleYAML(rules)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return matchCStats(assets, newFrag(frag))
}

// cFound prints each finding as rule@line:col-endcol (endline:endcol when it
// ends on another line).
func cFound(found []*Finding) []string {
	out := make([]string, 0, len(found))
	for _, f := range found {
		end := itoa(f.EndCol)
		if f.EndLine != 0 {
			end = itoa(f.EndLine) + ":" + end
		}
		out = append(out, fmt.Sprintf("%s@%d:%d-%s", f.RuleID, f.Line, f.Col, end))
	}
	slices.Sort(out)
	return out
}

func checkCFound(t *testing.T, rules map[string]string, frag *FragmentJSON, want ...string) {
	t.Helper()
	found, _ := cMatchRules(t, rules, frag)
	slices.Sort(want)
	if got := cFound(found); !slices.Equal(got, want) {
		t.Errorf("found\n got %v\nwant %v", got, want)
	}
}

// An #include context holds after a directive of its form and header in the
// same file; `#include "$H"` takes either form and binds `<h>` or `h`.
func TestCMatchIncludeContexts(t *testing.T) {
	src := []string{
		"void early(void) { acme_seal(k); }",
		"#include <acme/seal.h>",
		`#include "acme/open.h"`,
		"void f(void) {",
		"    acme_seal(k);",
		"}",
	}
	frag := cSrcFrag(src, cSrcCall{line: 1, text: "acme_seal(k)"}, cSrcCall{line: 5, text: "acme_seal(k)"})
	inside := func(directive string) string {
		return "patterns:\n- pattern-inside: |\n    " + directive + "\n    ...\n- pattern: acme_seal(...)"
	}
	checkCFound(t, map[string]string{
		"system":       inside("#include <acme/seal.h>"),
		"system-quote": inside(`#include "acme/seal.h"`),
		"quote":        inside(`#include "acme/open.h"`),
		"quote-system": inside("#include <acme/open.h>"),
		"any-angle":    inside(`#include "$H"`) + "\n- metavariable-regex: {metavariable: $H, regex: '^<acme/seal\\.h>$'}",
		"any-quote":    inside(`#include "$H"`) + "\n- metavariable-regex: {metavariable: $H, regex: '^acme/open\\.h$'}",
		"any-quoted":   inside(`#include "$H"`) + "\n- metavariable-regex: {metavariable: $H, regex: '^\"'}",
		"either": "patterns:\n- pattern-either:\n  - pattern-inside: |\n      #include <acme/none.h>\n      ...\n" +
			"  - pattern-inside: |\n      #include <acme/seal.h>\n      ...\n- pattern: acme_seal(...)",
	}, frag, "system@5:5-17", "quote@5:5-17", "any-angle@5:5-17", "any-quote@5:5-17", "either@5:5-17")
}

// A metavariable callee binds the callee as written; a focus reports the
// callee or the argument it binds, and each place it binds.
func TestCMatchCalleeAndFocus(t *testing.T) {
	src := []string{
		"void f(void) {",
		"    acme_seal_256(ctx, ACME_GCM | ACME_PAD, (ACME_KEY));",
		"    ctx->acme_seal_256(ctx, 1);",
		"    acme_mix(ACME_A(ACME_B), 2);",
		"}",
	}
	frag := cSrcFrag(src,
		cSrcCall{line: 2, text: "acme_seal_256(ctx, ACME_GCM | ACME_PAD, (ACME_KEY))"},
		cSrcCall{line: 3, text: "ctx->acme_seal_256(ctx, 1)"},
		cSrcCall{line: 4, text: "acme_mix(ACME_A(ACME_B), 2)"},
		cSrcCall{line: 4, text: "ACME_A(ACME_B)"},
	)
	checkCFound(t, map[string]string{
		"callee": "patterns:\n- pattern: $F(...)\n- metavariable-regex: {metavariable: $F, regex: '^acme_seal_(?<bits>\\d+)$'}\n- focus-metavariable: $F",
		"arg":    "patterns:\n- pattern: acme_seal_256($C, $M, $K)\n- focus-metavariable: $K",
		"deep":   "patterns:\n- pattern: acme_mix(<... $X ...>, ...)\n- metavariable-regex: {metavariable: $X, regex: '^ACME_'}\n- focus-metavariable: $X",
		"named":  "pattern: acme_seal_256($C, ...)",
	}, frag,
		"callee@2:5-18", "arg@2:46-54", "named@2:5-56",
		"deep@4:14-28", "deep@4:14-20", "deep@4:21-27",
	)
	found, _ := cMatchRules(t, map[string]string{
		"callee": "patterns:\n- pattern: $FUNC(...)\n- metavariable-regex: {metavariable: $FUNC, regex: '^acme_seal_(?<bits>\\d+)$'}",
	}, frag)
	if len(found) != 1 || found[0].Metadata.GetOr("api") != "acme_seal_256" {
		t.Errorf("metadata %v", found)
	}
}

// A pattern-not reads under the positive's bindings; a pattern-not-inside
// call drops a site written inside a matching call (or that is one).
func TestCMatchNegatives(t *testing.T) {
	src := []string{
		"void f(void) {",
		"    acme_kdf(x, y);",
		"    acme_kdf(x, x);",
		"    acme_hmac(acme_kdf(a, b), 1);",
		"    acme_hash(ACME_NONE, 1);",
		"    acme_hash(ACME_MD5, 1);",
		"}",
	}
	frag := cSrcFrag(src,
		cSrcCall{line: 2, text: "acme_kdf(x, y)"}, cSrcCall{line: 3, text: "acme_kdf(x, x)"},
		cSrcCall{line: 4, text: "acme_hmac(acme_kdf(a, b), 1)"}, cSrcCall{line: 4, text: "acme_kdf(a, b)"},
		cSrcCall{line: 5, text: "acme_hash(ACME_NONE, 1)"}, cSrcCall{line: 6, text: "acme_hash(ACME_MD5, 1)"},
	)
	checkCFound(t, map[string]string{
		"swap":   "patterns:\n- pattern: acme_kdf($A, $B)\n- pattern-not: acme_kdf($B, $A)",
		"hmac":   "patterns:\n- pattern: acme_kdf(...)\n- pattern-not-inside: acme_hmac(...)",
		"self":   "patterns:\n- pattern: acme_hmac(...)\n- pattern-not-inside: acme_hmac(...)",
		"none":   "patterns:\n- pattern: acme_hash($ALG, ...)\n- pattern-not: acme_hash(ACME_NONE, ...)",
		"inside": "patterns:\n- pattern-inside: acme_hmac(...)\n- pattern: acme_kdf(...)",
	}, frag, "swap@2:5-19", "swap@4:15-29", "hmac@2:5-19", "hmac@3:5-19", "none@6:5-27", "inside@4:15-29")
}

// An `|` pattern matches modulo associativity and commutativity: its
// operands match distinct operands of the written chain, others may be left
// over, and a `...` operand needs one. Integers compare by value, strings by
// content whatever their prefix.
func TestCMatchOrChainsAndLiterals(t *testing.T) {
	src := []string{
		"void f(void) {",
		"    acme_open(s, ACME_DGRAM);",
		"    acme_open(s, ACME_NB | ACME_DGRAM);",
		"    acme_open(s, (ACME_DGRAM | ACME_X) | ACME_NB);",
		"    acme_keygen(k, 0x800);",
		`    acme_name("gcm", L"gcm");`,
		"}",
	}
	frag := cSrcFrag(src,
		cSrcCall{line: 2, text: "acme_open(s, ACME_DGRAM)"}, cSrcCall{line: 3, text: "acme_open(s, ACME_NB | ACME_DGRAM)"},
		cSrcCall{line: 4, text: "acme_open(s, (ACME_DGRAM | ACME_X) | ACME_NB)"},
		cSrcCall{line: 5, text: "acme_keygen(k, 0x800)"}, cSrcCall{line: 6, text: `acme_name("gcm", L"gcm")`},
	)
	checkCFound(t, map[string]string{
		"dots": "pattern: acme_open($S, ACME_DGRAM | ...)",
		"pair": "pattern: acme_open($S, ACME_NB | ACME_DGRAM)",
		"bits": "pattern: acme_keygen($K, 2048)",
		"str":  `pattern: acme_name("gcm", $W)`,
		"wide": `pattern: acme_name($N, "gcm")`,
	}, frag, "dots@3:5-39", "dots@4:5-50", "pair@3:5-39", "pair@4:5-50", "bits@5:5-26", "str@6:5-29", "wide@6:5-29")
}

// A bare metavariable inside a call context matches every expression
// written in a matching call, the callee and the call itself included.
func TestCMatchBareExpression(t *testing.T) {
	src := []string{
		"#include <acme/psa.h>",
		"void f(void) {",
		"    acme_psa_run(ACME_ALG_HMAC(ACME_ALG_SHA256), (int) ACME_ALG_GCM);",
		"    other_run(ACME_ALG_GCM);",
		"}",
	}
	frag := cSrcFrag(src,
		cSrcCall{line: 3, text: "acme_psa_run(ACME_ALG_HMAC(ACME_ALG_SHA256), (int) ACME_ALG_GCM)"},
		cSrcCall{line: 3, text: "ACME_ALG_HMAC(ACME_ALG_SHA256)"},
		cSrcCall{line: 4, text: "other_run(ACME_ALG_GCM)"},
	)
	rule := func(rx string) string {
		return "patterns:\n- pattern-inside: |\n    #include \"$H\"\n    ...\n- pattern-inside: $F(...)\n" +
			"- metavariable-regex: {metavariable: $F, regex: '^acme_psa_\\w+$'}\n- pattern: $ALG\n" +
			"- metavariable-regex: {metavariable: $ALG, regex: '" + rx + "'}\n- focus-metavariable: $ALG"
	}
	checkCFound(t, map[string]string{"gcm": rule("^ACME_ALG_GCM$"), "sha": rule("^ACME_ALG_SHA\\d+$"), "all": rule("^acme_psa_run")},
		frag, "gcm@3:56-68", "sha@3:32-47", "all@3:5-17", "all@3:5-69")
}

// A pattern-regex positive is searched in each directive's text and
// reported at the columns it matches.
func TestCMatchIncludeRegex(t *testing.T) {
	src := []string{
		"#include <acme/seal.h>",
		`  #include "vendor/acme/open.h" /* "x" */`,
		"#include <other.h>",
		"#  include <acme/spaced.h>",
	}
	checkCFound(t, map[string]string{"usage": `pattern-regex: '#include\s+["<].*acme/.*[>"]'`}, cSrcFrag(src),
		"usage@1:1-23", "usage@2:3-39")
}

// A call whose text cannot be read (a preprocessor line inside it, no
// source line) is counted, not matched.
func TestCMatchUnreadableSites(t *testing.T) {
	src := []string{
		"void f(void) {",
		"    acme_seal(k,",
		"#ifdef ACME_X",
		"        1",
		"#endif",
		"    );",
		"}",
	}
	frag := cSrcFrag(src, cSrcCall{line: 2, text: "acme_seal(k,", endLine: 6, endText: ")"})
	line := 9
	frag.ExternalCalls = append(frag.ExternalCalls, ExternalJSON{CallerKey: "main", MethodName: "acme_seal", Line: &line, Resolution: "exact"})
	found, stats := cMatchRules(t, map[string]string{"any": "pattern: acme_seal(...)"}, frag)
	if len(found) != 0 || stats.UnreadableSites != 2 || stats.Entries != 1 {
		t.Errorf("found %v, stats %+v; want nothing, 2 unreadable sites, 1 entry", cFound(found), stats)
	}
}

// withCDecl lists the declaration written on line as a fact of the
// fragment's function, with each name it declares.
func withCDecl(frag *FragmentJSON, line int, names ...string) {
	text := frag.SourceLines[cTestFile][line]
	col := len(text) - len(strings.TrimLeft(text, " ")) + 1
	for _, n := range names {
		frag.Declarations = append(frag.Declarations, graphfrag.GraphFragmentDeclaration{
			Function: 0, Line: line, StartCol: col, EndCol: len(text) + 1, Name: n,
		})
	}
}

// withCStore lists the field store written on line (up to its semicolon).
func withCStore(frag *FragmentJSON, line int) {
	text := frag.SourceLines[cTestFile][line]
	col := len(text) - len(strings.TrimLeft(text, " ")) + 1
	frag.AttributeStores = append(frag.AttributeStores, graphfrag.GraphFragmentAttributeStore{
		Function: 0, Line: line, StartCol: col, EndCol: strings.LastIndex(text, ";") + 1, Operator: "=",
	})
}

// A field store positive matches the fragment's stores; a declaration and a
// statement call before the range in its function, and the function it is
// written in, are contexts.
func TestCMatchStoresAndStatementContexts(t *testing.T) {
	src := []string{
		"void acme_run(ACME_JOB *job) {",
		"    ACME_JOB local;",
		"    err = acme_job_init(&local);",
		"    if (acme_job_init(job)) { }",
		"    local.mode = ACME_GCM;",
		"    job->mode = ACME_CCM;",
		"}",
	}
	frag := cSrcFrag(src, cSrcCall{line: 3, text: "acme_job_init(&local)"}, cSrcCall{line: 4, text: "acme_job_init(job)"})
	frag.Functions[0].Name, frag.Functions[0].ReturnType = "acme_run", "void"
	withCDecl(frag, 2, "local")
	withCStore(frag, 5)
	withCStore(frag, 6)
	checkCFound(t, map[string]string{
		"any":  "patterns:\n- pattern-either:\n  - pattern: $J.mode = $V\n  - pattern: $J->mode = $V\n- focus-metavariable: $V",
		"decl": "patterns:\n- pattern-inside: |\n    ACME_JOB $J;\n    ...\n- pattern: $J.mode = $V",
		"init": "patterns:\n- pattern-inside: |\n    acme_job_init(&$J);\n    ...\n- pattern: $J.mode = $V",
		"cond": "patterns:\n- pattern-inside: |\n    acme_job_init($J);\n    ...\n- pattern: $J->mode = $V",
		"func": "patterns:\n- pattern-not-inside: |\n    static void acme_run(...) { ... }\n- pattern: $J->mode = $V",
		"ret":  "patterns:\n- pattern-inside: |\n    $R acme_run(...) { ... }\n- pattern: $J->mode = $V\n- metavariable-regex: {metavariable: $R, regex: '^void$'}",
	}, frag, "any@5:18-26", "any@6:17-25", "decl@5:5-26", "init@5:5-26", "ret@6:5-25")
}

// A taint sink holds when its focused argument, or an expression written in
// it, matches a source, or names a local whose last declaration before it
// initializes it with such a value.
func TestCMatchTaint(t *testing.T) {
	src := []string{
		"void f(int param) {",
		"    acme_init(h, ACME_ALG_256);",
		"    acme_init(h, &ACME_ALG_128);",
		"    const char *alias = ACME_ALG_512;",
		"    const char *name = alias;",
		"    acme_init(h, name);",
		"    acme_init(h, param);",
		"    acme_init(h, unknown);",
		"    acme_init(h, acme_md_sha256());",
		"}",
	}
	var calls []cSrcCall
	for i, l := range src {
		if j := strings.Index(l, "acme_init("); j >= 0 {
			calls = append(calls, cSrcCall{line: i + 1, text: strings.TrimSuffix(l[j:], ";")})
		}
	}
	frag := cSrcFrag(src, calls...)
	withCDecl(frag, 4, "alias")
	withCDecl(frag, 5, "name")
	found, _ := cMatchRules(t, map[string]string{
		"t": "mode: taint\npattern-sources:\n- patterns:\n  - pattern: $ALG\n  - metavariable-regex: {metavariable: $ALG, regex: '^ACME_ALG_(?<bits>\\d+)$'}\n" +
			"- pattern: acme_md_sha256()\npattern-sinks:\n- patterns:\n  - pattern: acme_init($H, $A)\n  - focus-metavariable: $A",
	}, frag)
	if got, want := cFound(found), []string{"t@2:18-30", "t@3:18-31", "t@6:18-22", "t@9:18-34"}; !slices.Equal(got, want) {
		t.Errorf("found\n got %v\nwant %v", got, want)
	}
	if len(found) > 0 && found[0].Metadata.Len() == 0 {
		t.Errorf("no metadata on %v", cFound(found))
	}
}

// A directive written in a function body is searched by a pattern-regex,
// but opens no `#include ...` range.
func TestCMatchLocalInclude(t *testing.T) {
	src := []string{
		"void f(void) {",
		"    #include <acme/seal.h>",
		"    acme_seal(k);",
		"}",
	}
	frag := cSrcFrag(src, cSrcCall{line: 3, text: "acme_seal(k)"})
	frag.Imports[cTestFile][0].Local = true
	checkCFound(t, map[string]string{
		"usage":  `pattern-regex: '#include\s+["<].*acme/.*[>"]'`,
		"inside": "patterns:\n- pattern-inside: |\n    #include <acme/seal.h>\n    ...\n- pattern: acme_seal(...)",
	}, frag, "usage@2:5-27")
}

// A string literal positive matches the fragment's literals, each piece of
// a concatenation on its own: the regex on its content binds and fills, and
// the finding is at the pattern-regex's match within it (inside the quotes
// of an unquoted regex, after a wide prefix).
func TestCMatchStringLiterals(t *testing.T) {
	src := []string{
		`static const struct alg algs[] = { { .name = "ACME-128" } };`,
		`int f(void) { return g(L"ACME-256", "x" "ACME-128", "ACME-512", "pre-ACME-128"); }`,
		`const char *h = "ACMEKEM768:other";`,
	}
	frag := cSrcFrag(src)
	frag.Strings = map[string][]graphfrag.GraphFragmentString{}
	for i, l := range src {
		for col := 0; col < len(l); {
			j := strings.IndexByte(l[col:], '"')
			if j < 0 {
				break
			}
			start := col + j
			if start > 0 && l[start-1] == 'L' {
				start--
			}
			end := col + j + 1 + strings.IndexByte(l[col+j+1:], '"') + 1
			frag.Strings[cTestFile] = append(frag.Strings[cTestFile], graphfrag.GraphFragmentString{
				Line: i + 1, StartCol: start + 1, EndCol: end + 1, Text: l[start:end],
			})
			col = end
		}
	}
	found, _ := cMatchRules(t, map[string]string{
		"q": "patterns:\n- pattern: '\"$ALGO\"'\n- metavariable-regex: {metavariable: $ALGO, regex: '^(?<v>ACME-(?<bits>128|256))$'}\n" +
			"- pattern-regex: '\"(?:ACME-128|ACME-256)\"'",
		"u": "patterns:\n- pattern: '\"$ALGO\"'\n- metavariable-regex: {metavariable: $ALGO, regex: '(?<v>ACMEKEM(?<bits>768))'}\n" +
			"- pattern-regex: 'ACMEKEM(?:768|1024)'",
		"plain": "patterns:\n- pattern: '\"$ALGO\"'\n- metavariable-regex: {metavariable: $ALGO, regex: '^ACME-512$'}",
	}, frag)
	want := []string{"plain@2:53-63", "q@1:46-56", "q@2:25-35", "q@2:41-51", "u@3:18-28"}
	if got := cFound(found); !slices.Equal(got, want) {
		t.Errorf("found\n got %v\nwant %v", got, want)
	}
}

// foldSpace folds whitespace as strings.Fields reads it, ASCII or not.
func TestFoldSpace(t *testing.T) {
	for _, text := range []string{
		"", " ", "a", "a b", "a  b", " a", "a ", "a\tb", "a\nb", "f(x, y)", "a b", "a\u0085b", "é b", "a \r\n b", "x\v", "\fx",
	} {
		if got, want := foldSpace(text), strings.Join(strings.Fields(text), " "); got != want {
			t.Errorf("foldSpace(%q) = %q, want %q", text, got, want)
		}
	}
}

// argsFit holds exactly when the argument counts let unifyArgs match: each
// argument but `...` takes one written argument.
func TestArgsFit(t *testing.T) {
	x, dots := CExpr{Kind: CExprMetavar, Var: "$X"}, CExpr{Kind: CExprEllipsis}
	m := &cMatcher{}
	for _, ps := range [][]CExpr{{}, {x}, {x, x}, {dots}, {x, dots}, {dots, x, dots}, {x, dots, x}} {
		for n := range 4 {
			ss := make([]CExpr, n)
			for i := range ss {
				ss[i] = CExpr{Kind: CExprIdent, Name: "a" + strings.Repeat("b", i)}
			}
			want := m.unifyArgs(ps, ss, &cRead{text: "abbb"}, cEnv{}, func(cEnv) bool { return true })
			if got := argsFit(ps, n); got != want {
				t.Errorf("argsFit(%d pattern args, %d) = %v, unifyArgs = %v", len(ps), n, got, want)
			}
		}
	}
}
