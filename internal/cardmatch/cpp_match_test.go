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
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

const cppTestFile = "src/acme.cpp"

// cppSite is a site of a C++ test fragment: the text reach spans (the
// call, the new expression, or the declaration from its type to its
// declarator), the anchor kind (call_expression when empty) and the
// constructed variable of a declaration.
type cppSite struct {
	line        int
	text        string
	kind        string
	assignedVar string
}

// cppSrcFrag is a C++ fragment over one file: every #include line is a
// directive and every `using ...;` line a using import (a function-body one,
// indented, is local).
func cppSrcFrag(src []string, sites ...cppSite) *FragmentJSON {
	frag := &FragmentJSON{
		SchemaVersion: "graph-fragment-1.38",
		Functions:     []FunctionJSON{{Key: "main", FilePath: cppTestFile}},
		SourceLines:   map[string]map[int]string{cppTestFile: {}},
		Imports:       map[string][]graphfrag.GraphFragmentImport{},
	}
	frag.ScanMetadata.Ecosystem = ecosystemCPP
	for i, l := range src {
		frag.SourceLines[cppTestFile][i+1] = l
		t := strings.TrimLeft(l, " ")
		col := len(l) - len(t) + 1
		switch {
		case strings.HasPrefix(t, "#include"):
			path := strings.TrimSpace(strings.TrimPrefix(t, "#include"))
			frag.Imports[cppTestFile] = append(frag.Imports[cppTestFile], graphfrag.GraphFragmentImport{
				Line: i + 1, Module: strings.Trim(path, `<>"`), StartCol: col, EndCol: len(l) + 1, EndLine: i + 1, Text: t,
			})
		case strings.HasPrefix(t, "using "):
			frag.Imports[cppTestFile] = append(frag.Imports[cppTestFile], graphfrag.GraphFragmentImport{
				Line: i + 1, StartCol: col, EndCol: len(l) + 1, EndLine: i + 1, Text: t, Local: col > 1,
			})
		}
	}
	for _, s := range sites {
		line := s.line
		col := strings.Index(src[line-1], s.text) + 1
		end := col + len(s.text)
		kind := s.kind
		if kind == "" {
			kind = "call_expression"
		}
		frag.ExternalCalls = append(frag.ExternalCalls, ExternalJSON{
			CallerKey: "main", Line: &line, StartCol: &col, EndCol: &end, Resolution: "exact", AssignedVar: s.assignedVar,
		})
		frag.Anchors = append(frag.Anchors, graphfrag.GraphFragmentCallAnchor{Line: line, StartCol: col, EndCol: end, Kind: kind})
	}
	return frag
}

// cppRuleYAML writes rules of languages [cpp], one per id.
func cppRuleYAML(rules map[string]string) string {
	return strings.ReplaceAll(cRuleYAML(rules), "languages: [c, cpp]", "languages: [cpp]")
}

func checkCPPFound(t *testing.T, rules map[string]string, frag *FragmentJSON, want ...string) {
	t.Helper()
	assets, err := Load("", "", writeRules(t, cppRuleYAML(rules)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	found, _ := matchCStats(assets, newFrag(frag))
	slices.Sort(want)
	if got := cFound(found); !slices.Equal(got, want) {
		t.Errorf("found\n got %v\nwant %v", got, want)
	}
}

// A qualified pattern matches the name written with its segments, or
// without a namespace a `using namespace` outside function bodies names
// (anywhere in the file), or a name a `using` declaration before it names.
// An unqualified pattern never matches a qualified name.
func TestCPPMatchQualifiedNames(t *testing.T) {
	src := []string{
		"void early() { auto a = Gizmo(1); }",
		"using namespace seal;",
		"using sub::Gizmo;",
		"void f() {",
		"    using namespace other;",
		"    auto b = seal::Params(seal::kind::bfv);",
		"    auto c = Params(kind::bfv);",
		"    auto d = ::Params(kind::bfv);",
		"    auto e = other::Params(kind::bfv);",
		"    auto g = Gizmo(2);",
		"    auto h = ::seal::Params(kind::bfv);",
		"}",
	}
	frag := cppSrcFrag(src,
		cppSite{line: 1, text: "Gizmo(1)"}, cppSite{line: 6, text: "seal::Params(seal::kind::bfv)"},
		cppSite{line: 7, text: "Params(kind::bfv)"}, cppSite{line: 8, text: "::Params(kind::bfv)"},
		cppSite{line: 9, text: "other::Params(kind::bfv)"}, cppSite{line: 10, text: "Gizmo(2)"},
		cppSite{line: 11, text: "::seal::Params(kind::bfv)"},
	)
	checkCPPFound(t, map[string]string{
		"qualified":   "pattern: seal::Params(seal::kind::bfv)",
		"unqualified": "pattern: Params(kind::bfv)",
		"other":       "pattern: other::Params(...)",
		"gizmo":       "pattern: sub::Gizmo(...)",
		"lead":        "pattern: $NS::Params(...)",
	}, frag,
		"qualified@6:14-43", "qualified@7:14-31", "qualified@8:14-33",
		"unqualified@7:14-31",
		"other@9:14-38",
		"gizmo@10:14-22",
		"lead@6:14-43", "lead@9:14-38",
	)
}

// `$X.m` matches `x.m`, `p->m` (binding `p->`) and `A::m` (binding A);
// `$X->m` matches `p->m` and `(*p).m`; a metavariable member name binds the
// name.
func TestCPPMatchMembers(t *testing.T) {
	src := []string{
		"void f() {",
		"    x.foo(1);",
		"    p->foo(2);",
		"    A::B::foo(3);",
		"    (*p).foo(4);",
		"    foo(5);",
		"    q.bar(6);",
		"}",
	}
	frag := cppSrcFrag(src,
		cppSite{line: 2, text: "x.foo(1)"}, cppSite{line: 3, text: "p->foo(2)"}, cppSite{line: 4, text: "A::B::foo(3)"},
		cppSite{line: 5, text: "(*p).foo(4)"}, cppSite{line: 6, text: "foo(5)"}, cppSite{line: 7, text: "q.bar(6)"},
	)
	checkCPPFound(t, map[string]string{
		"dot":       "pattern: $X.foo(...)",
		"arrow":     "pattern: $X->foo(...)",
		"deref":     "patterns:\n- pattern: $X.foo(...)\n- metavariable-regex: {metavariable: $X, regex: '^p->$'}",
		"qualifier": "patterns:\n- pattern: $X.foo(...)\n- metavariable-regex: {metavariable: $X, regex: '^A::B$'}",
		"name":      "patterns:\n- pattern: q.$M(...)\n- focus-metavariable: $M",
	}, frag,
		"dot@2:5-13", "dot@3:5-14", "dot@4:5-17", "dot@5:5-16",
		"arrow@3:5-14", "arrow@5:5-16",
		"deref@3:5-14", "qualifier@4:5-17", "name@7:7-10",
	)
}

// A template matches the template written with its arguments, never the
// name alone; a metavariable binds a qualified template callee as written.
func TestCPPMatchTemplates(t *testing.T) {
	src := []string{
		"void f() {",
		"    hmac<SHA256>(k, m);",
		"    hmac(k, m);",
		"    libsnark::gen<ppT>(cs);",
		"    a::b::init();",
		"}",
	}
	frag := cppSrcFrag(src,
		cppSite{line: 2, text: "hmac<SHA256>(k, m)"}, cppSite{line: 3, text: "hmac(k, m)"},
		cppSite{line: 4, text: "libsnark::gen<ppT>(cs)"}, cppSite{line: 5, text: "a::b::init()"},
	)
	checkCPPFound(t, map[string]string{
		"hmac":  "patterns:\n- pattern: hmac<$T>(...)\n- metavariable-regex: {metavariable: $T, regex: '^SHA256$'}",
		"plain": "pattern: hmac(...)",
		"gen":   "patterns:\n- pattern: $F(...)\n- metavariable-regex: {metavariable: $F, regex: '^libsnark::gen<.*>$'}",
		"init":  "patterns:\n- pattern: $C::init()\n- metavariable-regex: {metavariable: $C, regex: '^a::b$'}",
	}, frag, "hmac@2:5-23", "plain@3:5-15", "gen@4:5-27", "init@5:5-17")
}

// A declaration pattern matches a declaration of its declarator form only
// (`T $K(...)` with arguments that read as types is a function declarator,
// with a literal an init declarator), reported from its qualifiers to its
// `;`; `new T(...)` matches every construction expression, `new T` one
// without arguments; a declaration followed by `...` holds after it.
func TestCPPMatchConstructions(t *testing.T) {
	src := []string{
		"void f() {",
		"    const seal::KeyGen k1(ctx);",
		"    seal::KeyGen k2(\"x\", ctx);",
		"    seal::KeyGen k3;",
		"    seal::KeyGen a1(ctx), a2(ctx);",
		"    auto p = new seal::KeyGen(ctx);",
		"    auto q = new seal::KeyGen;",
		"    use(seal::KeyGen{ctx});",
		"    k1.create(pk);",
		"    k2.create(pk);",
		"}",
	}
	frag := cppSrcFrag(src,
		cppSite{line: 2, text: "seal::KeyGen k1(ctx)", kind: cppAnchorFunctionDecl, assignedVar: "k1"},
		cppSite{line: 3, text: `seal::KeyGen k2("x", ctx)`, kind: cppAnchorInitDecl, assignedVar: "k2"},
		cppSite{line: 4, text: "seal::KeyGen k3", kind: cppAnchorIdentifier, assignedVar: "k3"},
		cppSite{line: 5, text: "seal::KeyGen a1(ctx), a2(ctx)", kind: cppAnchorFunctionDecl, assignedVar: "a2"},
		cppSite{line: 6, text: "new seal::KeyGen(ctx)", kind: "new_expression"},
		cppSite{line: 7, text: "new seal::KeyGen", kind: "new_expression"},
		cppSite{line: 8, text: "use(seal::KeyGen{ctx})"},
		cppSite{line: 8, text: "seal::KeyGen{ctx}", kind: "compound_literal_expression"},
		cppSite{line: 9, text: "k1.create(pk)"}, cppSite{line: 10, text: "k2.create(pk)"},
	)
	checkCPPFound(t, map[string]string{
		"function": "pattern: seal::KeyGen $K(...);",
		"init":     "pattern: seal::KeyGen $K(\"...\", ...);",
		"bare":     "pattern: seal::KeyGen $K;",
		"new":      "pattern: new seal::KeyGen(...)",
		"new-bare": "pattern: new seal::KeyGen",
		"after":    "patterns:\n- pattern-inside: |\n    seal::KeyGen $R(...);\n    ...\n- pattern: $R.create(...)",
	}, frag,
		"function@2:5-32", "init@3:5-31", "bare@4:5-21",
		"new@6:14-35", "new@7:14-30", "new@8:9-26", "new-bare@7:14-30",
		"after@9:5-18",
	)
}

// A pattern-regex inside a construction context is searched in its lines
// and reported where it matches inside it, its named groups bound; a
// pattern-not-regex drops a match one of its matches holds or lies in.
func TestCPPMatchLineRegexes(t *testing.T) {
	src := []string{
		"#include <QCryptographicHash>",
		"void f() {",
		"    QByteArray a = QCryptographicHash::hash(d, QCryptographicHash::Sha256); QCryptographicHash::Sha512;",
		"    cc.KeyGen();",
		"    cc->KeyGen();",
		"}",
	}
	frag := cppSrcFrag(src,
		cppSite{line: 3, text: "QCryptographicHash::hash(d, QCryptographicHash::Sha256)"},
		cppSite{line: 4, text: "cc.KeyGen()"}, cppSite{line: 5, text: "cc->KeyGen()"},
	)
	assets, err := Load("", "", writeRules(t, cppRuleYAML(map[string]string{
		"hash": "patterns:\n- pattern-inside: |\n    #include \"$H\"\n    ...\n- pattern-inside: QCryptographicHash::hash(...)\n" +
			"- pattern-regex: '\\bQCryptographicHash::Sha(?<bits>\\d+)\\b'",
		"keygen": "patterns:\n- pattern: $CC.KeyGen()\n- pattern-not-regex: ->\\s*KeyGen",
	})), Options{})
	if err != nil {
		t.Fatal(err)
	}
	found, _ := matchCStats(assets, newFrag(frag))
	want := []string{"hash@3:48-74", "keygen@4:5-16"}
	if got := cFound(found); !slices.Equal(got, want) {
		t.Errorf("found\n got %v\nwant %v", got, want)
	}
}

// A pattern-regex with no construct context is searched in the lines of
// every call, construction and string literal: a match is reported where it
// lies wholly in one of them, never outside them or across one's end.
func TestCPPMatchSiteRegexes(t *testing.T) {
	src := []string{
		`#include <oqs_cpp.hpp>`,
		`void f() {`,
		`    oqs::Signature signer("ML-DSA-87");`,
		`    auto v = Proto::DTLS_V12;`,
		`    const char *name = "ML-DSA-65";`,
		`    sign(k, 2048); oqs::Signature x;`,
		`}`,
	}
	frag := cppSrcFrag(src,
		cppSite{line: 3, text: `oqs::Signature signer("ML-DSA-87")`, kind: cppAnchorInitDecl, assignedVar: "signer"},
		cppSite{line: 6, text: "sign(k, 2048)"},
	)
	frag.Strings = map[string][]graphfrag.GraphFragmentString{cppTestFile: {
		{Line: 3, StartCol: 27, EndCol: 38, Text: `"ML-DSA-87"`}, {Line: 5, StartCol: 24, EndCol: 35, Text: `"ML-DSA-65"`},
	}}
	checkCPPFound(t, map[string]string{
		"decl":    "patterns:\n- pattern-inside: |\n    #include \"$H\"\n    ...\n- pattern-regex: '\\boqs::Signature\\s*(?:\\w+\\s*)?[({]\\s*\"ML-DSA-(?<n>44|65|87)\"'",
		"literal": "pattern-regex: 'ML-DSA-\\d+'",
		"version": "pattern-regex: '\\bDTLS_V1\\d'",
		"across":  "pattern-regex: '2048\\); oqs'",
	}, frag, "decl@3:5-38", "literal@3:28-37", "literal@5:25-34")
}

// A typed metavariable reads a name's type from its latest declaration
// before it in the function (blocks are not scopes; a function declarator
// declares nothing), else from the parameter of that name; a typed
// parameter of a function context reads the parameters as written; `T $X =
// ...;` matches a declaration of one name with an initializer. Names in the
// types resolve through using directives. (Checked against OpenGrep 1.33.1.)
func TestCPPMatchDeclaredTypes(t *testing.T) {
	src := []string{
		"using namespace CryptoPP;",
		"void a(CryptoPP::SHA256 &pr, const SHA256 &cr, SHA256 v, SHA256 *pp) {",
		"  CryptoPP::SHA256 h1;",
		"  SHA256 h4(x);",
		"  SHA256 h5 = SHA256();",
		"  auto h6 = SHA256();",
		"  SHA256 *p1 = new SHA256;",
		"  SHA256 &r1 = h1;",
		"  h1.Update(1); h4.Update(4); h5.Update(5); h6.Update(6);",
		"  p1->Update(7); r1.Update(8);",
		"  pr.Update(10); cr.Update(11); v.Update(12); pp->Update(13);",
		"  { Other h1; h1.Update(14); }",
		"}",
	}
	var sites []cppSite
	for _, l := range []int{9, 10, 11, 12} {
		for _, call := range strings.Split(src[l-1], ";") {
			if i := strings.Index(call, "Update("); i > 0 {
				text := strings.TrimLeft(strings.TrimPrefix(strings.TrimSpace(call), "{"), " ")
				sites = append(sites, cppSite{line: l, text: text})
			}
		}
	}
	sites = append(sites, cppSite{line: 4, text: "SHA256 h4(x)", kind: cppAnchorFunctionDecl, assignedVar: "h4"})
	frag := cppSrcFrag(src, sites...)
	frag.Functions[0].Name = "a"
	decl := func(line int, text, typ, name, init string) graphfrag.GraphFragmentDeclaration {
		col := strings.Index(src[line-1], text) + 1
		return graphfrag.GraphFragmentDeclaration{Line: line, StartCol: col, EndCol: col + len(text), Type: typ, Name: name, Init: init}
	}
	frag.Declarations = []graphfrag.GraphFragmentDeclaration{
		decl(3, "CryptoPP::SHA256 h1;", "CryptoPP::SHA256", "h1", ""),
		decl(4, "SHA256 h4(x);", "SHA256", "h4", "call"),
		decl(5, "SHA256 h5 = SHA256();", "SHA256", "h5", "call"),
		decl(6, "auto h6 = SHA256();", "auto", "h6", "call"),
		decl(7, "SHA256 *p1 = new SHA256;", "SHA256*", "p1", "call"),
		decl(8, "SHA256 &r1 = h1;", "SHA256&", "r1", "other"),
		decl(12, "Other h1;", "Other", "h1", ""),
	}
	param := func(typ, name string) graphfrag.GraphFragmentWrittenParameter {
		col := strings.Index(src[1], typ) + 1
		return graphfrag.GraphFragmentWrittenParameter{Type: typ, Name: name, Line: 2, StartCol: col, EndCol: col + len(typ) + len(name)}
	}
	frag.Functions[0].WrittenParameters = []graphfrag.GraphFragmentWrittenParameter{
		param("CryptoPP::SHA256 &", "pr"), param("const SHA256 &", "cr"), param("SHA256", "v"), param("SHA256 *", "pp"),
	}
	checkCPPFound(t, map[string]string{
		"dot":    "pattern: (CryptoPP::SHA256 $H).Update(...)",
		"ptr":    "pattern: (CryptoPP::SHA256 *$P)->Update(...)",
		"cref":   "pattern: (const CryptoPP::SHA256& $H).Update(...)",
		"param":  "patterns:\n- pattern-inside: $RET $FN(..., CryptoPP::SHA256 &$R, ...) { ... }\n- pattern: $R.Update(...)",
		"assign": "pattern: CryptoPP::SHA256 $H = ...;",
	}, frag,
		"dot@9:3-15", "dot@9:31-43", "dot@11:33-45",
		"ptr@10:3-16", "ptr@11:47-61",
		"cref@11:18-31",
		"param@11:3-16", "param@11:18-31",
		"assign@5:3-24",
	)
}

// A using directive outside function bodies lets a qualified pattern match
// the unqualified name anywhere in the file; one in a function body does
// not count.
func TestCPPMatchUsingImports(t *testing.T) {
	src := []string{
		"void early() { auto a = SHA2Engine(); }",
		"void f() {",
		"    using namespace Local;",
		"    auto b = Thing();",
		"}",
		"using namespace Poco;",
	}
	frag := cppSrcFrag(src, cppSite{line: 1, text: "SHA2Engine()"}, cppSite{line: 4, text: "Thing()"})
	checkCPPFound(t, map[string]string{
		"poco":  "pattern: Poco::SHA2Engine()",
		"local": "pattern: Local::Thing()",
	}, frag, "poco@1:25-37")
}

// The matches of a site regex are kept while an entry still searches it and
// dropped after the last one, so a scan holds no regex's matches past its
// use. Two entries share one regex here; both still find it.
func TestCPPSiteRegexMatchesDropped(t *testing.T) {
	src := []string{
		`void f() {`,
		`    sign(k, "ML-DSA-65");`,
		`}`,
	}
	frag := cppSrcFrag(src, cppSite{line: 2, text: `sign(k, "ML-DSA-65")`})
	assets, err := Load("", "", writeRules(t, cppRuleYAML(map[string]string{
		"first":  "pattern-regex: 'ML-DSA-\\d+'",
		"second": "pattern-regex: 'ML-DSA-\\d+'",
		"other":  "patterns:\n- pattern: sign(...)\n- pattern-not-regex: 'RSA'",
	})), Options{})
	if err != nil {
		t.Fatal(err)
	}
	m := newCMatcher(newFrag(frag))
	m.matchEntries(assets)
	want := []string{"first@2:14-23", "other@2:5-25", "second@2:14-23"}
	if got := cFound(m.found); !slices.Equal(got, want) {
		t.Errorf("found\n got %v\nwant %v", got, want)
	}
	if len(m.rxMatches) != 0 {
		t.Errorf("site regex matches kept after the last entry: %v", slices.Collect(maps.Keys(m.rxMatches)))
	}
}

// An entry a hand card replaces is skipped, so it never searches its regex.
// When the last entry naming a regex is such an entry, the matches are still
// dropped after the last entry that does search it.
func TestCPPSiteRegexMatchesDroppedWhenLastUserSkipped(t *testing.T) {
	src := []string{
		`void f() {`,
		`    sign(k, "ML-DSA-65");`,
		`}`,
	}
	frag := cppSrcFrag(src, cppSite{line: 2, text: `sign(k, "ML-DSA-65")`})
	assets, err := Load("", "", writeRules(t, cppRuleYAML(map[string]string{
		"first":  "pattern-regex: 'ML-DSA-\\d+'",
		"second": "pattern-regex: 'ML-DSA-\\d+'",
	})), Options{})
	if err != nil {
		t.Fatal(err)
	}
	last := -1
	for i, e := range assets.index.Entries {
		if e.C != nil && len(e.C.siteRegexes()) > 0 {
			last = i
		}
	}
	if last < 0 {
		t.Fatal("no entry searches a site regex")
	}
	skipped := assets.index.Entries[last].RuleID
	assets.cards.RuleIDs[skipped] = true
	m := newCMatcher(newFrag(frag))
	m.matchEntries(assets)
	if len(m.found) != 1 || m.found[0].RuleID == skipped {
		t.Errorf("found %v, want the one entry not replaced by a hand card", cFound(m.found))
	}
	if len(m.rxMatches) != 0 {
		t.Errorf("site regex matches kept after the last entry that searched them: %v", slices.Collect(maps.Keys(m.rxMatches)))
	}
}
