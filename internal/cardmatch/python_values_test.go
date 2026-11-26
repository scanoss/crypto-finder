// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

func pyRef(line, col int, text, context string, operand *graphfrag.GraphFragmentParameter) graphfrag.GraphFragmentConstantRef {
	return graphfrag.GraphFragmentConstantRef{Line: line, StartCol: col, EndCol: col + len(text), Text: text, Context: context, Operand: operand}
}

func valueOperand(text string, values ...string) *graphfrag.GraphFragmentParameter {
	op := &graphfrag.GraphFragmentParameter{ArgumentExpression: text}
	for _, v := range values {
		op.SourceNodes = append(op.SourceNodes, graphfrag.GraphFragmentSourceNode{Type: "VALUE", Value: v})
	}
	return op
}

func pyConstantsFrag() *FragmentJSON {
	frag := pyFrag([]graphfrag.GraphFragmentImport{
		{Line: 1, Module: "ssl"},
		{Line: 2, Module: "cryptography.hazmat.primitives.ciphers", Name: "algorithms"},
		{Line: 3, Module: "cryptography.x509.oid", Name: "NameOID"},
		{Line: 4, Module: "fake_ssl", Alias: "tls"},
		{Line: 5, Module: "cryptography.hazmat.primitives", Name: "hashes"},
	},
		withSpan(pyCall("ssl.SSLContext", "ssl.SSLContext", 10, pos(0, "ssl.PROTOCOL_TLSv1")), 9, 40),
		withSpan(pyCall("app.main.use", "use", 11, pos(0, "ssl.PROTOCOL_TLSv1")), 9, 30),
	)
	frag.SchemaVersion = "graph-fragment-1.24"
	frag.ConstantRefs = []graphfrag.GraphFragmentConstantRef{
		pyRef(10, 24, "ssl.PROTOCOL_TLSv1", "arg", nil),
		pyRef(11, 13, "ssl.PROTOCOL_TLSv1", "arg", nil),
		pyRef(12, 9, "tls.PROTOCOL_TLSv1", "assign", nil),
		pyRef(13, 13, "NameOID.COMMON_NAME", "arg", nil),
		pyRef(14, 13, "algorithms.AES", "dict", valueOperand(`'aes'`, `'aes'`)),
		pyRef(15, 13, "hashes.SHA256", "in", valueOperand("alg", "hashes.SHA256")),
		pyRef(15, 28, "hashes.SHA384", "in", valueOperand("alg", "hashes.SHA256")),
		pyRef(16, 9, "hashes.SHA512", "array", nil),
		pyRef(17, 9, "oid.NameOID.COMMON_NAME", "arg", nil),
		pyRef(18, 9, "NameOID.ORGANIZATION_NAME", "arg", nil),
	}
	return frag
}

func pyConstantFindings(t *testing.T, membership ComparisonPolicy) []string {
	t.Helper()
	cards := cardsFrom(t, `
- rule: tlsv1
  constant: {const: ssl.PROTOCOL_TLSv1}
- rule: oid
  constant: {const: cryptography.x509.oid.NameOID, member: '^(?<name>COMMON_NAME)$'}
- rule: cipher
  constant: {const: cryptography.hazmat.primitives.ciphers.algorithms, member: '^(?<name>AES)$'}
- rule: hash
  constant: {const: cryptography.hazmat.primitives.hashes, member: '^(?<name>SHA\d+)$'}
- rule: suffix
  constant: {const: x509.oid.NameOID.COMMON_NAME}
`)
	cards[0].NotIn = []any{&OMap{Keys: []any{"call"}, Vals: []any{"ssl.SSLContext"}}}
	fr := newFrag(pyConstantsFrag())
	fr.Membership = membership
	return ruleLines(matchCards(cards, fr))
}

// Python constant references: qualified through the file's imports and
// compared exactly; an `in` operand reads as a comparison by default, a dict
// entry is a table entry, always reported.
func TestPythonConstantRefs(t *testing.T) {
	want := []string{
		`cipher@14 {"algorithmName": "AES"}`,
		`hash@15 {"algorithmName": "SHA256"}`,
		`hash@16 {"algorithmName": "SHA512"}`,
		`oid@13 {"algorithmName": "COMMON_NAME"}`,
		`tlsv1@11 {}`,
	}
	if got := pyConstantFindings(t, ComparisonsResolved); !reflect.DeepEqual(got, want) {
		t.Errorf("resolved\n got %v\nwant %v", got, want)
	}
	want = []string{
		`cipher@14 {"algorithmName": "AES"}`,
		`hash@15 {"algorithmName": "SHA256"}`,
		`hash@15 {"algorithmName": "SHA384"}`,
		`hash@16 {"algorithmName": "SHA512"}`,
		`oid@13 {"algorithmName": "COMMON_NAME"}`,
		`tlsv1@11 {}`,
	}
	if got := pyConstantFindings(t, ComparisonsAll); !reflect.DeepEqual(got, want) {
		t.Errorf("all\n got %v\nwant %v", got, want)
	}
}

// The membership switch reads only Python fragments: a Java fragment's
// position kinds keep their reading.
func TestMembershipIsPythonOnly(t *testing.T) {
	fr := newFrag(&FragmentJSON{})
	if fr.comparisonRef("in") || fr.comparisonRef("dict") || !fr.comparisonRef("compare") {
		t.Error("a Java fragment reads in / dict as comparisons")
	}
	py := newFrag(pyFrag(nil))
	if !py.comparisonRef("in") || py.comparisonRef("dict") || py.comparisonRef("array") || py.comparisonRef("arg") {
		t.Error("a Python fragment does not read in (only) as a comparison")
	}
}

// Declarations, assigned types and casts of a Python fragment: type names
// qualified through the imports, compared exactly.
func TestPythonDeclarationsAndCasts(t *testing.T) {
	frag := pyFrag([]graphfrag.GraphFragmentImport{
		{Line: 1, Module: "cryptography.hazmat.primitives.asymmetric", Name: "rsa"},
		{Line: 2, Module: "cryptography.hazmat.primitives", Name: "serialization"},
	},
		withAssigned(withSpan(pyCall("cryptography.hazmat.primitives.serialization.load_pem_private_key",
			"serialization.load_pem_private_key", 5, pos(0, "data"), pos(1, "None")), 30, 80), "k"),
		withSpan(pyCall("cryptography.hazmat.primitives.serialization.load_pem_public_key",
			"serialization.load_pem_public_key", 6, pos(0, "data")), 35, 75),
	)
	frag.SchemaVersion = "graph-fragment-1.24"
	frag.Declarations = []graphfrag.GraphFragmentDeclaration{
		{Function: 0, Line: 5, StartCol: 5, EndCol: 80, Type: "rsa.RSAPrivateKey", Name: "k", Init: "call"},
		{Function: 0, Line: 7, StartCol: 5, EndCol: 40, Type: "RSAPublicKey", Name: "p", Init: "other"},
	}
	frag.Casts = []graphfrag.GraphFragmentCast{{Function: 0, Line: 6, StartCol: 11, EndCol: 76, Type: "rsa.RSAPublicKey", InnerLine: 6, InnerCol: 35}}
	cards := cardsFrom(t, `
- rule: decl
  declaration: {type: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey}
- rule: decl-suffix
  declaration: {type: [RSAPrivateKey, rsa.RSAPublicKey, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey]}
- rule: assigned-short
  match: {call: cryptography.hazmat.primitives.serialization.load_pem_private_key, assigned_type: RSAPrivateKey}
- rule: assigned
  match: {call: cryptography.hazmat.primitives.serialization.load_pem_private_key, assigned_type: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey}
- rule: cast
  match: {call: cryptography.hazmat.primitives.serialization.load_pem_public_key, cast: cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey}
- rule: cast-short
  match: {call: cryptography.hazmat.primitives.serialization.load_pem_public_key, cast: RSAPublicKey}
`)
	want := []string{`assigned@5 {}`, `cast@6 {}`, `decl@5 {}`}
	if got := ruleLines(matchCards(cards, newFrag(frag))); !reflect.DeepEqual(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
}

func pyStore(fn, line int, recv, attr, op string, value graphfrag.GraphFragmentParameter) graphfrag.GraphFragmentAttributeStore {
	return graphfrag.GraphFragmentAttributeStore{
		Function: fn, Line: line, StartCol: 5, EndCol: 40, Receiver: recv, Attribute: attr,
		Operator: op, Value: value,
	}
}

// Store cards: an attribute assignment, by attribute, operator, receiver
// (here a local assigned from an SSL context factory) and value.
func TestStoreCards(t *testing.T) {
	frag := pyFrag([]graphfrag.GraphFragmentImport{{Line: 1, Module: "ssl"}, {Line: 2, Module: "ssl", Name: "CERT_NONE", Alias: "NONE"}},
		withAssigned(pyCall("ssl.create_default_context", "ssl.create_default_context", 5), "ctx"),
		withAssigned(pyCall("app.main.make", "make", 9), "other"),
	)
	frag.AttributeStores = []graphfrag.GraphFragmentAttributeStore{
		pyStore(0, 6, "ctx", "verify_mode", "=", graphfrag.GraphFragmentParameter{ArgumentExpression: "ssl.CERT_NONE"}),
		pyStore(0, 7, "ctx", "check_hostname", "=", graphfrag.GraphFragmentParameter{
			ArgumentExpression: "False",
			SourceNodes:        []graphfrag.GraphFragmentSourceNode{{Type: "VALUE", Value: "False"}},
		}),
		pyStore(0, 8, "ctx", "options", "|=", graphfrag.GraphFragmentParameter{ArgumentExpression: "ssl.OP_NO_TLSv1"}),
		pyStore(0, 10, "other", "verify_mode", "=", graphfrag.GraphFragmentParameter{ArgumentExpression: "ssl.CERT_NONE"}),
		pyStore(0, 11, "ctx", "verify_mode", "=", graphfrag.GraphFragmentParameter{ArgumentExpression: "NONE"}),
		pyStore(0, 12, "ctx", "minimum_version", "=", graphfrag.GraphFragmentParameter{ArgumentExpression: "'TLSv1'"}),
		pyStore(0, 13, "ctx", "options", "=", graphfrag.GraphFragmentParameter{ArgumentExpression: "ssl.OP_NO_TLSv1"}),
		pyStore(0, 14, "ctx", "options", "|=", graphfrag.GraphFragmentParameter{ArgumentExpression: "flags"}),
		pyStore(0, 3, "early", "options", "=", graphfrag.GraphFragmentParameter{ArgumentExpression: "0"}),
		pyStore(5, 15, "ctx", "verify_mode", "=", graphfrag.GraphFragmentParameter{ArgumentExpression: "ssl.CERT_NONE"}),
	}
	cards := cardsFrom(t, `
- rule: verify-none
  store: {attribute: verify_mode, receiver: {via: var, from: {call: [ssl.SSLContext, ssl.create_default_context]}}, value: {const: ssl.CERT_NONE}}
- rule: hostname
  store: {attribute: [check_hostname], value: {literal: "False"}}
- rule: options
  store: {attribute: options, operator: "|=", value: {const: ssl, member: '^OP_NO_(?<name>\w+)$'}}
- rule: minimum
  store: {attribute: minimum_version, value: {string: true, bind: name}}
- rule: with-context
  store: {attribute: options}
  with: [{call: ssl.create_default_context, when: before}]
`)
	want := []string{
		`hostname@7 {}`,
		`minimum@12 {"algorithmName": "TLSv1"}`,
		`options@8 {"algorithmName": "TLSv1"}`,
		`verify-none@11 {}`,
		`verify-none@6 {}`,
		`with-context@13 {}`,
		`with-context@14 {}`,
		`with-context@8 {}`,
	}
	got := ruleLines(matchCards(cards, newFrag(frag)))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n got %v\nwant %v", got, want)
	}
}

func TestLoadStoreCards(t *testing.T) {
	rules := t.TempDir()
	if err := os.WriteFile(filepath.Join(rules, "rules.yaml"), []byte("rules:\n- id: store\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for body, wantErr := range map[string]bool{
		`store: {attribute: verify_mode, value: {const: ssl.CERT_NONE}}`:         false,
		`store: {value: {const: ssl.CERT_NONE}}`:                                 true,
		`store: {attribute: verify_mode, type: ssl.SSLContext}`:                  true,
		"store: {attribute: verify_mode}\n  match: {method: wrap_socket}":        true,
		"store: {attribute: verify_mode}\n  declaration: {type: ssl.SSLContext}": true,
		"store: {attribute: verify_mode}\n  constant: {const: ssl.CERT_NONE}":    true,
	} {
		cards := t.TempDir()
		if err := os.WriteFile(filepath.Join(cards, "rules.cards"), []byte("cards:\n- rule: store\n  "+body+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		set, err := defaults.loadCards(cards, rules)
		if (err != nil) != wantErr {
			t.Errorf("%q: error %v, want error %v", body, err, wantErr)
		}
		if err == nil && (len(set.Cards) != 1 || set.Cards[0].Store == nil || !strings.Contains(jsonValue(set.Cards[0].Store), "verify_mode")) {
			t.Errorf("%q: cards %+v, want one store card", body, set.Cards)
		}
	}
}

// Assets.Match applies Options.PyMembership.
func TestMatchMembershipSwitch(t *testing.T) {
	cards := cardsFrom(t, `
- rule: hash
  constant: {const: cryptography.hazmat.primitives.hashes, member: '^(?<name>SHA384)$'}
`)
	assets := &Assets{index: &Index{}, cards: &CardSet{Cards: cards, RuleIDs: map[string]bool{"hash": true}}}
	run := func(policy ComparisonPolicy) int {
		assets.opts = Options{PyMembership: policy}.settings()
		found, _ := assets.mustMatch(t, pyConstantsFrag())
		return len(found)
	}
	if n := run(""); n != 0 {
		t.Errorf("default: %d findings, want 0 (an `in` operand that cannot be the constant reads as a comparison)", n)
	}
	if n := run(ComparisonsAll); n != 1 {
		t.Errorf("all: %d findings, want 1", n)
	}
}

// A constant card's `at` restricts the position kinds it reports: a rule
// written for algorithm tables reports a dict or list entry, not the same
// constant passed to a call or compared.
func TestConstantCardPositions(t *testing.T) {
	cards := cardsFrom(t, `
- rule: table
  constant: {const: cryptography.hazmat.primitives.hashes, member: '^(?<name>SHA\d+)$', at: [dict, array]}
- rule: dict-only
  constant: {const: cryptography.hazmat.primitives.ciphers.algorithms, member: '^(?<name>AES)$', at: dict}
- rule: arg-only
  constant: {const: ssl.PROTOCOL_TLSv1, at: [arg]}
- rule: in-only
  constant: {const: cryptography.hazmat.primitives.hashes, member: '^(?<name>SHA\d+)$', at: [in]}
`)
	fr := newFrag(pyConstantsFrag())
	fr.Membership = ComparisonsAll
	got := ruleLines(matchCards(cards, fr))
	want := []string{
		`arg-only@10 {}`,
		`arg-only@11 {}`,
		`dict-only@14 {"algorithmName": "AES"}`,
		`in-only@15 {"algorithmName": "SHA256"}`,
		`in-only@15 {"algorithmName": "SHA384"}`,
		`table@16 {"algorithmName": "SHA512"}`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
}

// A constant card's keys are checked: `at` is one, a misspelled key or a
// card without `const` is an error.
func TestConstantCardKeys(t *testing.T) {
	rules := t.TempDir()
	if err := os.WriteFile(filepath.Join(rules, "rules.yaml"), []byte("rules:\n- id: c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for body, wantErr := range map[string]bool{
		"{const: ssl.PROTOCOL_TLSv1, at: [dict]}":    false,
		"{const: ssl.PROTOCOL_TLSv1, where: [dict]}": true,
		"{member: '^X$'}":                            true,
	} {
		cards := t.TempDir()
		if err := os.WriteFile(filepath.Join(cards, "rules.cards"), []byte("cards:\n- rule: c\n  constant: "+body+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := defaults.loadCards(cards, rules); (err != nil) != wantErr {
			t.Errorf("%s: error %v, want error %v", body, err, wantErr)
		}
	}
}

// A constant passed to a call of a fragment without references of its own
// (before graph-fragment-1.17) is at "arg".
func TestConstantCardArgPosition(t *testing.T) {
	cards := cardsFrom(t, `
- rule: as-arg
  constant: {const: AlgorithmIdentifiers, member: '^RSA_USING_SHA(?<name>256)$', at: [arg, array]}
- rule: table
  constant: {const: AlgorithmIdentifiers, member: '^RSA_USING_SHA(?<name>256)$', at: dict}
`)
	got := ruleLines(matchCards(cards, tinyFrag()))
	if want := []string{`as-arg@8 {"algorithmName": "256"}`}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// A constant card's not_in naming a builtin (no call in the fragment) reads
// the reference's source line.
func TestConstantCardNotInBuiltin(t *testing.T) {
	cards := cardsFrom(t, `
- rule: table
  constant: {const: cryptography.hazmat.primitives.hashes, member: '^(?<name>SHA\d+)$', at: [array]}
`)
	cards[0].NotIn = []any{&OMap{Keys: []any{"call"}, Vals: []any{"issubclass"}}}
	frag := pyConstantsFrag()
	frag.ConstantRefs[7].StartCol = 16 // hashes.SHA512 on line 16
	frag.SourceLines = map[string]map[int]string{"app/main.py": {16: "    issubclass(hashes.SHA512, x)"}}
	if got := ruleLines(matchCards(cards, newFrag(frag))); len(got) != 0 {
		t.Errorf("got %v, want nothing", got)
	}
	frag.SourceLines["app/main.py"][16] = "    a(x) or (hashes.SHA512, issubclass)"
	if got := ruleLines(matchCards(cards, newFrag(frag))); len(got) != 1 {
		t.Errorf("got %v, want the table entry", got)
	}
}

// A parameter's values are the arguments its same-file callers pass for it:
// the keyword argument of its name, wherever it is written, else the
// positional argument at its index. A keyword-only parameter (index -1) is
// read by name alone; a `*args` spread at or before the position, a keyword
// argument of another name standing there and a missing argument give none.
// An edge that records no argument (a class instantiation's edge to
// __init__) reads those of the call written at its position.
func TestPythonCallerArguments(t *testing.T) {
	index := func(i int) *int { return &i }
	call := func(caller string, line int, name string, idx int) ExternalJSON {
		ln, col, end := line, 5, 40
		return ExternalJSON{
			CallerKey: caller, TargetKey: "hashlib.new", Raw: "hashlib.new", Line: &ln, Resolution: "exact",
			StartCol: &col, EndCol: &end, EntryCall: &CallSiteJSON{Parameters: []Param{
				{ParameterIndex: 0, ArgumentExpression: name, SourceNodes: []SourceNode{{Type: "PARAMETER", Name: name, ParameterIndex: index(idx)}}},
			}},
		}
	}
	edge := func(caller, callee, line int, params ...Param) CompactEdge {
		return CompactEdge{N: [13]int{caller, callee, line, 1, 0, 2, len(params), 0, 0, 0, 5, 40}, Entry: &CallSiteJSON{Parameters: params}}
	}
	lit := func(i int, text string) Param {
		return Param{ParameterIndex: i, ArgumentExpression: text, ResolvedValue: text}
	}
	kwLit := func(i int, name, text string) Param {
		return Param{ParameterIndex: i, Keyword: name, ArgumentExpression: text, ResolvedValue: text}
	}
	frag := &FragmentJSON{
		Functions: []FunctionJSON{
			{Key: "app.m.by_position", Package: "app.m", FilePath: "app/m.py"},
			{Key: "app.m.keyword_only", Package: "app.m", FilePath: "app/m.py"},
			{Key: "app.m.(C).method", Package: "app.m", FilePath: "app/m.py"},
			{Key: "app.m.callers", Package: "app.m", FilePath: "app/m.py"},
			{Key: "app.m.(C).<init>", Package: "app.m", FilePath: "app/m.py"},
		},
		InternalEdgeStrings: []string{"", "exact", "f"},
		InternalEdges: []CompactEdge{
			edge(3, 0, 20, lit(0, `b"x"`), lit(1, `'md5'`)),
			edge(3, 0, 21, lit(0, `b"x"`), kwLit(1, "name", `'sha1'`)),
			edge(3, 0, 22, kwLit(0, "name", `"sha224"`), kwLit(1, "data", `b"x"`)),
			edge(3, 0, 23, lit(0, `b"x"`), kwLit(1, "other", `"sha256"`)),
			edge(3, 0, 24, lit(0, `*args`), lit(1, `"sha384"`)),
			edge(3, 0, 25, lit(0, `b"x"`)),
			edge(3, 1, 30, lit(0, `"sha512"`)),
			edge(3, 1, 31, kwLit(0, "name", `"sha3_256"`)),
			edge(3, 2, 40, lit(0, `"blake2b"`)),
			// An instantiation: the edge to <init> records no argument, the
			// call `app.m.C` written at its position does. An edge elsewhere
			// on the line borrows none.
			edge(3, 4, 50),
			{N: [13]int{3, 4, 50, 1, 0, 2, 0, 0, 0, 0, 45, 60}},
		},
		ExternalCalls: []ExternalJSON{
			call("app.m.by_position", 5, "name", 1),
			call("app.m.keyword_only", 9, "name", -1),
			call("app.m.(C).method", 13, "name", 0),
			call("app.m.(C).<init>", 17, "name", 0),
			{
				CallerKey: "app.m.callers", TargetKey: "app.m.C", Raw: "C", Line: index(50), Resolution: "exact", StartCol: index(5),
				EndCol: index(40), EntryCall: &CallSiteJSON{Parameters: []Param{lit(0, `"blake2s"`)}},
			},
			{
				CallerKey: "app.m.callers", TargetKey: "app.m.C", Raw: "C", Line: index(50), Resolution: "exact", StartCol: index(45),
				EndCol: index(61), EntryCall: &CallSiteJSON{Parameters: []Param{lit(0, `"sha512"`)}},
			},
		},
	}
	frag.ScanMetadata.Ecosystem = "python"
	// One card per value: a card reports a call once.
	text := ""
	for _, name := range []string{"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "blake2b", "blake2s"} {
		text += "- rule: " + name + "\n  match: {call: hashlib.new, args: {0: {taint: '\"" + name + "\"'}}}\n"
	}
	fr := newFrag(frag)
	fr.ResolveParams = true
	found := matchCards(cardsFrom(t, text), fr)
	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, strconv.Itoa(f.Line)+" "+f.RuleID)
	}
	sort.Strings(got)
	want := []string{"13 blake2b", "17 blake2s", "5 md5", "5 sha1", "5 sha224", "9 sha3_256"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
}

// An argument whose value the graph knows for certain reads as that value:
// a subscript the graph resolved (a dispatch table read whose key selects
// one entry), and a name whose source is a VARIABLE of that name holding
// only fixed values (a literal, a constant, a resolved table read, a str
// enum member). A card on the value matches it, qualified through the
// file's imports, and a card on anything else does not. A name that may
// hold one of a few literals and nothing else reads as each of them (one
// finding per value). An unresolved subscript, a name with a resolved value
// but no such source, a parameter, a name that may hold something else and
// any other resolved expression read as written.
func TestPythonResolvedSubscript(t *testing.T) {
	resolved := func(i int, text, value string, nodes ...SourceNode) Param {
		return Param{ParameterIndex: i, ArgumentExpression: text, ResolvedValue: value, SourceNodes: nodes}
	}
	value := func(v string) SourceNode { return SourceNode{Type: "VALUE", Value: v} }
	variable := func(name string, nodes ...SourceNode) SourceNode {
		return SourceNode{Type: "VARIABLE", Name: name, SourceNodes: nodes}
	}
	may := func(name string, exhaustive bool, values ...string) SourceNode {
		return SourceNode{Type: "VARIABLE", Name: name, MayValues: values, MayValuesExhaustive: exhaustive}
	}
	zero := 0
	frag := pyFrag([]graphfrag.GraphFragmentImport{{Line: 1, Module: "hashlib"}, {Line: 2, Module: "hashlib", Name: "sha1"}},
		pyCall("hmac.new", "hmac.new", 10, pos(0, "k"), pos(1, "m"), resolved(2, `TABLE["HS512"]`, "hashlib.sha512")),
		pyCall("hmac.new", "hmac.new", 11, pos(0, "k"), pos(1, "m"), pos(2, `TABLE[alg]`)),
		pyCall("hmac.new", "hmac.new", 12, pos(0, "k"), pos(1, "m"), resolved(2, `TABLE['HS1']`, "sha1")),
		pyCall("hmac.new", "hmac.new", 13, pos(0, "k"), pos(1, "m"), resolved(2, `NAMES[key]`, `'sha256'`)),
		pyCall("hmac.new", "hmac.new", 14, pos(0, "k"), pos(1, "m"), resolved(2, `digest`, "hashlib.sha512")),
		pyCall("hmac.new", "hmac.new", 15, pos(0, "k"), pos(1, "m"), resolved(2, `alg`, `"sha256"`)),
		pyCall("hmac.new", "hmac.new", 16, pos(0, "k"), pos(1, "m"), resolved(2, `pick(d)`, "hashlib.sha512")),
		pyCall("hmac.new", "hmac.new", 17, pos(0, "k"), pos(1, "m"), resolved(2, `size`, "256")),
		pyCall("hmac.new", "hmac.new", 18, pos(0, "k"), pos(1, "m"), resolved(2, `alg`, `'sha384'`, variable("alg", value(`'sha384'`)))),
		pyCall("hmac.new", "hmac.new", 19, pos(0, "k"), pos(1, "m"), resolved(2, `digest`, "hashlib.sha512", variable("digest", value("hashlib.sha512")))),
		pyCall("hmac.new", "hmac.new", 20, pos(0, "k"), pos(1, "m"), resolved(2, `alg`, `"sha256"`,
			SourceNode{Type: "PARAMETER", Name: "alg", ParameterIndex: &zero, SourceNodes: []SourceNode{value(`"sha256"`)}})),
		pyCall("hmac.new", "hmac.new", 21, pos(0, "k"), pos(1, "m"), resolved(2, `digest`, "hashlib.sha512",
			variable("digest", variable(`TABLE["HS512"]`, value("hashlib.sha512"))))),
		pyCall("hmac.new", "hmac.new", 22, pos(0, "k"), pos(1, "m"), resolved(2, `alg`, "", may("alg", true, `'sha256'`, `"sha512"`))),
		pyCall("hmac.new", "hmac.new", 23, pos(0, "k"), pos(1, "m"), resolved(2, `alg`, "", may("alg", false, `"sha256"`, `"sha512"`))),
		pyCall("hmac.new", "hmac.new", 24, pos(0, "k"), pos(1, "m"), resolved(2, `alg`, "", variable("alg", value(`"sha256"`), SourceNode{Type: "CALL_RESULT"}))),
		pyCall("hmac.new", "hmac.new", 25, pos(0, "k"), pos(1, "m"), resolved(2, `other`, `"sha256"`, variable("alg", value(`"sha256"`)))),
		pyCall("hmac.new", "hmac.new", 26, pos(0, "k"), pos(1, "m"), resolved(2, `h`, "", variable("h", value("hashlib.sha256"), value("sha1")))),
	)
	cards := cardsFrom(t, `
- rule: sha2
  match: {call: hmac.new, args: {2: {regex: '^hashlib\.sha(?<name>256|512)$'}}}
- rule: sha1
  match: {call: hmac.new, args: {2: {const: hashlib.sha1}}}
- rule: name
  match: {call: hmac.new, args: {2: {regex: '^"sha(?<name>\d+)"$'}}}
- rule: dynamic
  match: {call: hmac.new, args: {2: {regex: '^(?!["'']|hashlib\.|sha1$)'}}}
`)
	want := []string{
		`dynamic@11 {}`, `dynamic@14 {}`, `dynamic@15 {}`, `dynamic@16 {}`, `dynamic@17 {}`,
		`dynamic@20 {}`, `dynamic@23 {}`, `dynamic@24 {}`, `dynamic@25 {}`,
		`name@13 {"algorithmName": "256"}`,
		`name@18 {"algorithmName": "384"}`,
		`name@22 {"algorithmName": "256"}`, `name@22 {"algorithmName": "512"}`,
		`sha1@12 {}`, `sha1@26 {}`,
		`sha2@10 {"algorithmName": "512"}`,
		`sha2@19 {"algorithmName": "512"}`,
		`sha2@21 {"algorithmName": "512"}`,
		`sha2@26 {"algorithmName": "256"}`,
	}
	if got := ruleLines(dropRepeats(matchCards(cards, newFrag(frag)))); !reflect.DeepEqual(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
	// A rule that does not read the argument the readings differ in finds
	// the call once.
	variants := pyFrag(nil, pyCall("hmac.new", "hmac.new", 30, pos(0, "k"), pos(1, "m"), resolved(2, `alg`, "", may("alg", true, `"sha256"`, `"sha512"`))))
	key := cardsFrom(t, `
- rule: key
  match: {call: hmac.new, args: {0: {regex: '^k$'}}}
`)
	if got, want := ruleLines(dropRepeats(matchCards(key, newFrag(variants)))), []string{`key@30 {}`}; !reflect.DeepEqual(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
	// The compiled entries read the value's qualified text.
	p := pyParam(resolved(2, `TABLE['HS1']`, "sha1"), map[string]string{"sha1": "hashlib.sha1"})
	if p.ArgumentExpression != "sha1" || p.Qualified != "hashlib.sha1" {
		t.Errorf("resolved subscript reads %q, qualified %q", p.ArgumentExpression, p.Qualified)
	}
}
