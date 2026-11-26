// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

func TestPyCallee(t *testing.T) {
	cases := []struct{ key, cls, method string }{
		{"cryptography.fernet.(Fernet).encrypt", "cryptography.fernet.Fernet", "encrypt"},
		{"cryptography.hazmat.primitives.ciphers.(Cipher).<init>", "cryptography.hazmat.primitives.ciphers", "Cipher"},
		{"app.mod.(Outer.Inner).run", "app.mod.Outer.Inner", "run"},
		{"hashlib.pbkdf2_hmac", "hashlib", "pbkdf2_hmac"},
		{"loader", "", "loader"},
		{
			"cryptography.hazmat.primitives.asymmetric.mlkem.(MLKEM1024PublicKey).encapsulate#-1",
			"cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PublicKey", "encapsulate",
		},
		{"_hashlib.(HASH).hexdigest#2", "_hashlib.HASH", "hexdigest"},
		{"app.mod.f#x", "app.mod", "f#x"},
		// An untyped chain keyed by the receiver's text, which holds calls.
		{
			"app.v.(ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()).verify",
			"app.v.ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()", "verify",
		},
		{"app.v.(ec.Numbers(\n    x\n).public_key()).verify", "app.v.ec.Numbers(\n    x\n).public_key()", "verify"},
		{`m.(b64encode(x).decode("u)").strip()).replace`, `m.b64encode(x).decode("u)").strip()`, "replace"},
	}
	for _, c := range cases {
		if cls, m := pyCallee(c.key); cls != c.cls || m != c.method {
			t.Errorf("pyCallee(%q) = %q %q, want %q %q", c.key, cls, m, c.cls, c.method)
		}
	}
}

func TestPythonText(t *testing.T) {
	for in, want := range map[string]string{
		`'HS256'`:            `"HS256"`,
		`b'key'`:             `b"key"`,
		`["a", 'b']`:         `["a", "b"]`,
		`'it\'s'`:            `'it\'s'`,
		`"don't"`:            `"don't"`,
		`"a'b" + 'c'`:        `"a'b" + "c"`,
		`'quote" inside'`:    `'quote" inside'`,
		"'two\nlines'":       "'two\nlines'",
		`''`:                 `""`,
		`{'alg': 'HS256'}`:   `{"alg": "HS256"}`,
		`hashlib.new('md5')`: `hashlib.new("md5")`,
		`x`:                  `x`,
	} {
		if got := dq(in); got != want {
			t.Errorf("dq(%q) = %q, want %q", in, got, want)
		}
	}
	names := pyNames([]graphfrag.GraphFragmentImport{
		{Line: 1, Module: "hashlib"},
		{Line: 2, Module: "Crypto.Cipher", Name: "AES"},
		{Line: 3, Module: "cryptography.hazmat.primitives.ciphers", Name: "algorithms", Alias: "alg"},
		{Line: 4, Module: "hmac", Alias: "h"},
		{Line: 5, Module: "os.path"},
		{Line: 6, Module: "other", Name: "*"},
		{Line: 9, Module: "late", Name: "AES", Local: true},
		{Line: 10, Module: "inner", Name: "secret", Local: true},
		{Line: 11, Module: "second", Name: "alg"},
	})
	want := map[string]string{
		"AES": "Crypto.Cipher.AES", "alg": "cryptography.hazmat.primitives.ciphers.algorithms", "h": "hmac",
		"secret": "inner.secret",
	}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("pyNames = %v, want %v", names, want)
	}
	for in, want := range map[string]string{
		"AES.MODE_GCM":            "Crypto.Cipher.AES.MODE_GCM",
		"alg.AES(key)":            "cryptography.hazmat.primitives.ciphers.algorithms.AES(key)",
		`h.new(k, "AES", alg.X)`:  `hmac.new(k, "AES", cryptography.hazmat.primitives.ciphers.algorithms.X)`,
		"x.AES":                   "x.AES",
		`"AES" + 'AES'`:           `"AES" + 'AES'`,
		"hashlib.sha256":          "hashlib.sha256",
		"AESX":                    "AESX",
		"":                        "",
		"[AES.MODE_EAX, alg.DES]": "[Crypto.Cipher.AES.MODE_EAX, cryptography.hazmat.primitives.ciphers.algorithms.DES]",
	} {
		if got := qualify(in, names); got != want {
			t.Errorf("qualify(%q) = %q, want %q", in, got, want)
		}
	}
}

// pyFrag is a Python fragment of one function in app/main.py, with the
// file's imports, made of external calls (target, raw, line, params).
func pyFrag(imports []graphfrag.GraphFragmentImport, calls ...ExternalJSON) *FragmentJSON {
	frag := &FragmentJSON{
		Functions:     []FunctionJSON{{Key: "app.main.run", Package: "app.main", FilePath: "app/main.py"}},
		ExternalCalls: calls,
		Imports:       map[string][]graphfrag.GraphFragmentImport{"app/main.py": imports},
	}
	frag.ScanMetadata.Ecosystem = "python"
	return frag
}

func pyCall(target, raw string, line int, params ...Param) ExternalJSON {
	ln, col, end := line, 5, 60
	return ExternalJSON{
		CallerKey: "app.main.run", TargetKey: target, Raw: raw, Line: &ln, Resolution: "exact",
		StartCol: &col, EndCol: &end, EntryCall: &CallSiteJSON{Parameters: params},
	}
}

func pos(i int, text string) Param { return Param{ParameterIndex: i, ArgumentExpression: text} }
func kw(i int, name, text string) Param {
	return Param{ParameterIndex: i, Keyword: name, ArgumentExpression: text}
}

func ruleLines(fs []*Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID+"@"+itoa(f.Line)+" "+jsonValue(f.Metadata))
	}
	sort.Strings(out)
	return out
}

// Python call sites: dotted callees compared exactly, class instantiation as
// a call, keyword and `i|name` argument keys, quotes, parentheses.
func TestPythonCallSites(t *testing.T) {
	imports := []graphfrag.GraphFragmentImport{
		{Line: 1, Module: "cryptography.hazmat.primitives.ciphers", Name: "Cipher"},
		{Line: 2, Module: "cryptography.hazmat.primitives.ciphers", Name: "algorithms"},
		{Line: 3, Module: "jwt"},
		{Line: 4, Module: "hashlib"},
		{Line: 5, Module: "notpyjwt.jose", Name: "jwt", Alias: "jose_jwt"},
		{Line: 6, Module: "Crypto.Cipher", Name: "AES"},
	}
	untyped := pyCall("app.main.(AES).new", "AES.new", 13, pos(0, "key"))
	untyped.Resolution = "name_only"
	name := pyCall("app.main.(ctx).set_ciphers", "ctx.set_ciphers", 9, pos(0, `'ECDHE+AESGCM'`))
	name.Resolution, name.ReceiverVar = "name_only", "ctx"
	frag := pyFrag(imports,
		pyCall("cryptography.hazmat.primitives.ciphers.(Cipher).<init>", "Cipher", 6,
			pos(0, "algorithms.AES(key)"), pos(1, "(mode)"), kw(2, "backend", "None")),
		pyCall("jwt.decode", "jwt.decode", 7, pos(0, "token"), pos(1, "key"), kw(2, "algorithms", `['HS256']`)),
		pyCall("jwt.decode", "jwt.decode", 8, pos(0, "token"), kw(1, "key", "secret"), kw(2, "algorithms", `["RS256"]`)),
		name,
		pyCall("hashlib.pbkdf2_hmac", "hashlib.pbkdf2_hmac", 10, pos(0, `'sha256'`), pos(1, "pw"), kw(2, "salt", "salt"),
			kw(3, "iterations", "1000"), kw(4, "dklen", "32")),
		pyCall("notpyjwt.jose.jwt.decode", "jose_jwt.decode", 11, pos(0, "token"), pos(1, "key"), kw(2, "algorithms", `["HS512"]`)),
		pyCall("cryptography.fernet.(Fernet).encrypt", "f.encrypt", 12, pos(0, "data")),
		untyped,
	)
	cards := cardsFrom(t, `
- rule: cipher
  match:
    call: cryptography.hazmat.primitives.ciphers.Cipher
    arity: 3
    args:
      0: {via: chain, from: {call: cryptography.hazmat.primitives.ciphers.algorithms.AES, arity: 1}}
      1: {regex: '^mode$'}
      backend: {literal: None}
- rule: jwt-alg
  match: {call: jwt.decode, args: {algorithms: {regex: '^\["(?<name>[A-Z]+\d+)"\]$'}, "1|key": {var: $K}}}
- rule: jwt-last
  match: {call: jwt.decode, args: {-1: {var: $T}}}
- rule: ciphers
  match: {method: set_ciphers, args: {0: {string: true, regex: '^"(?<name>[A-Z]+)'}}}
- rule: ciphers-typed
  match: {method: set_ciphers, type: ssl.SSLContext}
- rule: pbkdf2
  match: {call: hashlib.pbkdf2_hmac, arity: 5, args: {0: {literal: '"sha256"'}, "2|salt": {var: $S}, dklen: {number: ['>=32'], bind: name}}}
- rule: fernet
  match: {call: cryptography.fernet.Fernet.encrypt, arity: 1}
- rule: suffix
  match: {call: fernet.Fernet.encrypt}
- rule: untyped-module-receiver
  match: {call: Crypto.Cipher.AES.new}
`)
	got := ruleLines(matchCards(cards, newFrag(frag)))
	want := []string{
		`cipher@6 {}`,
		`ciphers@9 {"algorithmName": "ECDHE"}`,
		`fernet@12 {}`,
		`jwt-alg@7 {"algorithmName": "HS256"}`,
		`jwt-alg@8 {"algorithmName": "RS256"}`,
		`jwt-last@7 {}`,
		`jwt-last@8 {}`,
		`pbkdf2@10 {"algorithmName": "32"}`,
		`untyped-module-receiver@13 {}`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n got %v\nwant %v", got, want)
	}
}

// A call read from argument text (no recorded site) is qualified through the
// file's imports, and its keyword arguments are read by name.
func TestPythonCallFromText(t *testing.T) {
	frag := pyFrag([]graphfrag.GraphFragmentImport{{Line: 1, Module: "cryptography.hazmat.primitives.ciphers", Name: "algorithms", Alias: "alg"}},
		pyCall("cryptography.hazmat.primitives.ciphers.(Cipher).<init>", "Cipher", 6, pos(0, "alg.AES(key=k)"), pos(1, "modes.GCM(iv)")))
	cards := cardsFrom(t, `
- rule: aes
  match: {call: cryptography.hazmat.primitives.ciphers.Cipher, args: {0: {via: chain, from: {call: cryptography.hazmat.primitives.ciphers.algorithms.AES, args: {key: $K}}}}}
- rule: unqualified
  match: {call: cryptography.hazmat.primitives.ciphers.Cipher, args: {1: {via: chain, from: {call: cryptography.hazmat.primitives.ciphers.modes.GCM}}}}
`)
	if got, want := ruleLines(matchCards(cards, newFrag(frag))), []string{`aes@6 {}`}; !reflect.DeepEqual(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
}

// Compiled entries on Python sites: the callee exactly, an argument the rule
// writes qualified against the source's imported name, a keyword argument.
func TestPythonCompiledEntries(t *testing.T) {
	frag := pyFrag([]graphfrag.GraphFragmentImport{
		{Line: 1, Module: "Crypto.Cipher", Name: "AES"},
		{Line: 2, Module: "jwt"},
		{Line: 3, Module: "notpyjwt.jose", Name: "jwt", Alias: "jj"},
	},
		pyCall("Crypto.Cipher.AES.new", "AES.new", 5, pos(0, "key"), pos(1, "AES.MODE_GCM")),
		pyCall("jwt.encode", "jwt.encode", 6, pos(0, "p"), pos(1, "k"), kw(2, "algorithm", `'HS256'`)),
		pyCall("jwt.encode", "jwt.encode", 7, pos(0, "p"), pos(1, "k")),
		pyCall("notpyjwt.jose.jwt.encode", "jj.encode", 8, pos(0, "p"), pos(1, "k"), kw(2, "algorithm", `"HS256"`)),
	)
	meta := JSONMeta{M: &OMap{Keys: []any{"algorithmName"}, Vals: []any{"$ALG"}}}
	zero, one := 0, 1
	entries := []*Entry{
		{
			Receiver: "type", Type: strp("Crypto.Cipher.AES"), Method: strp("new"), MinArity: 2,
			Args:   []IndexArg{{Kind: "metavar", Index: &zero}, {Kind: "text", Value: strp("Crypto.Cipher.AES.MODE_GCM"), Index: &one}},
			RuleID: "aes-gcm", Metadata: meta,
		},
		{
			Receiver: "type", Type: strp("jwt"), Method: strp("encode"), MinArity: 2,
			Args:   []IndexArg{{Kind: "metavar", Name: strp("$ALG"), Keyword: strp("algorithm")}},
			RuleID: "jwt-alg", Metadata: meta,
		},
		{Receiver: "type", Type: strp("Cipher.AES"), Method: strp("new"), MinArity: 0, RuleID: "suffix", Metadata: meta},
		{Receiver: "type", Type: strp("AES"), Method: strp("new"), MinArity: 0, RuleID: "as-written", Metadata: meta},
	}
	found := matchIndex(entries, newFrag(frag), true, "cf")
	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, f.RuleID+"@"+itoa(f.Line)+" "+jsonValue(f.Metadata))
	}
	want := []string{`aes-gcm@5 {}`, `as-written@5 {}`, `jwt-alg@6 {"algorithmName": "HS256"}`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
}

// A Java fragment keeps the Java reading: the suffix type match and
// receiverless calls.
func TestJavaFragmentKeepsJavaReading(t *testing.T) {
	fr := tinyFrag()
	if fr.Python || fr.Sites[0].Python {
		t.Fatal("a fragment without the python ecosystem is read as Python")
	}
	if fr.Sites[0].Class != "java.security.KeyPairGenerator" || fr.Sites[0].Method != "getInstance" {
		t.Errorf("Java site = %q %q", fr.Sites[0].Class, fr.Sites[0].Method)
	}
}

// Values the fragment resolved for a Python argument read double-quoted: a
// local's literal, a VALUE node, the literals of a variable written twice.
func TestPythonResolvedValues(t *testing.T) {
	frag := pyFrag([]graphfrag.GraphFragmentImport{{Line: 1, Module: "hashlib"}},
		pyCall("hashlib.new", "hashlib.new", 5, Param{ParameterIndex: 0, ArgumentExpression: "n", VariableName: "n", ResolvedValue: `'md5'`}),
		pyCall("hashlib.new", "hashlib.new", 6, Param{
			ParameterIndex: 0, ArgumentExpression: "m",
			SourceNodes: []SourceNode{{Type: "VARIABLE", Name: "m", SourceNodes: []SourceNode{{Type: "VALUE", Value: `'sha1'`}}}},
		}),
		pyCall("hashlib.new", "hashlib.new", 7, Param{
			ParameterIndex: 0, ArgumentExpression: "x",
			SourceNodes: []SourceNode{{Type: "VARIABLE", Name: "x", MayValues: []string{`'sha224'`}, MayValuesExhaustive: true}},
		}),
	)
	cards := cardsFrom(t, `
- rule: new
  match: {call: hashlib.new, args: {0: {resolves: '^"(?<name>md5|sha1|sha224)"$'}}}
`)
	want := []string{`new@5 {"algorithmName": "md5"}`, `new@6 {"algorithmName": "sha1"}`, `new@7 {"algorithmName": "sha224"}`}
	if got := ruleLines(matchCards(cards, newFrag(frag))); !reflect.DeepEqual(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
}

// A Python dispatch edge is compared with its callee's class (Python
// exports no declared receiver type).
func TestPythonDispatchEdgeKeepsCalleeClass(t *testing.T) {
	frag := pyFrag(nil)
	frag.Functions = append(frag.Functions, FunctionJSON{Key: "app.algs.(Signer).sign", Package: "app.algs", FilePath: "app/algs.py"})
	frag.InternalEdgeStrings = []string{"", "interface_dispatch", "sign"}
	frag.InternalEdges = []CompactEdge{{N: [13]int{0, 1, 9, 1, 0, 2, 1, 0, 0, 0, 5, 20}}}
	cards := cardsFrom(t, `
- rule: sign
  match: {call: app.algs.Signer.sign}
`)
	if got, want := ruleLines(matchCards(cards, newFrag(frag))), []string{`sign@9 {}`}; !reflect.DeepEqual(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
}

func withAssigned(e ExternalJSON, v string) ExternalJSON { e.AssignedVar = v; return e }
func withSpan(e ExternalJSON, col, end int) ExternalJSON {
	e.StartCol, e.EndCol = &col, &end
	return e
}

func nameOnly(e ExternalJSON, recv string) ExternalJSON {
	e.Resolution, e.ReceiverVar = "name_only", recv
	return e
}

// `object:` types a receiver by the fragment (a typed call) or by the call a
// local was assigned from.
func TestCardObject(t *testing.T) {
	imports := []graphfrag.GraphFragmentImport{{Line: 1, Module: "cryptography.fernet", Name: "Fernet"}}
	frag := pyFrag(imports,
		pyCall("cryptography.fernet.(Fernet).encrypt", "self.f.encrypt", 5, pos(0, "d")),
		withAssigned(pyCall("cryptography.fernet.(Fernet).<init>", "Fernet", 6, pos(0, "k")), "f"),
		nameOnly(pyCall("app.main.(f).encrypt", "f.encrypt", 7, pos(0, "d")), "f"),
		nameOnly(pyCall("app.main.(g).encrypt", "g.encrypt", 8, pos(0, "d")), "g"),
		nameOnly(pyCall("app.main.(Fernet(k)).encrypt", "Fernet(k).encrypt", 9, pos(0, "d")), ""),
		pyCall("cryptography.fernet.(Fernet).<init>", "Fernet", 10, pos(0, "k")),
		nameOnly(pyCall("app.main.(b.c).encrypt", "b.c.encrypt", 11, pos(0, "d")), ""),
		withAssigned(pyCall("cryptography.fernet.(Fernet).<init>", "Fernet", 12, pos(0, "k")), "self.f"),
		nameOnly(pyCall("app.main.(self.f).encrypt", "self.f.encrypt", 13, pos(0, "d")), ""),
		nameOnly(pyCall("app.main.(b.d).encrypt", "b.d.encrypt", 14, pos(0, "d")), ""),
		nameOnly(pyCall("app.main.(42).encrypt", "42.encrypt", 15, pos(0, "d")), ""),
	)
	frag.AttributeStores = []graphfrag.GraphFragmentAttributeStore{
		{Line: 10, StartCol: 5, EndCol: 20, Receiver: "b", Attribute: "c", Operator: "=", Value: graphfrag.GraphFragmentParameter{ArgumentExpression: "Fernet(k)"}},
		{Line: 10, StartCol: 5, EndCol: 20, Receiver: "b", Attribute: "d", Operator: "|=", Value: graphfrag.GraphFragmentParameter{ArgumentExpression: "Fernet(k)"}},
		{Line: 10, StartCol: 5, EndCol: 20, Receiver: "b", Attribute: "d", Operator: "=", Value: graphfrag.GraphFragmentParameter{ArgumentExpression: "k"}},
	}
	cards := cardsFrom(t, `
- rule: fernet
  match: {method: encrypt, arity: 1, object: {type: cryptography.fernet.Fernet, from: [cryptography.fernet.Fernet]}}
- rule: fernet-chain
  match: {method: encrypt, object: {from: [{call: cryptography.fernet.Fernet, arity: 1}], via: chain}}
`)
	want := []string{`fernet-chain@9 {}`, `fernet@11 {}`, `fernet@13 {}`, `fernet@5 {}`, `fernet@7 {}`}
	if got := ruleLines(matchCards(cards, newFrag(frag))); !reflect.DeepEqual(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
	expanded := jsonValue(expandObjects(cards[0].Raw.GetOr("match")))
	if expanded != `{"any": [{"arity": 1, "call": ["cryptography.fernet.Fernet.encrypt"]}, {"arity": 1, "method": "encrypt", "receiver": {"via": "var", "from": {"any": [{"call": "cryptography.fernet.Fernet"}]}}}]}` {
		t.Errorf("expanded %s", expanded)
	}
}

// `inside:` / `not_inside:` read whether the call is written in the argument
// list of another call of the function.
func TestCardInside(t *testing.T) {
	imports := []graphfrag.GraphFragmentImport{
		{Line: 1, Module: "cryptography.hazmat.primitives.asymmetric", Name: "ec"},
		{Line: 2, Module: "cryptography.hazmat.primitives", Name: "hashes"},
	}
	frag := pyFrag(imports,
		withSpan(nameOnly(pyCall("app.main.(key).sign", "key.sign", 5, pos(0, "data"), pos(1, "ec.ECDSA(hashes.SHA256())")), "key"), 5, 50),
		withSpan(pyCall("cryptography.hazmat.primitives.asymmetric.ec.ECDSA", "ec.ECDSA", 5, pos(0, "hashes.SHA256()")), 20, 49),
		withSpan(pyCall("cryptography.hazmat.primitives.hashes.SHA256", "hashes.SHA256", 5), 29, 48),
		withSpan(pyCall("cryptography.hazmat.primitives.asymmetric.ec.ECDSA", "ec.ECDSA", 7, pos(0, "h")), 9, 20),
		// A call on the same line, within the span of sign but not in its arguments.
		withSpan(pyCall("cryptography.hazmat.primitives.asymmetric.ec.ECDSA", "ec.ECDSA", 9, pos(0, "h")), 5, 20),
		withSpan(nameOnly(pyCall("app.main.(ec.ECDSA(h)).verify", "ec.ECDSA(h).verify", 9, pos(0, "s")), ""), 5, 40),
		withSpan(pyCall("cryptography.hazmat.primitives.hashes.SHA256", "hashes.SHA256", 11), 9, 24),
		// A receiver call with no recorded site.
		withSpan(nameOnly(pyCall("app.main.(ec.ECDSA(h, x)).verify", "ec.ECDSA(h, x).verify", 12, pos(0, "s")), ""), 5, 40),
	)
	cards := cardsFrom(t, `
- rule: ecdsa
  match: {call: cryptography.hazmat.primitives.asymmetric.ec.ECDSA, not_inside: [{method: [sign, verify]}]}
- rule: sha-in-ecdsa
  match: {call: cryptography.hazmat.primitives.hashes.SHA256, inside: {call: cryptography.hazmat.primitives.asymmetric.ec.ECDSA}}
- rule: verify-unsigned
  match: {method: verify, receiver: {via: chain, from: {call: cryptography.hazmat.primitives.asymmetric.ec.ECDSA, not_inside: {method: sign}}}}
`)
	want := []string{`ecdsa@7 {}`, `ecdsa@9 {}`, `sha-in-ecdsa@5 {}`, `verify-unsigned@9 {}`}
	if got := ruleLines(matchCards(cards, newFrag(frag))); !reflect.DeepEqual(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
}

// `flows_to:` reports a producer whose result is passed as a given argument
// of another call: inline, or through a local passed by a later call.
func TestCardFlowsTo(t *testing.T) {
	imports := []graphfrag.GraphFragmentImport{{Line: 1, Module: "os"}, {Line: 2, Module: "hashlib"}}
	frag := pyFrag(imports,
		withAssigned(pyCall("os.urandom", "os.urandom", 5, pos(0, "16")), "salt"),
		pyCall("hashlib.pbkdf2_hmac", "hashlib.pbkdf2_hmac", 6, pos(0, `"sha256"`), pos(1, "pw"), pos(2, "salt"), pos(3, "1000")),
		pyCall("os.urandom", "os.urandom", 8, pos(0, "16")),
		pyCall("hashlib.scrypt", "hashlib.scrypt", 8, pos(0, "pw"), kw(1, "salt", "os.urandom(16)"), kw(2, "n", "2")),
		withAssigned(pyCall("os.urandom", "os.urandom", 10, pos(0, "16")), "nonce"),
		pyCall("hashlib.pbkdf2_hmac", "hashlib.pbkdf2_hmac", 11, pos(0, `"sha256"`), pos(1, "nonce"), pos(2, "pw"), pos(3, "1")),
		withAssigned(pyCall("os.urandom", "os.urandom", 13, pos(0, "16")), "late"),
		pyCall("hashlib.pbkdf2_hmac", "hashlib.pbkdf2_hmac", 12, pos(0, `"sha256"`), pos(1, "pw"), pos(2, "late"), pos(3, "1")),
		withAssigned(pyCall("os.urandom", "os.urandom", 15, pos(0, "16")), "iv"),
		pyCall("app.other.f", "other.f", 16, pos(0, "a"), pos(1, "b"), pos(2, "iv")),
	)
	cards := cardsFrom(t, `
- rule: salt
  match:
    call: os.urandom
    flows_to:
    - {arg: "2|salt", to: {call: hashlib.pbkdf2_hmac}}
    - {arg: salt, to: {call: hashlib.scrypt}}
`)
	want := []string{`salt@5 {}`, `salt@8 {}`}
	if got := ruleLines(matchCards(cards, newFrag(frag))); !reflect.DeepEqual(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
}

// A loaded card has its `object:` patterns expanded, in match and in its
// with / without / optional items.
func TestLoadExpandsObjects(t *testing.T) {
	rules, cards := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(rules, "rules.yaml"), []byte("rules:\n- id: enc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	card := "cards:\n- rule: enc\n  match: {method: encrypt, object: {from: [a.F]}}\n" +
		"  with: [{method: init, object: {type: a.F}}]\n  without: [{method: reset, object: {type: a.F}}]\n" +
		"  optional: [{method: mode, object: {type: a.F}}]\n"
	if err := os.WriteFile(filepath.Join(cards, "rules.cards"), []byte(card), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := loadCards(cards, rules)
	if err != nil {
		t.Fatal(err)
	}
	c := set.Cards[0]
	got := []string{jsonValue(c.Match), jsonValue(c.With), jsonValue(c.Without), jsonValue(c.Optional)}
	want := []string{
		`{"any": [{"method": "encrypt", "receiver": {"via": "var", "from": {"any": [{"call": "a.F"}]}}}]}`,
		`[{"any": [{"call": ["a.F.init"]}]}]`,
		`[{"any": [{"call": ["a.F.reset"]}]}]`,
		`[{"any": [{"call": ["a.F.mode"]}]}]`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("loaded\n got %v\nwant %v", got, want)
	}
}
