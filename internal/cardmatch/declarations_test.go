// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

// declarationsFrag is one function:
//
//	3  X509Certificate a = (X509Certificate) f.generateCertificate(in);
//	4  X509Certificate b = null;
//	5  X509Certificate c;
//	6  c = (X509Certificate) certs.get(0);
//	7  return (X509Certificate) f.generateCertificate(in2);
//	8  X509Certificate d = store.getCertificate(alias);
//	9  c = store.getCertificate(alias2);
//	10 use(c);
//	11 Certificate e = (Certificate) f.generateCertificate(in3);
//	12 b = store.getCertificate(alias3);
//
// schema is its schema_version; a 1.17 fragment has neither declarations nor
// casts, and `use(c)` tells the declared type of c through a source node.
func declarationsFrag(schema string) *FragmentJSON {
	ln := func(n int) *int { return &n }
	const caller = "app.(Demo).run#0"
	call := func(target, raw, method string, line, col, endCol int, assigned string) ExternalJSON {
		return ExternalJSON{
			CallerKey: caller, TargetKey: target, Raw: raw, Line: ln(line), Resolution: "exact",
			MethodName: method, Arity: 1, StartCol: ln(col), EndCol: ln(endCol), AssignedVar: assigned,
		}
	}
	use := call("app.(Demo).use#1", "use", "use", 10, 9, 15, "")
	use.EntryCall = &CallSiteJSON{Parameters: []Param{{
		ParameterIndex: 0, ArgumentExpression: "c",
		SourceNodes: []SourceNode{{Type: "VARIABLE", Name: "c", DeclaredType: "X509Certificate"}},
	}}}
	frag := &FragmentJSON{
		SchemaVersion: schema,
		Functions:     []FunctionJSON{{Key: caller, Package: "app", FilePath: "src/Demo.java"}},
		ExternalCalls: []ExternalJSON{
			call("java.security.cert.(CertificateFactory).generateCertificate#1", "f.generateCertificate", "generateCertificate", 3, 47, 74, "a"),
			call("java.util.(List).get#1", "certs.get", "get", 6, 31, 43, "c"),
			call("java.security.cert.(CertificateFactory).generateCertificate#1", "f.generateCertificate", "generateCertificate", 7, 34, 62, ""),
			call("java.security.(KeyStore).getCertificate#1", "store.getCertificate", "getCertificate", 8, 29, 56, "d"),
			call("java.security.(KeyStore).getCertificate#1", "store.getCertificate", "getCertificate", 9, 13, 41, "c"),
			use,
			call("java.security.cert.(CertificateFactory).generateCertificate#1", "f.generateCertificate", "generateCertificate", 11, 40, 68, "e"),
			call("java.security.(KeyStore).getCertificate#1", "store.getCertificate", "getCertificate", 12, 13, 41, "b"),
		},
	}
	if schema == "graph-fragment-1.17" {
		return frag
	}
	frag.Declarations = []graphfrag.GraphFragmentDeclaration{
		{Line: 3, StartCol: 9, EndCol: 75, Type: "X509Certificate", Name: "a", Init: "cast"},
		{Line: 4, StartCol: 9, EndCol: 34, Type: "X509Certificate", Name: "b", Init: "null"},
		{Line: 5, StartCol: 9, EndCol: 27, Type: "X509Certificate", Name: "c"},
		{Line: 8, StartCol: 9, EndCol: 57, Type: "java.security.cert.X509Certificate", Name: "d", Init: "call"},
		{Line: 11, StartCol: 9, EndCol: 69, Type: "Certificate", Name: "e", Init: "cast"},
	}
	frag.Casts = []graphfrag.GraphFragmentCast{
		{Line: 3, StartCol: 29, EndCol: 74, Type: "X509Certificate", InnerLine: 3, InnerCol: 47},
		{Line: 6, StartCol: 13, EndCol: 43, Type: "X509Certificate", InnerLine: 6, InnerCol: 31},
		{Line: 7, StartCol: 16, EndCol: 62, Type: "X509Certificate", InnerLine: 7, InnerCol: 34},
		{Line: 11, StartCol: 25, EndCol: 68, Type: "Certificate", InnerLine: 11, InnerCol: 40},
	}
	return frag
}

func declarationFindings(t *testing.T, schema, cardsYAML string) []string {
	t.Helper()
	found := matchCards(cardsFrom(t, cardsYAML), newFrag(declarationsFrag(schema)))
	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, fmt.Sprintf("%s %d:%d-%d %s", f.RuleID, f.Line, f.Col, f.EndCol, f.How))
	}
	sort.Strings(got)
	return got
}

const x509Cards = `
- rule: usage
  match: {cast: X509Certificate, method: generateCertificate}
- rule: usage
  declaration: {init: true, type: X509Certificate}
- rule: stored
  match: {method_regex: '.*', assigned_type: X509Certificate}
`

// A declaration card reports every declaration of its type that has an
// initializer, at the declaration, whatever the initializer is; a cast
// card reports the cast around its call wherever the value goes, at the
// cast; assigned_type holds for a declaration's initializer only, not for a
// plain assignment.
func TestDeclarationAndCastCards(t *testing.T) {
	want := []string{
		"stored 3:47-74 card", // a's initializer, through the cast
		"stored 8:29-56 card",
		"usage 3:29-74 card",
		"usage 3:9-75 declaration:cast",
		"usage 4:9-34 declaration:null",
		"usage 7:16-62 card",
		"usage 8:9-57 declaration:call",
	}
	if got := declarationFindings(t, "graph-fragment-1.18", x509Cards); !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n got %v\nwant %v", got, want)
	}
}

// On a 1.17 fragment a declaration card finds nothing, a cast is seen only in
// expression text, and assigned_type reads the declared type the source
// nodes give a variable, plain assignments included.
func TestDeclarationCardsOnOlderFragment(t *testing.T) {
	want := []string{"stored 6:31-43 card", "stored 9:13-41 card"}
	if got := declarationFindings(t, "graph-fragment-1.17", x509Cards); !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n got %v\nwant %v", got, want)
	}
}

// init selects declarations by initializer: false is none, a kind or a list
// of kinds is one of them; without init every declaration of the type.
func TestDeclarationCardInit(t *testing.T) {
	for cards, want := range map[string][]string{
		`[{rule: r, declaration: {type: X509Certificate}}]`:                                {"r 3:9-75 declaration:cast", "r 4:9-34 declaration:null", "r 5:9-27 declaration:", "r 8:9-57 declaration:call"},
		`[{rule: r, declaration: {type: X509Certificate, init: false}}]`:                   {"r 5:9-27 declaration:"},
		`[{rule: r, declaration: {type: X509Certificate, init: 'null'}}]`:                  {"r 4:9-34 declaration:null"},
		`[{rule: r, declaration: {type: [Certificate], init: [call, cast]}}]`:              {"r 11:9-69 declaration:cast"},
		`[{rule: r, declaration: {type: java.security.cert.X509Certificate, init: call}}]`: {"r 8:9-57 declaration:call"},
	} {
		if got := declarationFindings(t, "graph-fragment-1.18", cards); !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %v\nwant %v", cards, got, want)
		}
	}
}

// A card has exactly one of match, constant and declaration; a declaration
// card names a type and takes only type and init.
func TestLoadDeclarationCards(t *testing.T) {
	rules := t.TempDir()
	if err := os.WriteFile(filepath.Join(rules, "rules.yaml"), []byte("rules:\n- id: usage\n  metadata: {crypto: {assetType: certificate}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for body, wantErr := range map[string]bool{
		`declaration: {type: X509Certificate, init: true}`:                             false,
		`declaration: {init: true}`:                                                    true,
		`declaration: {type: X509Certificate, value: x}`:                               true,
		"declaration: {type: X509Certificate}\n  match: {method: generateCertificate}": true,
		"declaration: {type: X509Certificate}\n  constant: {const: A.B}":               true,
	} {
		cards := t.TempDir()
		if err := os.WriteFile(filepath.Join(cards, "rules.cards"), []byte("cards:\n- rule: usage\n  "+body+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		set, err := loadCards(cards, rules)
		if (err != nil) != wantErr {
			t.Errorf("%q: error %v, want error %v", body, err, wantErr)
		}
		if err == nil && (len(set.Cards) != 1 || set.Cards[0].Declaration == nil || !strings.Contains(jsonValue(set.Cards[0].Declaration), "X509Certificate")) {
			t.Errorf("%q: cards %+v, want one declaration card", body, set.Cards)
		}
	}
}

// A cast a with item matches does not move the finding: it stays at the
// card's own call.
func TestCastInWithItemReportsAtCall(t *testing.T) {
	cards := `[{rule: r, match: {call: KeyStore.getCertificate}, with: [{method: generateCertificate, cast: X509Certificate}]}]`
	want := []string{"r 12:13-41 card", "r 8:29-56 card", "r 9:13-41 card"}
	if got := declarationFindings(t, "graph-fragment-1.18", cards); !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n got %v\nwant %v", got, want)
	}
}
