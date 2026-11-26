// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

// pyFlowCall is a Python call site of the flow tests: an external call
// written at line, col 5.
func pyFlowCall(caller, target, raw string, line int, resolution, recv, assigned string) ExternalJSON {
	ln, col, end := line, 5, 40
	return ExternalJSON{
		CallerKey: caller, TargetKey: target, Raw: raw, Line: &ln, Resolution: resolution, StartCol: &col,
		EndCol: &end, ReceiverVar: recv, AssignedVar: assigned, EntryCall: &CallSiteJSON{},
	}
}

func pyFlowFindings(t *testing.T, frag *FragmentJSON, cards string) []string {
	t.Helper()
	frag.ScanMetadata.Ecosystem = "python"
	fr := newFrag(frag)
	fr.ResolveParams = true
	found := matchCards(cardsFrom(t, cards), fr)
	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, strconv.Itoa(f.Line)+" "+f.RuleID)
	}
	sort.Strings(got)
	return got
}

// A receiver whose leading name the calling function binds itself is that
// local, not the module an import of the file binds the name to: a
// parameter, a local the parser identified as the receiver (assignment,
// for / with / except target, comprehension variable), a local assigned a
// call (E2.7-py.14b gap 1). The module itself still matches, and so do a
// module or class body, where the import and another binding of the name
// are one variable (`try: import rsa` / `except ImportError: rsa = None`), a
// function that imports the name itself, and a receiver whose name no
// import binds (it is matched as written, as before).
func TestPythonShadowedImport(t *testing.T) {
	frag := &FragmentJSON{
		Functions: []FunctionJSON{
			{Key: "app.m.param", FilePath: "app/m.py", StartLine: 3, EndLine: 5, ParameterNames: []string{"rsa", "m"}},
			{Key: "app.m.local", FilePath: "app/m.py", StartLine: 6, EndLine: 9},
			{Key: "app.m.dotted", FilePath: "app/m.py", StartLine: 10, EndLine: 12, ParameterNames: []string{"rsa"}},
			{Key: "app.m.assigned", FilePath: "app/m.py", StartLine: 13, EndLine: 16},
			{Key: "app.m.real", FilePath: "app/m.py", StartLine: 17, EndLine: 19, ParameterNames: []string{"m"}},
			{Key: "app.m.<module>", FilePath: "app/m.py", StartLine: 1, EndLine: 40},
			{Key: "app.m.imports", FilePath: "app/m.py", StartLine: 25, EndLine: 30, ParameterNames: []string{"rsa"}},
			{Key: "app.m.unimported", FilePath: "app/m.py", StartLine: 31, EndLine: 33, ParameterNames: []string{"argon2"}},
		},
		Imports: map[string][]graphfrag.GraphFragmentImport{"app/m.py": {
			{Line: 1, Module: "rsa"},
			{Line: 26, Module: "rsa", Local: true},
		}},
		ExternalCalls: []ExternalJSON{
			pyFlowCall("app.m.param", "app.m.(rsa).encrypt", "rsa.encrypt", 4, "name_only", "rsa", ""),
			pyFlowCall("app.m.local", "app.m.(rsa).encrypt", "rsa.encrypt", 8, "name_only", "rsa", ""),
			pyFlowCall("app.m.dotted", "app.m.(rsa.sub).encrypt", "rsa.sub.encrypt", 11, "name_only", "", ""),
			pyFlowCall("app.m.assigned", "app.m.make", "make", 14, "exact", "", "rsa"),
			pyFlowCall("app.m.assigned", "app.m.(rsa.sub).encrypt", "rsa.sub.encrypt", 15, "name_only", "", ""),
			pyFlowCall("app.m.real", "rsa.encrypt", "rsa.encrypt", 18, "exact", "", ""),
			pyFlowCall("app.m.<module>", "app.m.(rsa).encrypt", "rsa.encrypt", 22, "name_only", "rsa", ""),
			pyFlowCall("app.m.imports", "app.m.(rsa).encrypt", "rsa.encrypt", 27, "name_only", "rsa", ""),
			pyFlowCall("app.m.unimported", "app.m.(argon2.low_level).hash_secret", "argon2.low_level.hash_secret", 32,
				"name_only", "", ""),
		},
	}
	cards := `- rule: encrypt
  match: {call: rsa.encrypt}
- rule: sub-encrypt
  match: {call: rsa.sub.encrypt}
- rule: argon2
  match: {call: argon2.low_level.hash_secret}
`
	got := pyFlowFindings(t, frag, cards)
	want := []string{"18 encrypt", "22 encrypt", "27 encrypt", "32 argon2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
}

// pyReaches reads the fragment's local bindings: a use reads the assignment
// whose binding is the last to take effect in a block holding the use, or
// any of the assignments in branches that do not hold it; a use before a
// binding reads it only inside a loop around both. A site with no binding
// of its own, and a name with none, reach every use (E2.7-py.14b gap 2).
func TestPythonReachingDefinitions(t *testing.T) {
	frag := &FragmentJSON{
		Functions: []FunctionJSON{{Key: "app.m.f", FilePath: "app/m.py"}},
		ExternalCalls: []ExternalJSON{
			pyFlowCall("app.m.f", "M2Crypto.EVP.Cipher", "EVP.Cipher", 2, "exact", "", "e"),  // e = A()        line 2
			pyFlowCall("app.m.f", "M2Crypto.EVP.Cipher", "EVP.Cipher", 4, "exact", "", "e"),  // if c: e = B()  line 4
			pyFlowCall("app.m.f", "M2Crypto.EVP.Cipher", "EVP.Cipher", 8, "exact", "", "e"),  // e = C() in loop line 8
			pyFlowCall("app.m.f", "M2Crypto.EVP.Cipher", "EVP.Cipher", 12, "exact", "", "z"), // z bound once
		},
		LocalBindings: []graphfrag.GraphFragmentLocalBinding{
			{Function: 0, Name: "e", Line: 2, Col: 1, EffectLine: 2, EffectCol: 50, BlockEndLine: 20, BlockEndCol: 1},
			{Function: 0, Name: "e", Line: 4, Col: 1, EffectLine: 4, EffectCol: 50, BlockEndLine: 4, BlockEndCol: 50},
			{Function: 0, Name: "e", Line: 8, Col: 1, EffectLine: 8, EffectCol: 50, BlockEndLine: 9, BlockEndCol: 9, LoopLine: 6, LoopCol: 5},
			{Function: 0, Name: "e", Line: 10, Col: 1, EffectLine: 10, EffectCol: 12, BlockEndLine: 20, BlockEndCol: 1},
		},
	}
	frag.ScanMetadata.Ecosystem = "python"
	fr := newFrag(frag)
	sites := fr.VarSites[pairKey("app.m.f", "e")]
	a, b, c := sites[0], sites[1], sites[2]
	z := fr.VarSites[pairKey("app.m.f", "z")][0]
	for _, tc := range []struct {
		what      string
		d         *Site
		name      string
		line, col int
		want      bool
	}{
		{"A on the next line", a, "e", 3, 5, true},
		{"A after the branch", a, "e", 5, 5, true},
		{"B after the branch", b, "e", 5, 5, true},
		{"A in the loop before C", a, "e", 7, 5, true},
		{"C in the loop before itself, next iteration", c, "e", 7, 5, true},
		{"C before the loop", c, "e", 5, 5, false},
		{"A after the rebinding to no call", a, "e", 11, 5, false},
		{"C after the rebinding to no call", c, "e", 11, 5, false},
		{"A inside its own statement", a, "e", 2, 30, false},
		{"a name bound once", z, "z", 13, 5, true},
	} {
		if got := fr.pyReaches(tc.d, tc.name, tc.line, tc.col); got != tc.want {
			t.Errorf("%s: pyReaches = %v, want %v", tc.what, got, tc.want)
		}
	}
}

// A named group of a value pattern's regex binds its text in the card's
// environment under the group's name, the environment `var:` and
// `assigned:` read (E2.7-py.14b): `receiver: {regex: '^(?<KEY>\w+)\.public_key$'}` with
// `with: [{call: F, assigned: KEY}]` ties `sk.public_key.verify()` to an F
// assigned to sk, and to no other local. The name is written without `$`
// (`$KEY` is another name).
func TestPythonRegexGroupSharedWithAssigned(t *testing.T) {
	frag := &FragmentJSON{
		Functions: []FunctionJSON{{Key: "app.m.f", FilePath: "app/m.py"}, {Key: "app.m.g", FilePath: "app/m.py"}},
		ExternalCalls: []ExternalJSON{
			pyFlowCall("app.m.f", "eth_keys.keys.PrivateKey", "keys.PrivateKey", 2, "exact", "", "sk"),
			pyFlowCall("app.m.f", "app.m.(sk.public_key).verify_msg", "sk.public_key.verify_msg", 3, "name_only", "", ""),
			pyFlowCall("app.m.f", "app.m.(other.public_key).verify_msg", "other.public_key.verify_msg", 4, "name_only", "", ""),
			pyFlowCall("app.m.g", "app.m.make", "make", 7, "exact", "", "sk"),
			pyFlowCall("app.m.g", "app.m.(sk.public_key).verify_msg", "sk.public_key.verify_msg", 8, "name_only", "", ""),
		},
	}
	cards := `- rule: group
  match: {method: verify_msg, receiver: {regex: '^(?<KEYVAR>[A-Za-z_]\w*)\.public_key$'}}
  with: [{call: eth_keys.keys.PrivateKey, assigned: KEYVAR, when: before}]
- rule: dollar-is-another-name
  match: {method: verify_msg, receiver: {regex: '^(?<KEYVAR>[A-Za-z_]\w*)\.public_key$'}}
  with: [{call: eth_keys.keys.PrivateKey, assigned: $KEYVAR, when: before}]
`
	got := pyFlowFindings(t, frag, cards)
	want := []string{"3 dollar-is-another-name", "3 group", "4 dollar-is-another-name"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
}
