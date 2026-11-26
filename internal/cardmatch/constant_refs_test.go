// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package cardmatch

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

// constantRefsFrag: one function with a constant inside a not_in call
// (line 3) and after it on its line, as the argument of another call (4), returned (5), compared (6),
// and as an argument the fragment has no reference for (7, a 1.16 fragment).
func constantRefsFrag() *FragmentJSON {
	ln := func(n int) *int { return &n }
	call := func(target, raw, method string, line, col, endCol int, arg string) ExternalJSON {
		return ExternalJSON{
			CallerKey: "app.(Demo).run#0", TargetKey: target, Raw: raw, Line: ln(line), Resolution: "exact",
			MethodName: method, Arity: 1, StartCol: ln(col), EndCol: ln(endCol),
			EntryCall: &CallSiteJSON{Parameters: []Param{{ParameterIndex: 0, ArgumentExpression: arg}}},
		}
	}
	ref := func(line, col int, text, context string) graphfrag.GraphFragmentConstantRef {
		return graphfrag.GraphFragmentConstantRef{Line: line, StartCol: col, EndCol: col + len(text), Text: text, Context: context}
	}
	return &FragmentJSON{
		Functions: []FunctionJSON{{Key: "app.(Demo).run#0", Package: "app", FilePath: "src/Demo.java"}},
		ExternalCalls: []ExternalJSON{
			call("org.jose4j.(EcJwkGenerator).generateJwk#1", "EcJwkGenerator.generateJwk", "generateJwk", 3, 15, 61, "EllipticCurves.P256"),
			call("app.(Demo).use#1", "use", "use", 4, 9, 33, "EllipticCurves.P384"),
			call("app.(Demo).wrap#1", "wrap", "wrap", 7, 9, 34, "EllipticCurves.P256"),
		},
		ConstantRefs: []graphfrag.GraphFragmentConstantRef{
			ref(3, 42, "EllipticCurves.P256", "arg"),
			ref(3, 66, "EllipticCurves.P521", "assign"),
			ref(4, 13, "EllipticCurves.P384", "arg"),
			ref(5, 16, "EllipticCurves.P521", "return"),
			ref(6, 20, "EllipticCurves.SECP256K1", "compare"),
		},
	}
}

func constantRefFindings(t *testing.T, policy ComparisonPolicy) []string {
	t.Helper()
	cards := cardsFrom(t, `
- rule: curve
  constant: {const: EllipticCurves, member: '^(?<name>P256|P384|P521|SECP256K1)$'}
`)
	cards[0].NotIn = []any{&OMap{Keys: []any{"call"}, Vals: []any{"EcJwkGenerator.generateJwk"}}}
	fr := newFrag(constantRefsFrag())
	fr.Comparisons = policy
	found := matchCards(cards, fr)
	got := make([]string, 0, len(found))
	for _, f := range found {
		got = append(got, fmt.Sprintf("%d:%d-%d %s %s", f.Line, f.Col, f.EndCol, f.How, jsonValue(f.Metadata)))
	}
	sort.Strings(got)
	return got
}

// A constant card reports a constant reference wherever it is written, at
// the reference, once; a reference inside a not_in call is left out; an
// argument the fragment has no reference for is still reported at its call.
func TestConstantCardsMatchReferences(t *testing.T) {
	want := []string{
		`3:66-85 constant:assign {"algorithmName": "P521"}`,
		`4:13-32 constant:arg {"algorithmName": "P384"}`,
		`5:16-35 constant:return {"algorithmName": "P521"}`,
		`6:20-44 constant:compare {"algorithmName": "SECP256K1"}`,
		`7:9-34 constant {"algorithmName": "P256"}`,
	}
	if got := constantRefFindings(t, ComparisonsAll); !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n got %v\nwant %v", got, want)
	}
}

// With ComparisonsOff a reference read in a comparison is not reported.
func TestConstantCardsSkipComparisons(t *testing.T) {
	want := []string{
		`3:66-85 constant:assign {"algorithmName": "P521"}`,
		`4:13-32 constant:arg {"algorithmName": "P384"}`,
		`5:16-35 constant:return {"algorithmName": "P521"}`,
		`7:9-34 constant {"algorithmName": "P256"}`,
	}
	if got := constantRefFindings(t, ComparisonsOff); !reflect.DeepEqual(got, want) {
		t.Errorf("findings\n got %v\nwant %v", got, want)
	}
}

// comparedFrag: run(alg) in Demo.java compares alg (its parameter 0, or what
// operand says) with EllipticCurves.P256 (line 5); caller, in callerFile,
// calls run with arg.
func comparedFrag(operand *graphfrag.GraphFragmentParameter, callerFile, arg string) *FragmentJSON {
	frag := &FragmentJSON{
		SchemaVersion: "graph-fragment-1.19",
		Functions: []FunctionJSON{
			{Key: "app.(Demo).run#1", Package: "app", FilePath: "src/Demo.java"},
			{Key: "app.(Caller).go#0", Package: "app", FilePath: callerFile},
		},
		ConstantRefs: []graphfrag.GraphFragmentConstantRef{
			{Function: 0, Line: 5, StartCol: 13, EndCol: 32, Text: "EllipticCurves.P256", Context: "equals", Operand: operand},
		},
	}
	if arg != "" {
		frag.InternalEdgeStrings = []string{"", "exact", "run"}
		frag.InternalEdges = []CompactEdge{{
			N: [13]int{1, 0, 9, 1, 0, 2, 1, 0, 0, 0, 9, 20, 0},
			Entry: &CallSiteJSON{Parameters: []Param{{
				ParameterIndex: 0, ArgumentExpression: arg,
				SourceNodes: []SourceNode{{Type: "VALUE", Name: arg, Value: arg}},
			}}},
		}}
	}
	return frag
}

func comparedFindings(t *testing.T, frag *FragmentJSON) int {
	t.Helper()
	cards := cardsFrom(t, `
- rule: curve
  constant: {const: EllipticCurves, member: '^(?<name>P256|P384)$'}
`)
	fr := newFrag(frag)
	fr.ResolveParams = true
	n := 0
	for _, f := range matchCards(cards, fr) {
		if f.Line == 5 { // the caller's argument is reported at its call
			n++
		}
	}
	return n
}

// A constant read in a comparison is reported only when the value compared
// with it can be that constant: a literal or constant the operand is
// assigned, or what a same-file caller passes for the parameter it is. An
// operand that cannot be resolved, a caller in another file, a field's
// constructor parameter, and a reference with no traced operand are not
// reported; a fragment older than 1.19 (no operands) reports every one.
func TestConstantComparisonNeedsResolvedValue(t *testing.T) {
	zero := 0
	param := func() *graphfrag.GraphFragmentParameter {
		return &graphfrag.GraphFragmentParameter{
			ArgumentExpression: "alg", VariableName: "alg",
			SourceNodes: []graphfrag.GraphFragmentSourceNode{{Type: "PARAMETER", Name: "alg", ParameterIndex: &zero}},
		}
	}
	variable := func(value string) *graphfrag.GraphFragmentParameter {
		return &graphfrag.GraphFragmentParameter{
			ArgumentExpression: "alg", VariableName: "alg",
			SourceNodes: []graphfrag.GraphFragmentSourceNode{{
				Type: "VARIABLE", Name: "alg",
				SourceNodes: []graphfrag.GraphFragmentSourceNode{{Type: "VALUE", Name: value, Value: value}},
			}},
		}
	}
	field := &graphfrag.GraphFragmentParameter{
		ArgumentExpression: "alg", VariableName: "alg",
		SourceNodes: []graphfrag.GraphFragmentSourceNode{{
			Type: "FIELD", Name: "alg",
			SourceNodes: []graphfrag.GraphFragmentSourceNode{{Type: "PARAMETER", Name: "alg", ParameterIndex: &zero}},
		}},
	}
	old := comparedFrag(nil, "", "")
	old.SchemaVersion = "graph-fragment-1.18"
	for name, tc := range map[string]struct {
		frag *FragmentJSON
		want int
	}{
		"parameter, no caller":                  {comparedFrag(param(), "", ""), 0},
		"parameter, same-file caller passes it": {comparedFrag(param(), "src/Demo.java", "EllipticCurves.P256"), 1},
		"parameter, caller passes another":      {comparedFrag(param(), "src/Demo.java", "EllipticCurves.P384"), 0},
		"parameter, qualified constant passed":  {comparedFrag(param(), "src/Demo.java", "org.jose4j.keys.EllipticCurves.P256"), 1},
		"parameter, caller in another file":     {comparedFrag(param(), "src/Other.java", "EllipticCurves.P256"), 0},
		"variable assigned it":                  {comparedFrag(variable("EllipticCurves.P256"), "", ""), 1},
		"variable assigned another":             {comparedFrag(variable("EllipticCurves.P384"), "", ""), 0},
		"field from a constructor parameter":    {comparedFrag(field, "src/Demo.java", "EllipticCurves.P256"), 0},
		"no operand":                            {comparedFrag(nil, "", ""), 0},
		"1.18 fragment":                         {old, 1},
	} {
		if got := comparedFindings(t, tc.frag); got != tc.want {
			t.Errorf("%s: %d findings, want %d", name, got, tc.want)
		}
	}
}
