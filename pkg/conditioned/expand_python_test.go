// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package conditioned

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

// A Python dependency hands its parameter to a selector by keyword:
//
//	def sign(payload, key, alg="HS256", *, curve=None):
//	    jwt.encode(payload, key, algorithm=alg)
//	    ec.generate_private_key(curve)
//
// and the project fills the parameter by position, by keyword, or not at
// all. The rules name the selector with a keyword alternative
// (`param[2|algorithm]`), as the Python rules do: over the closure the
// generic finding is specialized with each value a caller passes, whichever
// way it is passed, and a keyword-only parameter with the value passed
// under its name.
func TestExpand_PythonKeywordSelectors(t *testing.T) {
	t.Parallel()
	app := graphfrag.ComponentKey{Purl: "pkg:pypi/app", Version: "1.0.0"}
	tokens := graphfrag.ComponentKey{Purl: "pkg:pypi/tokens", Version: "2.0.0"}
	index := func(i int) *int { return &i }
	value := func(i int, text string) graphfrag.Parameter {
		return graphfrag.Parameter{ParameterIndex: i, ArgumentExpression: text, ResolvedValue: text}
	}
	keyword := func(i int, name, text string) graphfrag.Parameter {
		p := value(i, text)
		p.Keyword = name
		return p
	}
	call := func(line int, params ...graphfrag.Parameter) graphfrag.ExternalCall {
		return graphfrag.ExternalCall{
			Caller: "app.main.run", TargetSignature: "tokens.sign", Resolution: graphfrag.ResolutionExact,
			MethodName: "sign", Arity: len(params), CallSite: line, EntryCall: &graphfrag.CallSite{Line: line, Parameters: params},
		}
	}
	generic, _ := json.Marshal(map[string]string{"api": "jwt.encode"})
	fragments := map[graphfrag.ComponentKey]graphfrag.Fragment{
		app: {
			Component: app, Functions: []graphfrag.Function{{Signature: "app.main.run"}},
			ExternalCalls: []graphfrag.ExternalCall{
				call(10, value(0, "p"), value(1, "k"), value(2, `"RS256"`)),
				call(11, value(0, "p"), value(1, "k"), keyword(2, "alg", `'ES384'`)),
				call(12, keyword(0, "alg", `"PS512"`), keyword(1, "key", "k"), keyword(2, "payload", "p")),
				call(13, value(0, "p"), value(1, "k"), keyword(2, "curve", `"secp521r1"`)),
				call(14, value(0, "p"), value(1, "k")),
			},
		},
		tokens: {
			Component: tokens, Functions: []graphfrag.Function{{Signature: "tokens.sign"}},
			CryptoOperations: []graphfrag.CryptoOperation{
				{Function: "tokens.sign", FindingID: "encode", RuleID: "python.pyjwt.dynamic", StartLine: 5, Metadata: generic, CryptoCall: &graphfrag.CryptoCall{
					FunctionName: "jwt.encode", Line: 5, Parameters: []graphfrag.Parameter{
						{ParameterIndex: 0, VariableName: "payload", ArgumentExpression: "payload", SourceNodes: []graphfrag.SourceNode{{Type: "PARAMETER", Name: "payload", ParameterIndex: index(0)}}},
						{ParameterIndex: 1, VariableName: "key", ArgumentExpression: "key", SourceNodes: []graphfrag.SourceNode{{Type: "PARAMETER", Name: "key", ParameterIndex: index(1)}}},
						{ParameterIndex: 2, Keyword: "algorithm", VariableName: "alg", ArgumentExpression: "alg", SourceNodes: []graphfrag.SourceNode{{Type: "PARAMETER", Name: "alg", ParameterIndex: index(2)}}},
					},
				}},
				{Function: "tokens.sign", FindingID: "curve", RuleID: "python.cryptography.dynamic", StartLine: 6, Metadata: generic, CryptoCall: &graphfrag.CryptoCall{
					FunctionName: "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key", Line: 6, Parameters: []graphfrag.Parameter{
						{ParameterIndex: 0, VariableName: "curve", ArgumentExpression: "curve", SourceNodes: []graphfrag.SourceNode{{Type: "PARAMETER", Name: "curve", ParameterIndex: index(-1)}}},
					},
				}},
			},
		},
	}
	catalog := catalogOf(t,
		Rule{
			ID: "python.pyjwt.encode-asymmetric", Symbols: []string{"jwt.encode"},
			Metadata: map[string]string{"algorithmName": "$alg", "parameterCondition": `param[2|algorithm]~=^(?P<alg>(?:RS|ES|PS)\d+)$`},
		},
		Rule{
			ID: "python.cryptography.ec-curve", Symbols: []string{"cryptography.hazmat.primitives.asymmetric.ec.generate_private_key"},
			Metadata: map[string]string{"algorithmName": "$curve", "parameterCondition": `param[0|curve]~=^(?P<curve>secp\w+)$`},
		},
	)
	plan := NewPlan(fragments, app, catalog)
	res, err := graphfrag.StitchWithOptions(app, graphfrag.DependencyGraph{app: {tokens}}, fragments,
		graphfrag.StitchOptions{EntryRootedOnly: true, SelectorCalls: plan.Calls})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	var got []string
	for _, expansion := range plan.Expand(res.SelectorValues()) {
		for _, spec := range expansion.Specializations {
			got = append(got, fmt.Sprintf("%s %s %s %s", expansion.Anchor.Operation.FindingID, spec.Rule.ID, spec.Metadata["algorithmName"], spec.Reachability))
		}
	}
	slices.Sort(got)
	want := []string{
		"curve python.cryptography.ec-curve secp521r1 reachable",
		"encode python.pyjwt.encode-asymmetric ES384 reachable",
		"encode python.pyjwt.encode-asymmetric PS512 reachable",
		"encode python.pyjwt.encode-asymmetric RS256 reachable",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("specializations:\n%v\nwant\n%v", got, want)
	}
}
