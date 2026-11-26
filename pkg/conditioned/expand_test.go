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

var (
	project = graphfrag.ComponentKey{Purl: "pkg:generic/project"}
	pkix    = graphfrag.ComponentKey{Purl: "pkg:maven/org.bouncycastle/bcpkix-jdk18on", Version: "1.78.1"}
	prov    = graphfrag.ComponentKey{Purl: "pkg:maven/org.bouncycastle/bcprov-jdk18on", Version: "1.78.1"}
)

const helperCreate = "org.bouncycastle.jcajce.util.(DefaultJcaJceHelper).createSecretKeyFactory#1"

func catalogOf(t *testing.T, rules ...Rule) *Catalog {
	t.Helper()
	catalog, err := NewCatalog(rules)
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	return catalog
}

func pbkdf2Rule() Rule {
	return Rule{
		ID: "fixture.java.bouncycastle.pbkdf2", Message: "PBKDF2", Severity: "INFO",
		Symbols:  []string{"SecretKeyFactory.getInstance"},
		Metadata: map[string]string{"algorithmFamily": "PBKDF2", "algorithmName": "$alg", "operation": "keyderive", "parameterCondition": `param[0]~=^(?P<alg>PBKDF.*)$`},
		PURL:     "pkg:maven/org.bouncycastle/bcprov-jdk18on",
	}
}

func scryptRule() Rule {
	return Rule{
		ID: "fixture.java.bouncycastle.scrypt-bcrypt", Symbols: []string{"javax.crypto.SecretKeyFactory.getInstance"},
		Metadata: map[string]string{"algorithmName": "SCRYPT", "parameterCondition": "param[0]==SCRYPT"},
	}
}

func parameterArgument() []graphfrag.Parameter {
	zero := 0
	return []graphfrag.Parameter{{ParameterIndex: 0, VariableName: "algorithm", ArgumentExpression: "algorithm", SourceNodes: []graphfrag.SourceNode{{Type: "PARAMETER", Name: "algorithm", ParameterIndex: &zero}}}}
}

func getInstance(params []graphfrag.Parameter) *graphfrag.CryptoCall {
	return &graphfrag.CryptoCall{FunctionName: "javax.crypto.SecretKeyFactory.getInstance", Line: 82, Parameters: params}
}

func literal(value string) *graphfrag.CallSite {
	return &graphfrag.CallSite{Line: 1, Parameters: []graphfrag.Parameter{{ArgumentExpression: value, ResolvedValue: value}}}
}

// closure is a project (its own finding is the client's, never an anchor)
// calling bcpkix, which passes "PBKDF-OpenSSL" and
// "SCRYPT" to bcprov's helper, and "AES" from a function nothing calls. The
// helper hands its parameter to SecretKeyFactory.getInstance: a generic
// finding there, one bcprov already specialized itself (PBKDF2withHMacSHA256)
// and one on a call that resolved in place.
func closure() (graphfrag.DependencyGraph, map[graphfrag.ComponentKey]graphfrag.Fragment) {
	generic, _ := json.Marshal(map[string]string{"api": "javax.crypto.SecretKeyFactory.getInstance"})
	specialized, _ := json.Marshal(map[string]string{"parameterCondition": "param[0]==PBKDF2withHMacSHA256"})
	fragments := map[graphfrag.ComponentKey]graphfrag.Fragment{
		project: {
			Component: project, Functions: []graphfrag.Function{{Signature: "app.(Main).run#0"}},
			CryptoOperations: []graphfrag.CryptoOperation{{Function: "app.(Main).run#0", FindingID: "project", Metadata: generic, CryptoCall: getInstance(parameterArgument())}},
			ExternalCalls:    []graphfrag.ExternalCall{{Caller: "app.(Main).run#0", TargetSignature: "org.bouncycastle.openssl.jcajce.(PEMUtilities).getKey#0", Resolution: graphfrag.ResolutionExact, CallSite: 1}},
		},
		pkix: {
			Component: pkix, Functions: []graphfrag.Function{{Signature: "org.bouncycastle.openssl.jcajce.(PEMUtilities).getKey#0"}, {Signature: "org.bouncycastle.cms.(Unused).run#0"}},
			ExternalCalls: []graphfrag.ExternalCall{
				{Caller: "org.bouncycastle.openssl.jcajce.(PEMUtilities).getKey#0", TargetSignature: helperCreate, Resolution: graphfrag.ResolutionExact, CallSite: 327, EntryCall: literal(`"PBKDF-OpenSSL"`)},
				{Caller: "org.bouncycastle.openssl.jcajce.(PEMUtilities).getKey#0", TargetSignature: helperCreate, Resolution: graphfrag.ResolutionExact, CallSite: 330, EntryCall: literal(`"SCRYPT"`)},
				{Caller: "org.bouncycastle.cms.(Unused).run#0", TargetSignature: helperCreate, Resolution: graphfrag.ResolutionExact, CallSite: 9, EntryCall: literal(`"PBKDF2with8BIT"`)},
			},
		},
		prov: {
			Component: prov, Functions: []graphfrag.Function{{Signature: helperCreate}},
			ExternalCalls: []graphfrag.ExternalCall{
				{Caller: helperCreate, TargetSignature: "javax.crypto.(Other).wrap#1", Resolution: graphfrag.ResolutionExact, CallSite: 82, StartCol: 10, EndCol: 60},
				{Caller: helperCreate, TargetSignature: "javax.crypto.(SecretKeyFactory).getInstance#1", Resolution: graphfrag.ResolutionExact, CallSite: 82, StartCol: 16, EndCol: 55},
				{Caller: helperCreate, TargetSignature: "javax.crypto.(Next).line#0", Resolution: graphfrag.ResolutionExact, CallSite: 83, StartCol: 44, EndCol: 55},
			},
			CryptoOperations: []graphfrag.CryptoOperation{
				{Function: helperCreate, FindingID: "generic", RuleID: "jca.dynamic-secret-key-factory", StartLine: 82, Metadata: generic, CryptoCall: getInstance(parameterArgument())},
				{Function: helperCreate, FindingID: "specialized", RuleID: "fixture.java.bouncycastle.pbkdf2", StartLine: 82, Metadata: specialized, CryptoCall: getInstance(parameterArgument())},
				{Function: helperCreate, FindingID: "resolved", RuleID: "jca.dynamic-secret-key-factory", StartLine: 90, Metadata: generic, CryptoCall: getInstance([]graphfrag.Parameter{{ResolvedValue: `"SCRYPT"`}})},
			},
		},
	}
	return graphfrag.DependencyGraph{project: {pkix, prov}, pkix: {prov}}, fragments
}

func expandClosure(t *testing.T, catalog *Catalog) (Plan, []Expansion) {
	t.Helper()
	deps, fragments := closure()
	plan := NewPlan(fragments, project, catalog)
	res, err := graphfrag.StitchWithOptions(project, deps, fragments, graphfrag.StitchOptions{EntryRootedOnly: true, SelectorCalls: plan.Calls})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	return plan, plan.Expand(res.SelectorValues())
}

// The generic finding of a dependency is specialized with the values another
// dependency passes it, by every rule that holds, each with the verdict of the
// call sites passing its value.
func TestExpand_SpecializesAnchorsWithClosureValues(t *testing.T) {
	t.Parallel()
	plan, expansions := expandClosure(t, catalogOf(t, scryptRule(), pbkdf2Rule()))
	if len(plan.Anchors) != 1 || plan.Anchors[0].Operation.FindingID != "generic" || len(plan.Calls) != 1 {
		t.Fatalf("plan: %d anchors, %d calls; want the generic finding only", len(plan.Anchors), len(plan.Calls))
	}
	if len(expansions) != 1 {
		t.Fatalf("%d expansions, want 1", len(expansions))
	}
	got := make([]string, 0, len(expansions[0].Specializations))
	for _, spec := range expansions[0].Specializations {
		got = append(got, fmt.Sprintf("%s %s %s %s", spec.Rule.ID, spec.ConditionedValue, spec.Metadata["algorithmName"], spec.Reachability))
	}
	slices.Sort(got)
	want := []string{
		"fixture.java.bouncycastle.pbkdf2 param[0]==PBKDF-OpenSSL PBKDF-OpenSSL reachable",
		"fixture.java.bouncycastle.pbkdf2 param[0]==PBKDF2with8BIT PBKDF2with8BIT unreachable",
		"fixture.java.bouncycastle.scrypt-bcrypt param[0]==SCRYPT SCRYPT reachable",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("specializations:\n%v\nwant\n%v", got, want)
	}
	spec := expansions[0].Specializations[0]
	if spec.Metadata["parameterCondition"] != spec.ConditionedValue || len(spec.Conditions) != 1 || expansions[0].Truncated {
		t.Errorf("specialization %+v: metadata condition, conditions or truncation wrong", spec)
	}
}

// Without a rule for the call there is nothing to trace.
func TestNewPlan_NoRuleNoAnchor(t *testing.T) {
	t.Parallel()
	_, fragments := closure()
	other := Rule{ID: "r", Symbols: []string{"Cipher.getInstance"}, Metadata: map[string]string{"parameterCondition": "param[0]==AES"}}
	if plan := NewPlan(fragments, project, catalogOf(t, other)); len(plan.Anchors) != 0 || len(plan.Calls) != 0 {
		t.Fatalf("plan has %d anchors, want none", len(plan.Anchors))
	}
	if plan := NewPlan(fragments, project, nil); len(plan.Anchors) != 0 {
		t.Fatalf("nil catalog: %d anchors, want none", len(plan.Anchors))
	}
}

func TestCatalogRulesFor(t *testing.T) {
	t.Parallel()
	catalog := catalogOf(t, scryptRule(), pbkdf2Rule(), Rule{ID: "c", Symbols: []string{"Cipher.getInstance"}, Metadata: map[string]string{"parameterCondition": "param[0]==AES"}})
	ids := func(rules []*Rule) []string {
		out := make([]string, 0, len(rules))
		for _, r := range rules {
			out = append(out, r.ID)
		}
		return out
	}
	if got := ids(catalog.RulesFor("javax.crypto.SecretKeyFactory.getInstance")); !slices.Equal(got, []string{"fixture.java.bouncycastle.pbkdf2", "fixture.java.bouncycastle.scrypt-bcrypt"}) {
		t.Errorf("RulesFor(qualified) = %v", got)
	}
	if got := ids(catalog.RulesFor("SecretKeyFactory.getInstance")); !slices.Equal(got, []string{"fixture.java.bouncycastle.pbkdf2", "fixture.java.bouncycastle.scrypt-bcrypt"}) {
		t.Errorf("RulesFor(short) = %v", got)
	}
	twice := catalogOf(t, scryptRule(), scryptRule())
	if got := ids(twice.RulesFor("SecretKeyFactory.getInstance")); len(got) != 1 {
		t.Errorf("a rule listed twice: RulesFor = %v, want it once", got)
	}
	if got := ids(catalog.RulesFor("javax.crypto.OtherSecretKeyFactory.getInstance")); len(got) != 0 {
		t.Errorf("RulesFor(another type) = %v, want none", got)
	}
}

func TestNewCatalogRejectsRulesItCannotApply(t *testing.T) {
	t.Parallel()
	for name, rule := range map[string]Rule{
		"no condition":   {ID: "r", Symbols: []string{"A.b"}, Metadata: map[string]string{}},
		"bad condition":  {ID: "r", Symbols: []string{"A.b"}, Metadata: map[string]string{"parameterCondition": "arg0 is AES"}},
		"no symbols":     {ID: "r", Metadata: map[string]string{"parameterCondition": "param[0]==AES"}},
		"bad binder":     {ID: "r", Symbols: []string{"A.b"}, Metadata: map[string]string{"parameterCondition": "param[0]==AES"}, CaptureBinders: []string{"("}},
		"no rule id set": {Symbols: []string{"A.b"}, Metadata: map[string]string{"parameterCondition": "param[0]==AES"}},
	} {
		if _, err := NewCatalog([]Rule{rule}); err == nil {
			t.Errorf("%s: NewCatalog accepted it", name)
		}
	}
}

// The terminal call of a finding is the narrowest call on its line that holds
// its span.
func TestTerminalColumns(t *testing.T) {
	t.Parallel()
	_, fragments := closure()
	fragment := fragments[prov]
	op := &fragment.CryptoOperations[0]
	if s, e := TerminalColumns(&fragment, op, 45, 54); s != 16 || e != 55 {
		t.Errorf("TerminalColumns = %d, %d; want 16, 55 (the getInstance call)", s, e)
	}
	if s, e := TerminalColumns(&fragment, op, 20, 58); s != 10 || e != 60 {
		t.Errorf("span only the outer call holds: %d, %d; want 10, 60", s, e)
	}
	if s, e := TerminalColumns(&fragment, op, 5, 70); s != 0 || e != 0 {
		t.Errorf("span no call holds: %d, %d; want 0, 0", s, e)
	}
}

// The ids are pinned: a change to how a finding id is hashed changes every
// stored report's ids.
func TestFindingIDAndOccurrenceKey(t *testing.T) {
	t.Parallel()
	if got := FindingID("org/bouncycastle/jcajce/util/DefaultJcaJceHelper.java", 82, "fixture.java.bouncycastle.pbkdf2", "param[0]==PBKDF2withHMacSHA256"); got != "c5ad0ba7" {
		t.Errorf("FindingID = %s, want c5ad0ba7", got)
	}
	if got := FindingID("a.java", 1, "r", ""); got != FindingID("a.java", 1, "r", "") || got == FindingID("a.java", 1, "r", "param[0]==X") {
		t.Errorf("FindingID does not tell values apart")
	}
	a, b := OccurrenceKey("v1:199a0d1c6e929520", "param[0]==SCRYPT"), OccurrenceKey("v1:199a0d1c6e929520", "param[0]==PBKDF2")
	if a == b || len(a) != len("v1:")+16 || a != OccurrenceKey("v1:199a0d1c6e929520", "param[0]==SCRYPT") {
		t.Errorf("OccurrenceKey = %q, %q: want distinct, stable v1 keys", a, b)
	}
	if OccurrenceKey("", "param[0]==SCRYPT") != "" {
		t.Error("OccurrenceKey without an anchor key is not empty")
	}
}
