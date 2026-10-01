// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"fmt"
	"sort"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

const selectorValueRules = `rules:
  - id: java.digest.variant
    message: Variant digest
    severity: INFO
    pattern: MessageDigest.getInstance($ALGO)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: VARIANT
        algorithmName: V$n
        parameterCondition: param[0]~=V(?<n>[0-9]+)
        operation: digest
        api: MessageDigest.getInstance
`

var (
	selectorHelperID = callgraph.FunctionID{Package: "example", Type: "Digests", Name: "getDigest#1"}
	selectorTargetID = callgraph.FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance#1"}
)

// selectorGraph is a call graph whose helper forwards its parameter to
// MessageDigest.getInstance, the conditioned anchor.
type selectorGraph struct{ graph *callgraph.CallGraph }

func newSelectorGraph() selectorGraph {
	helper := &callgraph.FunctionDecl{
		ID: selectorHelperID, FilePath: "Digests.java", StartLine: 10, EndLine: 12,
		Parameters: []callgraph.FunctionParameter{{Name: "algorithm", Type: "String"}},
		Calls:      []callgraph.FunctionCall{forwardCall(selectorTargetID, "algorithm", 11)},
	}
	return selectorGraph{graph: &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{selectorHelperID.String(): helper},
		Callers:   map[string][]string{},
	}}
}

func forwardCall(callee callgraph.FunctionID, parameter string, line int) callgraph.FunctionCall {
	return callgraph.FunctionCall{
		Callee: callee, FilePath: "Digests.java", Line: line, StartCol: 16, EndCol: 52,
		Arguments:       []string{parameter},
		ArgumentSources: [][]callgraph.SourceNode{{{Type: "PARAMETER", Name: parameter, ParameterIndex: 0}}},
	}
}

func (g selectorGraph) addFunction(fn *callgraph.FunctionDecl) {
	g.graph.Functions[fn.ID.String()] = fn
	for i := range fn.Calls {
		callee := fn.Calls[i].Callee.String()
		g.graph.Callers[callee] = append(g.graph.Callers[callee], fn.ID.String())
	}
}

// addLiteralCaller adds a function that calls callee with the literal "V<value>".
func (g selectorGraph) addLiteralCaller(name string, callee callgraph.FunctionID, value int) {
	literal := fmt.Sprintf("%q", fmt.Sprintf("V%d", value))
	g.addFunction(&callgraph.FunctionDecl{
		ID: callgraph.FunctionID{Package: "example", Type: "Callers", Name: name + "#0"}, FilePath: "Callers.java",
		Calls: []callgraph.FunctionCall{{
			Callee: callee, FilePath: "Callers.java", Line: 5, StartCol: 9, EndCol: 30,
			Arguments: []string{literal}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: literal}}},
		}},
	})
}

func (g selectorGraph) report() *entities.InterimReport {
	return &entities.InterimReport{Findings: []entities.Finding{{FilePath: "Digests.java", Language: "java", CryptographicAssets: []entities.CryptographicAsset{{
		StartLine: 11, EndLine: 11, StartCol: 16, EndCol: 52, Match: "MessageDigest.getInstance(algorithm)",
		Rules: []entities.RuleInfo{{ID: "java.digest.dynamic"}}, Metadata: map[string]string{"api": "java.security.MessageDigest.getInstance"},
	}}}}}
}

func specializedNames(t *testing.T, report *entities.InterimReport) []string {
	t.Helper()
	assets := report.Findings[0].CryptographicAssets[1:]
	names := make([]string, 0, len(assets))
	for i := range assets {
		names = append(names, assets[i].Metadata["algorithmName"])
	}
	sort.Strings(names)
	return names
}

func wantVariantNames(count int) []string {
	names := make([]string, count)
	for i := range count {
		names[i] = fmt.Sprintf("V%d", i)
	}
	sort.Strings(names)
	return names
}

func assertNames(t *testing.T, got, want []string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("specialized %d assets %v, want %d assets %v", len(got), got, len(want), want)
	}
}

// More distinct callers than the chain budget: the sampled chains cannot hold
// every value, and each caller's value must still become one asset.
func TestMaterializeConditionedFindings_SpecializesEveryCallerBeyondChainBudget(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, selectorValueRules)
	values := graphfrag.DefaultMaxChainsPerOp + 12
	g := newSelectorGraph()
	for i := range values {
		g.addLiteralCaller(fmt.Sprintf("caller%03d", i), selectorHelperID, i)
		// A second caller per value: one value through many callers is one asset.
		g.addLiteralCaller(fmt.Sprintf("again%03d", i), selectorHelperID, i)
	}
	report := g.report()

	if got := MaterializeConditionedFindings(report, g.graph, []string{rules}, "java"); got != values {
		t.Fatalf("MaterializeConditionedFindings() = %d, want %d", got, values)
	}
	assertNames(t, specializedNames(t, report), wantVariantNames(values))
	if got := MaterializeConditionedFindings(report, g.graph, []string{rules}, "java"); got != 0 {
		t.Fatalf("second MaterializeConditionedFindings() = %d, want idempotent 0", got)
	}
}

// Callers reach the helper through an intermediate method that forwards its
// own parameter, so each value is two parameter hops away from the anchor.
func TestMaterializeConditionedFindings_FollowsTwoLevelParameterForwarding(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, selectorValueRules)
	values := graphfrag.DefaultMaxChainsPerOp + 5
	middleID := callgraph.FunctionID{Package: "example", Type: "Digests", Name: "digestFor#1"}
	g := newSelectorGraph()
	g.addFunction(&callgraph.FunctionDecl{
		ID: middleID, FilePath: "Digests.java", StartLine: 20, EndLine: 22,
		Parameters: []callgraph.FunctionParameter{{Name: "name", Type: "String"}},
		Calls:      []callgraph.FunctionCall{forwardCall(selectorHelperID, "name", 21)},
	})
	for i := range values {
		g.addLiteralCaller(fmt.Sprintf("caller%03d", i), middleID, i)
	}
	// A direct caller keeps the helper's parameter multi-sourced. With the
	// intermediate as its only caller, export inlines that one caller's
	// parameter ahead of the walk, and neither chains nor this walk resolve it.
	g.addLiteralCaller("direct", selectorHelperID, values)
	report := g.report()

	if got := MaterializeConditionedFindings(report, g.graph, []string{rules}, "java"); got != values+1 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want %d", got, values+1)
	}
	assertNames(t, specializedNames(t, report), wantVariantNames(values+1))
}

// The helper forwards its parameter to itself. The walk must end and still
// collect every outside caller's value.
func TestMaterializeConditionedFindings_StopsAtParameterCycle(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, selectorValueRules)
	values := graphfrag.DefaultMaxChainsPerOp + 3
	g := newSelectorGraph()
	helper := g.graph.Functions[selectorHelperID.String()]
	helper.Calls = append(helper.Calls, forwardCall(selectorHelperID, "algorithm", 12))
	g.graph.Callers[selectorHelperID.String()] = append(g.graph.Callers[selectorHelperID.String()], selectorHelperID.String())
	for i := range values {
		g.addLiteralCaller(fmt.Sprintf("caller%03d", i), selectorHelperID, i)
	}
	report := g.report()

	if got := MaterializeConditionedFindings(report, g.graph, []string{rules}, "java"); got != values {
		t.Fatalf("MaterializeConditionedFindings() = %d, want %d", got, values)
	}
	assertNames(t, specializedNames(t, report), wantVariantNames(values))
}

// Past the bound the enumeration stops and says it was cut short.
func TestConditionedValueEnumerator_StopsAtValueBound(t *testing.T) {
	t.Parallel()

	g := newSelectorGraph()
	for i := range 10 {
		g.addLiteralCaller(fmt.Sprintf("caller%03d", i), selectorHelperID, i)
	}
	report := g.report()
	ctx := newExportBuildContext(&engine.DepScanResult{Report: report, CallGraph: g.graph, Ecosystem: "java"})
	helper := g.graph.Functions[selectorHelperID.String()]
	terminal := buildCryptoCall(ctx, g.graph, helper, &helper.Calls[0])

	enumerator := newConditionedValueEnumerator(ctx)
	enumerator.maxValue = 4
	variants, complete := enumerator.resolveVariants(helper.ID, terminal.Parameters, 0, 0)
	if complete {
		t.Fatal("resolveVariants() complete = true, want false at the value bound")
	}
	distinct := make(map[string]struct{})
	for _, params := range variants {
		distinct[params[0].ResolvedValue] = struct{}{}
	}
	if len(variants) != 4 || len(distinct) != 4 {
		t.Fatalf("resolveVariants() = %d variants (%d distinct), want 4 distinct", len(variants), len(distinct))
	}

	enumerator = newConditionedValueEnumerator(ctx)
	if variants, complete = enumerator.resolveVariants(helper.ID, terminal.Parameters, 0, 0); !complete || len(variants) != 10 {
		t.Fatalf("resolveVariants() = %d variants, complete %v; want all 10, complete", len(variants), complete)
	}
}

// A recursion above a stack of diamonds: the walk below the recursion is only
// partial from each entry, so before the per-walk memo every path through the
// diamonds was re-walked, doubling the work per layer. Each (function,
// parameter) must now be walked once, and every value must still arrive.
func TestConditionedValueEnumerator_WalksOnceBelowARecursion(t *testing.T) {
	t.Parallel()

	const layers = 16
	g := newSelectorGraph()
	forwarder := func(name string, callees ...callgraph.FunctionID) callgraph.FunctionID {
		id := callgraph.FunctionID{Package: "example", Type: "Layers", Name: name + "#1"}
		fn := &callgraph.FunctionDecl{
			ID: id, FilePath: "Digests.java", StartLine: 20, EndLine: 30,
			Parameters: []callgraph.FunctionParameter{{Name: "algorithm", Type: "String"}},
		}
		for i, callee := range callees {
			fn.Calls = append(fn.Calls, forwardCall(callee, "algorithm", 21+i))
		}
		g.addFunction(fn)
		return id
	}
	below := []callgraph.FunctionID{selectorHelperID}
	for layer := range layers {
		below = []callgraph.FunctionID{
			forwarder(fmt.Sprintf("l%02da", layer), below...),
			forwarder(fmt.Sprintf("l%02db", layer), below...),
		}
	}
	// The top layer calls itself, which is what made every result below it
	// partial.
	top := g.graph.Functions[below[0].String()]
	top.Calls = append(top.Calls, forwardCall(below[0], "algorithm", 29))
	g.graph.Callers[below[0].String()] = append(g.graph.Callers[below[0].String()], below[0].String())
	const values = 3
	for i := range values {
		g.addLiteralCaller(fmt.Sprintf("caller%03d", i), below[i%2], i)
	}

	report := g.report()
	ctx := newExportBuildContext(&engine.DepScanResult{Report: report, CallGraph: g.graph, Ecosystem: "java"})
	helper := g.graph.Functions[selectorHelperID.String()]
	terminal := buildCryptoCall(ctx, g.graph, helper, &helper.Calls[0])

	enumerator := newConditionedValueEnumerator(ctx)
	variants := enumerator.terminalVariants(helper.ID, terminal.Parameters)
	distinct := make(map[string]struct{})
	for _, params := range variants {
		distinct[params[0].ResolvedValue] = struct{}{}
	}
	if len(distinct) != values {
		t.Fatalf("terminalVariants() = %d distinct values %v, want %d", len(distinct), distinct, values)
	}
	// One walk per forwarding function and per literal caller, plus the helper.
	if limit := 2*layers + values + 1; enumerator.walks > limit {
		t.Fatalf("walked %d times, want at most %d: a partial result below the recursion was re-walked per path", enumerator.walks, limit)
	}
}

// A value that only the enumeration found, from a caller outside the chain
// sample, has no sampled chain left after per-asset filtering. Its chain set
// is then incomplete: the export must not call an empty set complete.
func TestBuildCallGraphExport_OutOfSampleValueReportsPartialChains(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, selectorValueRules)
	values := graphfrag.DefaultMaxChainsPerOp + 12
	g := newSelectorGraph()
	for i := range values {
		g.addLiteralCaller(fmt.Sprintf("caller%03d", i), selectorHelperID, i)
	}
	report := g.report()
	if got := MaterializeConditionedFindings(report, g.graph, []string{rules}, "java"); got != values {
		t.Fatalf("MaterializeConditionedFindings() = %d, want %d", got, values)
	}

	payload := buildCallGraphExportV2(&engine.DepScanResult{Report: report, CallGraph: g.graph, Ecosystem: "java"})
	emptied := 0
	for i := range payload.FindingGraphs {
		fg := &payload.FindingGraphs[i]
		if len(fg.CallChains) != 0 || fg.Analysis == nil {
			continue
		}
		emptied++
		if fg.Analysis.CallChains != graphfrag.AnalysisPartial {
			t.Errorf("finding graph %s has no call chains but analysis.call_chains = %q, want %q",
				fg.FindingID, fg.Analysis.CallChains, graphfrag.AnalysisPartial)
		}
	}
	if emptied == 0 {
		t.Fatal("no specialized finding lost all its sampled chains; the test needs more callers than the chain budget")
	}
}
