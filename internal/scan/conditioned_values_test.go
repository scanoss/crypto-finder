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
	// The blank anchor is dropped once its call is specialized, so every
	// remaining asset is a per-value one.
	assets := report.Findings[0].CryptographicAssets
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

	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: g.graph, Ecosystem: "java"}, []string{rules}); got != values {
		t.Fatalf("MaterializeConditionedFindings() = %d, want %d", got, values)
	}
	assertNames(t, specializedNames(t, report), wantVariantNames(values))
	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: g.graph, Ecosystem: "java"}, []string{rules}); got != 0 {
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

	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: g.graph, Ecosystem: "java"}, []string{rules}); got != values+1 {
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

	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: g.graph, Ecosystem: "java"}, []string{rules}); got != values {
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
	variants, _, _ := enumerator.terminalVariants(helper.ID, terminal.Parameters)
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
	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: g.graph, Ecosystem: "java"}, []string{rules}); got != values {
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

// addForwarderChain stacks depth functions that each forward their parameter to
// the one below, ending at the helper, and returns the topmost one. A literal
// caller beside each hop keeps its parameter multi-sourced, so the export does
// not inline the chain ahead of the walk.
func (g selectorGraph) addForwarderChain(depth int) callgraph.FunctionID {
	below := selectorHelperID
	for i := range depth {
		id := callgraph.FunctionID{Package: "example", Type: "Chain", Name: fmt.Sprintf("hop%03d#1", i)}
		g.addFunction(&callgraph.FunctionDecl{
			ID: id, FilePath: "Digests.java", StartLine: 20, EndLine: 30,
			Parameters: []callgraph.FunctionParameter{{Name: "algorithm", Type: "String"}},
			Calls:      []callgraph.FunctionCall{forwardCall(below, "algorithm", 21)},
		})
		g.addLiteralCaller(fmt.Sprintf("side%03d", i), id, 0)
		below = id
	}
	g.addLiteralCaller("direct", selectorHelperID, 0)
	return below
}

func partialChainFindings(payload *callGraphExportV2) (partial, total int) {
	for i := range payload.FindingGraphs {
		total++
		if a := payload.FindingGraphs[i].Analysis; a != nil && a.CallChains == graphfrag.AnalysisPartial {
			partial++
		}
	}
	return partial, total
}

// A caller value beyond the depth cap, or past the value bound, is not
// enumerated. That must reach the export: the finding's call chains read
// partial, where a walk that completed leaves them complete.
func TestConditionedValueEnumeration_TruncationReportsPartialChains(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, selectorValueRules)
	cases := []struct {
		name        string
		depth       int
		callers     int
		maxValue    int
		wantPartial bool
	}{
		{name: "shallow chain completes", depth: 3, callers: 1, wantPartial: false},
		{name: "chain at the depth cap", depth: maxConditionedWalkDepth - 1, callers: 1, wantPartial: false},
		{name: "chain deeper than the depth cap", depth: maxConditionedWalkDepth + 2, callers: 1, wantPartial: true},
		{name: "values past the bound", depth: 1, callers: maxConditionedSelectorValues + 5, wantPartial: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := newSelectorGraph()
			top := g.addForwarderChain(tc.depth)
			for i := range tc.callers {
				g.addLiteralCaller(fmt.Sprintf("top%03d", i), top, i+1)
			}
			report := g.report()
			MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: g.graph, Ecosystem: "java"}, []string{rules})

			anchor := report.Findings[0].CryptographicAssets[0]
			if anchor.ConditionedValuesIncomplete != tc.wantPartial {
				t.Errorf("anchor ConditionedValuesIncomplete = %v, want %v", anchor.ConditionedValuesIncomplete, tc.wantPartial)
			}
			payload := buildCallGraphExportV2(&engine.DepScanResult{Report: report, CallGraph: g.graph, Ecosystem: "java"})
			partial, total := partialChainFindings(&payload)
			if total == 0 {
				t.Fatal("export holds no finding graph")
			}
			if tc.wantPartial && partial != total {
				t.Errorf("%d of %d finding graphs read analysis.call_chains partial, want all", partial, total)
			}
			if !tc.wantPartial && partial != 0 {
				t.Errorf("%d finding graphs read analysis.call_chains partial, want none", partial)
			}
		})
	}
}

// addDynamicCaller adds a function that calls callee with an argument the graph
// cannot resolve.
func (g selectorGraph) addDynamicCaller(name string, callee callgraph.FunctionID) callgraph.FunctionID {
	id := callgraph.FunctionID{Package: "example", Type: "Callers", Name: name + "#0"}
	g.addFunction(&callgraph.FunctionDecl{
		ID: id, FilePath: "Callers.java",
		Calls: []callgraph.FunctionCall{{
			Callee: callee, FilePath: "Callers.java", Line: 8, StartCol: 9, EndCol: 30,
			Arguments:       []string{"fromConfig()"},
			ArgumentSources: [][]callgraph.SourceNode{{{Type: "CALL_RESULT", Name: "fromConfig"}}},
		}},
	})
	return id
}

func blankAnchors(report *entities.InterimReport) int {
	blank := 0
	assets := report.Findings[0].CryptographicAssets
	for i := range assets {
		if len(assets[i].ParameterConditions) == 0 {
			blank++
		}
	}
	return blank
}

// The blank anchor is the report's only entry for a caller whose value does not
// resolve, so it stays beside the per-value assets of the callers that do, and
// its chains still reach that caller.
func TestMaterializeConditionedFindings_KeepsAnchorForDynamicCaller(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, selectorValueRules)
	g := newSelectorGraph()
	g.addLiteralCaller("literal", selectorHelperID, 1)
	dynamicID := g.addDynamicCaller("dynamic", selectorHelperID)
	report := g.report()

	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: g.graph, Ecosystem: "java"}, []string{rules}); got != 1 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want 1", got)
	}
	if got := blankAnchors(report); got != 1 {
		t.Fatalf("blank anchors = %d, want the anchor kept for the dynamic caller (assets %v)", got, specializedNames(t, report))
	}
	var anchor entities.CryptographicAsset
	for _, asset := range report.Findings[0].CryptographicAssets {
		if len(asset.ParameterConditions) == 0 {
			anchor = asset
		}
	}
	ctx := newExportBuildContext(&engine.DepScanResult{Report: report, CallGraph: g.graph, Ecosystem: "java"})
	fg := buildFindingGraph(ctx, report.Findings[0], anchor)
	for _, chain := range fg.CallChains {
		for _, node := range chain {
			if node.FunctionKey == dynamicID.String() {
				return
			}
		}
	}
	t.Fatalf("anchor call chains %d do not reach the dynamic caller %s", len(fg.CallChains), dynamicID)
}

// A value no rule matches is as unaccounted for as a dynamic one.
func TestMaterializeConditionedFindings_KeepsAnchorForUnmatchedValue(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, selectorValueRules)
	g := newSelectorGraph()
	g.addLiteralCaller("literal", selectorHelperID, 1)
	g.addFunction(&callgraph.FunctionDecl{
		ID: callgraph.FunctionID{Package: "example", Type: "Callers", Name: "other#0"}, FilePath: "Callers.java",
		Calls: []callgraph.FunctionCall{{
			Callee: selectorHelperID, FilePath: "Callers.java", Line: 9, StartCol: 9, EndCol: 30,
			Arguments: []string{`"FOO"`}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: `"FOO"`}}},
		}},
	})
	report := g.report()

	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: g.graph, Ecosystem: "java"}, []string{rules}); got != 1 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want 1", got)
	}
	if got := blankAnchors(report); got != 1 {
		t.Fatalf("blank anchors = %d, want the anchor kept for the unmatched value", got)
	}
}

// The helper is also reached through a forwarder that nothing calls, so the
// forwarded value is unknown too.
func TestMaterializeConditionedFindings_KeepsAnchorBehindUncalledForwarder(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, selectorValueRules)
	g := newSelectorGraph()
	g.addLiteralCaller("literal", selectorHelperID, 1)
	g.addFunction(&callgraph.FunctionDecl{
		ID: callgraph.FunctionID{Package: "example", Type: "Digests", Name: "forward#1"}, FilePath: "Digests.java", StartLine: 20, EndLine: 22,
		Parameters: []callgraph.FunctionParameter{{Name: "name", Type: "String"}},
		Calls:      []callgraph.FunctionCall{forwardCall(selectorHelperID, "name", 21)},
	})
	report := g.report()

	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: g.graph, Ecosystem: "java"}, []string{rules}); got != 1 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want 1", got)
	}
	if got := blankAnchors(report); got != 1 {
		t.Fatalf("blank anchors = %d, want the anchor kept for the forwarded unknown value", got)
	}
}

// The dynamic caller's route can fall beyond the chain budget, where only the
// value enumeration sees it.
func TestMaterializeConditionedFindings_KeepsAnchorForDynamicCallerBeyondChainBudget(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, selectorValueRules)
	values := graphfrag.DefaultMaxChainsPerOp + 12
	g := newSelectorGraph()
	for i := range values {
		g.addLiteralCaller(fmt.Sprintf("caller%03d", i), selectorHelperID, i)
	}
	g.addDynamicCaller("zdynamic", selectorHelperID)
	report := g.report()

	if got := MaterializeConditionedFindings(report, &engine.DepScanResult{CallGraph: g.graph, Ecosystem: "java"}, []string{rules}); got != values {
		t.Fatalf("MaterializeConditionedFindings() = %d, want %d", got, values)
	}
	if got := blankAnchors(report); got != 1 {
		t.Fatalf("blank anchors = %d, want the anchor kept for the dynamic caller", got)
	}
}
