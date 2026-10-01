// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// routeSelectorGraph is one library function that forwards its parameter to
// MessageDigest.getInstance, reached by two application callers: one calls it
// exactly with "V1", the other through an interface dispatch with "V2".
func routeSelectorGraph() *callgraph.CallGraph {
	return routeSelectorGraphOf(
		routeCaller{typ: "Direct", value: 1, kind: callgraph.EdgeKindExact},
		routeCaller{typ: "Dispatched", value: 2, kind: callgraph.EdgeKindInterfaceDispatch},
	)
}

// routeCaller is one application caller of the library function: it calls it
// with the literal "V<value>" over an edge of the given kind, and is a
// recognized entry point when entry is set (otherwise nothing calls it).
type routeCaller struct {
	typ   string
	value int
	kind  callgraph.EdgeKind
	entry bool
}

func routeSelectorGraphOf(callers ...routeCaller) *callgraph.CallGraph {
	helperID := callgraph.FunctionID{Package: "org.lib", Type: "Digests", Name: "getDigest#1"}
	helper := &callgraph.FunctionDecl{
		ID: helperID, FilePath: "Digests.java", StartLine: 10, EndLine: 12,
		Parameters: []callgraph.FunctionParameter{{Name: "algorithm", Type: "String"}},
		Calls:      []callgraph.FunctionCall{forwardCall(selectorTargetID, "algorithm", 11)},
	}
	graph := &callgraph.CallGraph{
		Functions:       map[string]*callgraph.FunctionDecl{helperID.String(): helper},
		Callers:         map[string][]string{},
		EdgeResolutions: map[string]callgraph.EdgeResolution{},
	}
	for _, c := range callers {
		literal := fmt.Sprintf("%q", fmt.Sprintf("V%d", c.value))
		id := callgraph.FunctionID{Package: "com.app", Type: c.typ, Name: "run#0"}
		fn := &callgraph.FunctionDecl{
			ID: id, FilePath: c.typ + ".java", StartLine: 1, EndLine: 9,
			Calls: []callgraph.FunctionCall{{
				Callee: helperID, FilePath: c.typ + ".java", Line: 5, StartCol: 9, EndCol: 30,
				Arguments: []string{literal}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: literal}}},
			}},
		}
		if c.entry {
			fn.EntryKind = callgraph.RootKindFrameworkEntry
		}
		graph.Functions[id.String()] = fn
		graph.Callers[helperID.String()] = append(graph.Callers[helperID.String()], id.String())
		res := callgraph.EdgeResolution{Kind: c.kind, CallSite: 5, StartCol: 9, EndCol: 30, DeclaredType: "org.lib.Digester"}
		graph.EdgeResolutions[callgraph.EdgeResolutionKey(id.String(), helperID.String(), res)] = res
	}
	return graph
}

// perValueGraphs materializes the selector rule over graph and returns the
// export's finding graph of each specialized asset, keyed by its value name.
func perValueGraphs(t *testing.T, graph *callgraph.CallGraph, wantAssets int) map[string]callGraphExportFinding {
	t.Helper()
	rules := writeConditionedRules(t, selectorValueRules)
	report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "Digests.java", Language: "java", CryptographicAssets: []entities.CryptographicAsset{{
		StartLine: 11, EndLine: 11, StartCol: 16, EndCol: 52, Match: "MessageDigest.getInstance(algorithm)",
		Rules: []entities.RuleInfo{{ID: "java.digest.dynamic"}}, Metadata: map[string]string{"api": "java.security.MessageDigest.getInstance"},
	}}}}}
	if got := MaterializeConditionedFindings(report, graph, []string{rules}, "java"); got != wantAssets {
		t.Fatalf("MaterializeConditionedFindings() = %d, want %d", got, wantAssets)
	}
	assets := report.Findings[0].CryptographicAssets
	for i := range assets {
		assets[i].FindingID = fmt.Sprintf("finding-%d", i)
	}
	payload := buildCallGraphExportV2(&engine.DepScanResult{
		Report: report, CallGraph: graph, Ecosystem: "java", RootModule: "com.app",
		Dependencies: []dependency.Dependency{{Module: "org.lib:digest"}},
	})
	out := map[string]callGraphExportFinding{}
	for i := range payload.FindingGraphs {
		for j := range assets {
			if assets[j].FindingID == payload.FindingGraphs[i].FindingID {
				out[assets[j].Metadata["algorithmName"]] = payload.FindingGraphs[i]
			}
		}
	}
	return out
}

// Two findings in one function, specialized by different values. The cached
// per-function trace rates the direct route, but the V2 finding's condition
// refutes it: only a dispatch route survives, so that is its evidence. A V1
// finding keeps the direct route and its evidence.
func TestBuildCallGraphExport_ConditionedFindingRatesItsSurvivingRoutes(t *testing.T) {
	t.Parallel()

	rules := writeConditionedRules(t, selectorValueRules)
	graph := routeSelectorGraph()
	report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "Digests.java", Language: "java", CryptographicAssets: []entities.CryptographicAsset{{
		StartLine: 11, EndLine: 11, StartCol: 16, EndCol: 52, Match: "MessageDigest.getInstance(algorithm)",
		Rules: []entities.RuleInfo{{ID: "java.digest.dynamic"}}, Metadata: map[string]string{"api": "java.security.MessageDigest.getInstance"},
	}}}}}
	if got := MaterializeConditionedFindings(report, graph, []string{rules}, "java"); got != 2 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want 2", got)
	}
	assets := report.Findings[0].CryptographicAssets
	for i := range assets {
		assets[i].FindingID = fmt.Sprintf("finding-%d", i)
	}

	payload := buildCallGraphExportV2(&engine.DepScanResult{
		Report: report, CallGraph: graph, Ecosystem: "java", RootModule: "com.app",
		Dependencies: []dependency.Dependency{{Module: "org.lib:digest"}},
	})

	evidence := map[string]string{}
	for i := range payload.FindingGraphs {
		fg := &payload.FindingGraphs[i]
		for j := range assets {
			if assets[j].FindingID == fg.FindingID && len(assets[j].ParameterConditions) > 0 {
				if fg.Analysis == nil {
					t.Fatalf("finding %s has no analysis", assets[j].Metadata["algorithmName"])
				}
				evidence[assets[j].Metadata["algorithmName"]] = fg.Analysis.RouteEvidence
			}
		}
	}
	want := map[string]string{"V1": graphfrag.RouteEvidenceDirect, "V2": graphfrag.RouteEvidenceDispatch}
	for name, tier := range want {
		if evidence[name] != tier {
			t.Errorf("route_evidence of the %s finding = %q, want %q (all: %v)", name, evidence[name], tier, evidence)
		}
	}
}

// A specialized finding whose condition leaves no chain has no route to rate.
func TestReviseRouteEvidence_NoSurvivingChainLeavesEvidenceEmpty(t *testing.T) {
	t.Parallel()

	fg := callGraphExportFinding{Analysis: &graphfrag.ExportFindingAnalysis{
		RouteEvidence: graphfrag.RouteEvidenceDirect, NoCallersOnly: true,
	}}
	reviseRouteEvidence(&fg, true)
	if fg.Analysis.RouteEvidence != "" || fg.Analysis.NoCallersOnly {
		t.Fatalf("Analysis = %+v, want empty route_evidence and no_callers_only false", fg.Analysis)
	}
}

// no_callers_only is rated over the surviving routes that support the verdict:
// those free of name_only edges, or all of them when each needs one.
func TestReviseRouteEvidence_NoCallersOnlyReadsSurvivingChains(t *testing.T) {
	t.Parallel()

	chain := func(root string, resolution string) []callGraphChainNode {
		return []callGraphChainNode{
			{FunctionName: "root", RootKind: root},
			{FunctionName: "sink", EntryResolution: resolution},
		}
	}
	tests := []struct {
		name         string
		chains       [][]callGraphChainNode
		wantEvidence string
		wantNoCaller bool
	}{
		{
			name:         "typed route from a no_callers root, guessed route from a main",
			chains:       [][]callGraphChainNode{chain("no_callers", "exact"), chain("main", "name_only")},
			wantEvidence: graphfrag.RouteEvidenceDirect, wantNoCaller: true,
		},
		{
			name:         "typed route from a main",
			chains:       [][]callGraphChainNode{chain("main", "interface_dispatch"), chain("no_callers", "name_only")},
			wantEvidence: graphfrag.RouteEvidenceDispatch, wantNoCaller: false,
		},
		{
			name:         "only guessed routes count all of them",
			chains:       [][]callGraphChainNode{chain("no_callers", "name_only"), chain("no_callers", "name_only")},
			wantEvidence: graphfrag.RouteEvidenceNameOnly, wantNoCaller: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fg := callGraphExportFinding{CallChains: tc.chains, Analysis: &graphfrag.ExportFindingAnalysis{}}
			reviseRouteEvidence(&fg, true)
			if fg.Analysis.RouteEvidence != tc.wantEvidence || fg.Analysis.NoCallersOnly != tc.wantNoCaller {
				t.Errorf("RouteEvidence = %q, NoCallersOnly = %v; want %q, %v",
					fg.Analysis.RouteEvidence, fg.Analysis.NoCallersOnly, tc.wantEvidence, tc.wantNoCaller)
			}
		})
	}
}

// A value that arrives only through a name_only guess is not shown to run, even
// when another value of the same function has an exact route: the verdict reads
// the routes that carry the value, not the function's best route.
func TestBuildCallGraphExport_GuessOnlyValueReadsUnknown(t *testing.T) {
	t.Parallel()

	graphs := perValueGraphs(t, routeSelectorGraphOf(
		routeCaller{typ: "Direct", value: 1, kind: callgraph.EdgeKindExact},
		routeCaller{typ: "Guessed", value: 3, kind: callgraph.EdgeKindNameOnly},
	), 2)

	exact, guessed := graphs["V1"], graphs["V3"]
	if exact.Reachability != graphfrag.ReachabilityReachable || exact.Analysis.RouteEvidence != graphfrag.RouteEvidenceDirect {
		t.Errorf("V1 reachability = %q evidence = %q, want reachable over direct", exact.Reachability, exact.Analysis.RouteEvidence)
	}
	if guessed.Reachability != graphfrag.ReachabilityUnknown || guessed.Reachable != nil {
		t.Errorf("V3 reachability = %q reachable = %v, want unknown and unset", guessed.Reachability, guessed.Reachable)
	}
	if guessed.UnresolvedReason != "unresolved_dispatch" {
		t.Errorf("V3 unresolved_reason = %q, want unresolved_dispatch", guessed.UnresolvedReason)
	}
	if guessed.Analysis == nil || guessed.Analysis.RouteEvidence != graphfrag.RouteEvidenceNameOnly {
		t.Errorf("V3 analysis = %+v, want route_evidence name_only", guessed.Analysis)
	}
}

// A value reached by both a guess and an exact route is still reachable.
func TestBuildCallGraphExport_ValueWithAnExactRouteStaysReachable(t *testing.T) {
	t.Parallel()

	graphs := perValueGraphs(t, routeSelectorGraphOf(
		routeCaller{typ: "Direct", value: 1, kind: callgraph.EdgeKindExact},
		routeCaller{typ: "Guessed", value: 1, kind: callgraph.EdgeKindNameOnly},
	), 1)

	if got := graphs["V1"]; got.Reachability != graphfrag.ReachabilityReachable || got.Analysis.RouteEvidence != graphfrag.RouteEvidenceDirect {
		t.Fatalf("V1 reachability = %q evidence = %q, want reachable over direct", got.Reachability, got.Analysis.RouteEvidence)
	}
}

// A value whose only caller nothing calls keeps the verdict a finding reached
// only from such a caller has, flagged no_callers_only; a value another entry
// reaches is not flagged.
func TestBuildCallGraphExport_DeadCallerValueIsFlaggedNoCallersOnly(t *testing.T) {
	t.Parallel()

	graphs := perValueGraphs(t, routeSelectorGraphOf(
		routeCaller{typ: "Live", value: 1, kind: callgraph.EdgeKindExact, entry: true},
		routeCaller{typ: "Dead", value: 2, kind: callgraph.EdgeKindExact},
	), 2)

	live, dead := graphs["V1"], graphs["V2"]
	if live.Analysis.NoCallersOnly || live.Reachability != graphfrag.ReachabilityReachable {
		t.Errorf("V1 = %q no_callers_only %v, want reachable and unflagged", live.Reachability, live.Analysis.NoCallersOnly)
	}
	if !dead.Analysis.NoCallersOnly || dead.Reachability != graphfrag.ReachabilityReachable {
		t.Errorf("V2 = %q no_callers_only %v, want reachable and flagged", dead.Reachability, dead.Analysis.NoCallersOnly)
	}
}
