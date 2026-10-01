// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/dependency"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
	"github.com/scanoss/crypto-finder/pkg/paramcondition"
)

// A condition that refutes every chain reads unreachable only when the routes
// it refuted are ones the graph proves. A finding reached only through
// name_only edges reads unknown (unresolved_dispatch) without a condition, and
// a condition that refutes those guesses cannot make it a definite verdict:
// the call that really reaches the function is not among them.
func TestBuildCallGraphExport_RefutedGuessedRoutesStayUnknown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		kinds            map[string]callgraph.EdgeKind
		wantReachability string
		wantReason       string
		wantReachable    *bool
	}{
		{
			name:             "every route is a guess",
			kinds:            map[string]callgraph.EdgeKind{"Direct": callgraph.EdgeKindNameOnly, "Dispatched": callgraph.EdgeKindNameOnly},
			wantReachability: graphfrag.ReachabilityUnknown, wantReason: unresolvedDispatch,
		},
		{
			name:             "a proven route is refuted too",
			kinds:            map[string]callgraph.EdgeKind{"Direct": callgraph.EdgeKindNameOnly, "Dispatched": callgraph.EdgeKindExact},
			wantReachability: graphfrag.ReachabilityUnreachable, wantReachable: boolPtr(false),
		},
		{
			name:             "every route is proven",
			kinds:            map[string]callgraph.EdgeKind{"Direct": callgraph.EdgeKindExact, "Dispatched": callgraph.EdgeKindInterfaceDispatch},
			wantReachability: graphfrag.ReachabilityUnreachable, wantReachable: boolPtr(false),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			graph := routeSelectorGraph()
			retypeCallerEdges(graph, tc.kinds)
			conditions, err := paramcondition.ParseAll("param[0]==V9")
			if err != nil {
				t.Fatal(err)
			}
			report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "Digests.java", Language: "java", CryptographicAssets: []entities.CryptographicAsset{{
				FindingID: "refuted", StartLine: 11, EndLine: 11, StartCol: 16, EndCol: 52, Match: "MessageDigest.getInstance(algorithm)",
				Rules:               []entities.RuleInfo{{ID: "java.digest.v9"}},
				Metadata:            map[string]string{"api": "java.security.MessageDigest.getInstance"},
				ParameterConditions: conditions,
			}}}}}
			payload := buildCallGraphExportV2(&engine.DepScanResult{
				Report: report, CallGraph: graph, Ecosystem: "java", RootModule: "com.app",
				Dependencies: []dependency.Dependency{{Module: "org.lib:digest"}},
			})

			if len(payload.FindingGraphs) != 1 {
				t.Fatalf("finding graphs = %d, want 1", len(payload.FindingGraphs))
			}
			fg := payload.FindingGraphs[0]
			if fg.Reachability != tc.wantReachability || fg.UnresolvedReason != tc.wantReason || len(fg.CallChains) != 0 {
				t.Errorf("reachability %q reason %q chains %d, want %q %q 0", fg.Reachability, fg.UnresolvedReason, len(fg.CallChains), tc.wantReachability, tc.wantReason)
			}
			switch {
			case tc.wantReachable == nil && fg.Reachable != nil:
				t.Errorf("reachable = %v, want unset", *fg.Reachable)
			case tc.wantReachable != nil && (fg.Reachable == nil || *fg.Reachable != *tc.wantReachable):
				t.Errorf("reachable = %v, want %v", fg.Reachable, *tc.wantReachable)
			}
		})
	}
}

// retypeCallerEdges gives each application caller's call into the helper the
// edge kind named for its type.
func retypeCallerEdges(graph *callgraph.CallGraph, kinds map[string]callgraph.EdgeKind) {
	callee := callgraph.FunctionID{Package: "org.lib", Type: "Digests", Name: "getDigest#1"}.String()
	graph.EdgeResolutions = make(map[string]callgraph.EdgeResolution, len(kinds))
	for typ, kind := range kinds {
		caller := callgraph.FunctionID{Package: "com.app", Type: typ, Name: "run#0"}.String()
		res := callgraph.EdgeResolution{Kind: kind, CallSite: 5, StartCol: 9, EndCol: 30, DeclaredType: "org.lib.Digester"}
		graph.EdgeResolutions[callgraph.EdgeResolutionKey(caller, callee, res)] = res
	}
}
