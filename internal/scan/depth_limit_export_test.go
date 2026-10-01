// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package scan

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// depthChainHops is how many functions below app.Main the crypto sits.
const depthChainHops = 6

// depthChainContext builds a straight call chain app.Main -> <pkg>.F1 -> ... ->
// <pkg>.F6 where the last function holds the crypto, and an export context that
// limits chains to maxDepth frames.
func depthChainContext(pkg string, maxDepth int, userPackages map[string]bool) (*exportBuildContext, *callgraph.FunctionDecl) {
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{}, Callers: map[string][]string{}}
	caller := callgraph.FunctionID{Package: "com.app", Type: "Main", Name: "run#0"}
	graph.Functions[caller.String()] = &callgraph.FunctionDecl{ID: caller, FilePath: "app/Main.java", StartLine: 1, EndLine: 3}
	var last *callgraph.FunctionDecl
	for i := 1; i <= depthChainHops; i++ {
		id := callgraph.FunctionID{Package: pkg, Type: "Step", Name: fmt.Sprintf("f%d#0", i)}
		decl := &callgraph.FunctionDecl{ID: id, FilePath: "lib/Step.java", StartLine: i * 10, EndLine: i*10 + 5}
		graph.Functions[id.String()] = decl
		graph.Callers[id.String()] = []string{caller.String()}
		graph.Functions[caller.String()].Calls = []callgraph.FunctionCall{{Callee: id, Line: graph.Functions[caller.String()].StartLine + 1}}
		caller, last = id, decl
	}
	ctx := &exportBuildContext{
		graph:                   graph,
		packageSeparator:        ".",
		userPackages:            userPackages,
		containingFunctionCache: make(map[string]cachedContainingFunction),
		maxDepth:                maxDepth,
	}
	ensureCallChainCaches(ctx)
	ctx.callChainRemainingUses[last.ID.String()] = 1
	return ctx, last
}

func buildDepthFindingGraph(ctx *exportBuildContext, decl *callgraph.FunctionDecl) callGraphExportFinding {
	finding := entities.Finding{
		FilePath: decl.FilePath,
		CryptographicAssets: []entities.CryptographicAsset{{
			FindingID: "f-depth", StartLine: decl.StartLine, EndLine: decl.EndLine,
		}},
	}
	return buildFindingGraph(ctx, finding, finding.CryptographicAssets[0])
}

// TestBuildFindingGraph_DepthLimitInLibraryReadsUnknown: the application
// reaches the crypto through six library frames, but the walk may only see
// three. Before, the cut route vanished and the finding read unreachable with
// its analysis complete. Nothing was proved either way.
func TestBuildFindingGraph_DepthLimitInLibraryReadsUnknown(t *testing.T) {
	t.Parallel()
	ctx, target := depthChainContext("org.lib", 3, map[string]bool{"com.app": true})

	fg := buildDepthFindingGraph(ctx, target)

	if fg.Reachability != graphfrag.ReachabilityUnknown {
		t.Fatalf("Reachability = %q, want unknown when the depth limit cut every route", fg.Reachability)
	}
	if fg.UnresolvedReason != unresolvedTraversalTruncated {
		t.Fatalf("UnresolvedReason = %q, want %q", fg.UnresolvedReason, unresolvedTraversalTruncated)
	}
	if fg.FindingLocation != nil {
		t.Fatalf("FindingLocation = %+v, want none: the finding is attributed", fg.FindingLocation)
	}
	if fg.Reachable != nil {
		t.Fatalf("Reachable = %v, want unset", *fg.Reachable)
	}
	if fg.Analysis == nil || fg.Analysis.CallChains != graphfrag.AnalysisPartial {
		t.Fatalf("Analysis = %+v, want call_chains partial", fg.Analysis)
	}
	if len(fg.CallChains) != 0 {
		t.Fatalf("CallChains = %d, want none rather than a self-chain", len(fg.CallChains))
	}

	// Unbounded, the same graph reaches the application.
	ctx, target = depthChainContext("org.lib", 0, map[string]bool{"com.app": true})
	if fg := buildDepthFindingGraph(ctx, target); fg.Reachability != graphfrag.ReachabilityReachable {
		t.Fatalf("unbounded Reachability = %q, want reachable", fg.Reachability)
	}
}

// TestBuildFindingGraph_DepthLimitInApplicationKeepsReachable: when the limit
// stops the walk inside application code, application code does reach the
// crypto, so the verdict stands, but the chain says where it was cut and the
// analysis is partial.
func TestBuildFindingGraph_DepthLimitInApplicationKeepsReachable(t *testing.T) {
	t.Parallel()
	ctx, target := depthChainContext("com.app.deep", 3, map[string]bool{"com.app": true})

	fg := buildDepthFindingGraph(ctx, target)

	if fg.Reachability != graphfrag.ReachabilityReachable {
		t.Fatalf("Reachability = %q, want reachable", fg.Reachability)
	}
	if len(fg.CallChains) != 1 || len(fg.CallChains[0]) != 3 {
		t.Fatalf("CallChains = %#v, want one 3-frame chain", fg.CallChains)
	}
	if got := fg.CallChains[0][0].RootKind; got != string(callgraph.RootKindDepthLimit) {
		t.Fatalf("root_kind = %q, want depth_limit", got)
	}
	if fg.Analysis == nil || fg.Analysis.CallChains != graphfrag.AnalysisPartial {
		t.Fatalf("Analysis = %+v, want call_chains partial: the chain is cut short", fg.Analysis)
	}
}

// TestBuildFindingGraph_DepthLimitOnMinePathMarksPartial: a library scanned
// alone has no reachability verdict, but a cut walk still says it was cut.
func TestBuildFindingGraph_DepthLimitOnMinePathMarksPartial(t *testing.T) {
	t.Parallel()
	ctx, target := depthChainContext("org.lib", 3, nil)

	fg := buildDepthFindingGraph(ctx, target)

	if fg.Reachability != graphfrag.ReachabilityNotApplicable {
		t.Fatalf("Reachability = %q, want not_applicable on the mine path", fg.Reachability)
	}
	if fg.Analysis == nil || fg.Analysis.CallChains != graphfrag.AnalysisPartial {
		t.Fatalf("Analysis = %+v, want call_chains partial", fg.Analysis)
	}
}
