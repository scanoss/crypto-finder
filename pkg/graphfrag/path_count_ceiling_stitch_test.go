package graphfrag

import (
	"fmt"
	"testing"

	"github.com/scanoss/crypto-finder/pkg/graphwalk"
)

// TestToCallgraphExport_PathCountTruncatedEmitsEmptyUnknownPartial pins the
// #292 stitch consumer contract: a FindingChain marked PathCountTruncated is a
// finding carrier, not a self-entry. Served call_chains stay empty, reachability
// is unknown, and analysis.call_chains is partial.
func TestToCallgraphExport_PathCountTruncatedEmitsEmptyUnknownPartial(t *testing.T) {
	root := ComponentKey{Purl: "pkg:maven/com.acme/app", Version: "1"}
	result := &Result{
		Chains: []FindingChain{{
			FindingID: "f-ceiling",
			RuleID:    "rule",
			Symbol:    "digest",
			Frames: []CallFrame{{
				Component: root,
				Signature: "org.lib.(Util).digest#1",
				Function:  Function{FunctionName: "digest"},
			}},
			Confidence:         ConfidenceHigh,
			CryptoOp:           &CryptoOperation{FindingID: "f-ceiling", Symbol: "digest", StartLine: 10},
			PathCountTruncated: true,
		}},
	}

	out := result.ToCallgraphExport(root, ScanMeta{Ecosystem: "java"})
	if len(out.FindingGraphs) != 1 {
		t.Fatalf("FindingGraphs len = %d, want 1", len(out.FindingGraphs))
	}
	fg := out.FindingGraphs[0]
	if len(fg.CallChains) != 0 {
		t.Fatalf("CallChains = %#v, want empty after path-count ceiling", fg.CallChains)
	}
	if fg.Reachability != ReachabilityUnknown {
		t.Fatalf("Reachability = %q, want %q", fg.Reachability, ReachabilityUnknown)
	}
	if fg.Analysis == nil || fg.Analysis.CallChains != AnalysisPartial {
		t.Fatalf("Analysis = %+v, want call_chains partial", fg.Analysis)
	}
}

// TestCondensedBackwardChains_SkipsRoutesAbovePathCountCeiling exercises the
// stitch-side ceiling against a high-fan-in reverse adjacency.
func TestCondensedBackwardChains_SkipsRoutesAbovePathCountCeiling(t *testing.T) {
	comp := ComponentKey{Purl: "pkg:maven/org.lib/lib", Version: "1"}
	op := graphNode{Component: comp, Function: "op"}
	reverse := map[graphNode][]reverseEdge{}
	entrySet := map[graphNode]bool{}

	// Build width^depth fan-in ending at entry roots, same shape as the live
	// high-fan-in fixture. width=8 depth=6 => 262144 > PathCountSkipThreshold.
	const width, depth = 8, 6
	prev := []graphNode{op}
	for d := 1; d <= depth; d++ {
		layer := make([]graphNode, 0, width)
		for w := 0; w < width; w++ {
			n := graphNode{Component: comp, Function: fmt.Sprintf("L%dN%d", d, w)}
			layer = append(layer, n)
			if d == depth {
				entrySet[n] = true
			}
		}
		for _, callee := range prev {
			edges := make([]reverseEdge, 0, width)
			for _, caller := range layer {
				edges = append(edges, reverseEdge{caller: caller})
			}
			reverse[callee] = edges
		}
		prev = layer
	}

	chains, total, truncated := condensedBackwardChains(op, reverse, entrySet)
	if total <= graphwalk.PathCountSkipThreshold {
		t.Fatalf("total = %d, want above PathCountSkipThreshold=%d", total, graphwalk.PathCountSkipThreshold)
	}
	if !truncated {
		t.Fatal("truncated = false, want true")
	}
	if len(chains) != 0 {
		t.Fatalf("chains = %d, want 0 when the ceiling skips Routes", len(chains))
	}
}
