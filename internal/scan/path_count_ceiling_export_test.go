package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// TestBuildFindingGraph_PathCountCeilingKeepsUnknownNotUnreachable is the #292
// consumer contract: when condensed traceback skips Routes above the path-count
// ceiling, the finding must not be stamped reachable=false (that drops it from
// crypto_entry_points) and must not synthesize a one-node self-chain. Reachability
// stays unknown, analysis stays partial, and call_chains stays empty.
func TestBuildFindingGraph_PathCountCeilingKeepsUnknownNotUnreachable(t *testing.T) {
	target := callgraph.FunctionID{Package: "dep/crypto", Name: "Cipher"}
	decl := &callgraph.FunctionDecl{
		ID: target, FilePath: "dep/Cipher.java", StartLine: 10, EndLine: 20,
	}
	ctx := &exportBuildContext{
		graph: &callgraph.CallGraph{
			Functions: map[string]*callgraph.FunctionDecl{target.String(): decl},
			Callers:   map[string][]string{},
		},
		packageSeparator:        ".",
		userPackages:            map[string]bool{"com.app": true},
		containingFunctionCache: make(map[string]cachedContainingFunction),
	}
	ensureCallChainCaches(ctx)
	cacheKey := target.String()
	ctx.callChainRawCache[cacheKey] = nil
	ctx.callChainTruncated[cacheKey] = true
	ctx.callChainRemainingUses[cacheKey] = 1

	finding := entities.Finding{
		FilePath: decl.FilePath,
		CryptographicAssets: []entities.CryptographicAsset{{
			FindingID: "f-ceiling",
			StartLine: decl.StartLine,
			EndLine:   decl.EndLine,
		}},
	}
	asset := finding.CryptographicAssets[0]
	fg := buildFindingGraph(ctx, finding, asset)

	if fg.Reachable != nil && !*fg.Reachable {
		t.Fatalf("Reachable = false, want unset: ceiling skip must not claim unreachable")
	}
	if fg.Reachability != graphfrag.ReachabilityUnknown {
		t.Fatalf("Reachability = %q, want %q", fg.Reachability, graphfrag.ReachabilityUnknown)
	}
	if fg.Analysis == nil || fg.Analysis.CallChains != graphfrag.AnalysisPartial {
		t.Fatalf("Analysis = %+v, want call_chains partial", fg.Analysis)
	}
	if len(fg.CallChains) != 0 {
		t.Fatalf("CallChains len = %d, want 0 (no self-chain after ceiling skip)", len(fg.CallChains))
	}
}

// TestBuildFindingGraph_PathCountCeilingMinePathStillMarksPartial covers the
// groovy mine-path face: no user-package universe means reachability is
// not_applicable, but a ceiling skip must still surface analysis.call_chains
// partial so consumers see the truncation.
func TestBuildFindingGraph_PathCountCeilingMinePathStillMarksPartial(t *testing.T) {
	target := callgraph.FunctionID{Package: "org.codehaus.groovy.runtime", Name: "digest"}
	decl := &callgraph.FunctionDecl{
		ID: target, FilePath: "groovy/Encoding.java", StartLine: 40, EndLine: 50,
	}
	ctx := &exportBuildContext{
		graph: &callgraph.CallGraph{
			Functions: map[string]*callgraph.FunctionDecl{target.String(): decl},
			Callers:   map[string][]string{},
		},
		packageSeparator:        ".",
		userPackages:            nil, // mine path
		containingFunctionCache: make(map[string]cachedContainingFunction),
	}
	ensureCallChainCaches(ctx)
	cacheKey := target.String()
	ctx.callChainRawCache[cacheKey] = nil
	ctx.callChainTruncated[cacheKey] = true
	ctx.callChainRemainingUses[cacheKey] = 1

	finding := entities.Finding{
		FilePath: decl.FilePath,
		CryptographicAssets: []entities.CryptographicAsset{{
			FindingID: "f-mine-ceiling",
			StartLine: decl.StartLine,
			EndLine:   decl.EndLine,
		}},
	}
	fg := buildFindingGraph(ctx, finding, finding.CryptographicAssets[0])

	if fg.Reachability != graphfrag.ReachabilityNotApplicable {
		t.Fatalf("Reachability = %q, want %q on the mine path", fg.Reachability, graphfrag.ReachabilityNotApplicable)
	}
	if fg.Analysis == nil || fg.Analysis.CallChains != graphfrag.AnalysisPartial {
		t.Fatalf("Analysis = %+v, want call_chains partial even when reachability is not_applicable", fg.Analysis)
	}
	if len(fg.CallChains) != 0 {
		t.Fatalf("CallChains len = %d, want 0", len(fg.CallChains))
	}
}
