package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// twoEntryDiamondGraph is the live-export face of the #249 diamond: two user
// roots both reach one crypto sink through a shared mid function.
func twoEntryDiamondGraph() (*callgraph.CallGraph, *entities.InterimReport) {
	alpha := callgraph.FunctionID{Package: "com.acme", Type: "App", Name: "alpha#0"}
	beta := callgraph.FunctionID{Package: "com.acme", Type: "App", Name: "beta#0"}
	mid := callgraph.FunctionID{Package: "com.acme", Type: "App", Name: "mid#0"}
	sink := callgraph.FunctionID{Package: "com.acme", Type: "App", Name: "sink#0"}
	digest := callgraph.FunctionID{Package: "javax.crypto", Type: "Mac", Name: "doFinal#0"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			alpha.String(): {ID: alpha, FilePath: "App.java", StartLine: 1, EndLine: 4, Calls: []callgraph.FunctionCall{{
				Callee: mid, FilePath: "App.java", Line: 3, Raw: "mid()",
			}}},
			beta.String(): {ID: beta, FilePath: "App.java", StartLine: 6, EndLine: 9, Calls: []callgraph.FunctionCall{{
				Callee: mid, FilePath: "App.java", Line: 8, Raw: "mid()",
			}}},
			mid.String(): {ID: mid, FilePath: "App.java", StartLine: 11, EndLine: 14, Calls: []callgraph.FunctionCall{{
				Callee: sink, FilePath: "App.java", Line: 13, Raw: "sink()",
			}}},
			sink.String(): {ID: sink, FilePath: "App.java", StartLine: 16, EndLine: 22, Calls: []callgraph.FunctionCall{{
				Callee: digest, FilePath: "App.java", Line: 20, Raw: "mac.doFinal()", StartCol: 5, EndCol: 17,
			}}},
		},
		Callers: map[string][]string{
			mid.String():    {alpha.String(), beta.String()},
			sink.String():   {mid.String()},
			digest.String(): {sink.String()},
		},
	}
	report := &entities.InterimReport{
		Tool: entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Findings: []entities.Finding{{
			FilePath: "App.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				FindingID: "f-sink",
				StartLine: 20,
				EndLine:   20,
				StartCol:  5,
				EndCol:    17,
				Match:     "mac.doFinal()",
				Rules:     []entities.RuleInfo{{ID: "java.jca.mac"}},
			}},
		}},
	}
	return graph, report
}

func TestBuildCallGraphExport_MaxChainsOneKeepsFullEntryIndex(t *testing.T) {
	t.Parallel()

	graph, report := twoEntryDiamondGraph()
	payload := buildCallGraphExportV2WithMaxChains(&engine.DepScanResult{
		Report:    report,
		CallGraph: graph,
		Ecosystem: "java",
	}, 1)

	if len(payload.FindingGraphs) != 1 {
		t.Fatalf("FindingGraphs len = %d, want 1", len(payload.FindingGraphs))
	}
	fg := payload.FindingGraphs[0]
	if len(fg.CallChains) != 1 {
		t.Fatalf("CallChains len = %d, want 1 (emit budget)", len(fg.CallChains))
	}
	if fg.Analysis == nil || fg.Analysis.CallChains != graphfrag.AnalysisPartial {
		t.Fatalf("Analysis = %+v, want call_chains partial when routes exceed N", fg.Analysis)
	}
	if fg.Reachable != nil && !*fg.Reachable {
		t.Fatal("Reachable = false, budget truncation must not stamp unreachable")
	}

	var sawAlpha, sawBeta bool
	for _, ep := range payload.CryptoEntryPoints {
		switch ep.FunctionName {
		case "com.acme.App.alpha":
			sawAlpha = true
		case "com.acme.App.beta":
			sawBeta = true
		}
	}
	if !sawAlpha || !sawBeta {
		t.Fatalf("crypto_entry_points = %#v, want both alpha and beta (#249)", payload.CryptoEntryPoints)
	}

	if payload.SchemaVersion != graphfrag.CallgraphSchemaVersion {
		t.Fatalf("schema_version = %q, want %q", payload.SchemaVersion, graphfrag.CallgraphSchemaVersion)
	}
	if len(payload.Functions) == 0 {
		t.Fatal("functions catalog empty on live export")
	}
	if len(fg.CallChainIndexes) != len(fg.CallChains) {
		t.Fatalf("call_chain_indexes len = %d, want %d", len(fg.CallChainIndexes), len(fg.CallChains))
	}
	rebuilt, ok := graphfrag.ReconstructChainIdentities(payload.Functions, fg.CallChainIndexes)
	if !ok {
		t.Fatal("live call_chain_indexes pointed outside functions[]")
	}
	if len(rebuilt) != len(fg.CallChains) {
		t.Fatalf("rebuilt routes = %d, want %d", len(rebuilt), len(fg.CallChains))
	}
	for i, chain := range fg.CallChains {
		if len(rebuilt[i]) != len(chain) {
			t.Fatalf("route %d rebuilt len = %d, contracted len = %d", i, len(rebuilt[i]), len(chain))
		}
		for j, got := range rebuilt[i] {
			if got.FunctionName == "" || got.FilePath == "" {
				t.Fatalf("live route %d frame %d catalog identity empty: %+v", i, j, got)
			}
		}
	}
}

func TestBuildCallGraphExport_DefaultMaxChainsUnchanged(t *testing.T) {
	t.Parallel()

	graph, report := twoEntryDiamondGraph()
	limited := buildCallGraphExportV2WithMaxChains(&engine.DepScanResult{
		Report: report, CallGraph: graph, Ecosystem: "java",
	}, 0)
	plain := buildCallGraphExportV2(&engine.DepScanResult{
		Report: report, CallGraph: graph, Ecosystem: "java",
	})
	if len(limited.FindingGraphs[0].CallChains) != len(plain.FindingGraphs[0].CallChains) {
		t.Fatalf("default max-chains drifted: limited=%d plain=%d",
			len(limited.FindingGraphs[0].CallChains), len(plain.FindingGraphs[0].CallChains))
	}
	if len(plain.FindingGraphs[0].CallChains) != 2 {
		t.Fatalf("default emit = %d chains, want both diamond routes", len(plain.FindingGraphs[0].CallChains))
	}
}

func catalogChains(t *testing.T, payload *callGraphExportV2, fg callGraphExportFinding) [][]graphfrag.ExportInternedFunction {
	t.Helper()
	rebuilt, ok := graphfrag.ReconstructChainIdentities(payload.Functions, fg.CallChainIndexes)
	if !ok {
		t.Fatal("call_chain_indexes pointed outside functions[]")
	}
	return rebuilt
}
