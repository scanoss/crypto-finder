package scan

import (
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// TestBuildGraphFragmentExport13_DerivesSupportingCallsFromObjectLifecycle
// exercises the call-graph-derived supporting-call model: a single terminal
// crypto finding (the SHA3Digest constructor bound to `digest`) yields supporting
// calls for the lifecycle methods invoked on that object (update, doFinal),
// recovered structurally from the call graph rather than from rule metadata.
// Entry points that reach the finding also surface the derived supporting calls.
func TestBuildGraphFragmentExport13_DerivesSupportingCallsFromObjectLifecycle(t *testing.T) {
	t.Parallel()

	apiID := callgraph.FunctionID{Package: "com.acme", Type: "Facade", Name: "run#0"}
	cryptoFnID := callgraph.FunctionID{Package: "com.acme", Type: "Service", Name: "hashSHA3#1"}
	ctorID := callgraph.FunctionID{Package: "org.bouncycastle.crypto.digests", Type: "SHA3Digest", Name: "<init>#1"}
	updateID := callgraph.FunctionID{Package: "org.bouncycastle.crypto.digests", Type: "SHA3Digest", Name: "update#3"}
	doFinalID := callgraph.FunctionID{Package: "org.bouncycastle.crypto.digests", Type: "SHA3Digest", Name: "doFinal#2"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			apiID.String(): {
				ID:        apiID,
				FilePath:  "Facade.java",
				StartLine: 1,
				EndLine:   8,
				Calls: []callgraph.FunctionCall{
					{Callee: cryptoFnID, FilePath: "Facade.java", Line: 5, Raw: "service.hashSHA3(msg)"},
				},
			},
			cryptoFnID.String(): {
				ID:        cryptoFnID,
				FilePath:  "Service.java",
				StartLine: 16,
				EndLine:   22,
				Calls: []callgraph.FunctionCall{
					{Callee: ctorID, FilePath: "Service.java", Line: 17, Raw: "new SHA3Digest(256)", AssignedVar: "digest"},
					{Callee: updateID, FilePath: "Service.java", Line: 18, Raw: "digest.update(b, 0, n)", ReceiverVar: "digest"},
					{Callee: doFinalID, FilePath: "Service.java", Line: 19, Raw: "digest.doFinal(out, 0)", ReceiverVar: "digest"},
				},
			},
		},
		Callers: map[string][]string{
			cryptoFnID.String(): {apiID.String()},
		},
	}
	report := &entities.InterimReport{
		Findings: []entities.Finding{{
			FilePath: "Service.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{
				{
					FindingID: "sha3-256",
					StartLine: 17,
					EndLine:   17,
					Match:     "SHA3Digest digest = new SHA3Digest(256);",
					Rules:     []entities.RuleInfo{{ID: "java.bouncycastle.algorithm.hash.sha-3-lightweight"}},
					Metadata:  map[string]string{"api": "SHA3Digest", "assetType": "algorithm"},
				},
			},
		}},
	}

	payload := BuildGraphFragmentExport(&engine.DepScanResult{
		Report:     report,
		CallGraph:  graph,
		RootModule: "com.acme:digest-app",
		Ecosystem:  "java",
	})

	if payload.SchemaVersion != "graph-fragment-1.5" {
		t.Fatalf("SchemaVersion = %q, want graph-fragment-1.5", payload.SchemaVersion)
	}

	// The terminal finding is the only crypto annotation; the lifecycle calls are
	// supporting calls, not findings.
	if len(payload.CryptoAnnotations) != 1 || payload.CryptoAnnotations[0].FindingID != "sha3-256" {
		t.Fatalf("crypto_annotations = %#v, want sha3-256 only", payload.CryptoAnnotations)
	}

	// update + doFinal are derived from the object's lifecycle.
	supportSymbols := map[string]bool{}
	for _, sc := range payload.SupportingCalls {
		if sc.MatchedOperation != nil {
			supportSymbols[callgraph.BaseFunctionName(lastSegment(sc.MatchedOperation.Symbol))] = true
		}
	}
	if len(payload.SupportingCalls) != 2 || !supportSymbols["update"] || !supportSymbols["doFinal"] {
		t.Fatalf("supporting_calls = %#v, want derived update + doFinal", payload.SupportingCalls)
	}

	// The entry point that reaches the finding also surfaces the derived
	// supporting calls.
	entry := findGraphFragmentEntryPoint(payload.CryptoEntryPoints, apiID.String())
	if entry == nil {
		t.Fatalf("no crypto entrypoint for %s: %#v", apiID.String(), payload.CryptoEntryPoints)
	}
	if len(entry.ReachableFindings) != 1 || entry.ReachableFindings[0].FindingID != "sha3-256" {
		t.Fatalf("entry reachable_findings = %#v, want sha3-256", entry.ReachableFindings)
	}
	if len(entry.ReachableSupportingCalls) != 2 {
		t.Fatalf("entry reachable_supporting_calls = %#v, want 2 derived calls", entry.ReachableSupportingCalls)
	}
}

// lastSegment returns the substring after the final dot, or the input unchanged.
func lastSegment(s string) string {
	if i := lastIndexByte(s, '.'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func findGraphFragmentEntryPoint(entries []graphfrag.GraphFragmentCryptoEntryPoint, key string) *graphfrag.GraphFragmentCryptoEntryPoint {
	for i := range entries {
		if entries[i].FunctionKey == key {
			return &entries[i]
		}
	}
	return nil
}
