package scan

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// annotateGoldenFixture builds a callgraph + report that exercise the crypto
// annotation path: a containing function doEncrypt that calls
// javax.crypto.Cipher.getInstance("AES"), with a matching crypto asset.
func annotateGoldenFixture(t *testing.T) (*engine.DepScanResult, ComponentKey) {
	t.Helper()

	cryptoFnID := callgraph.FunctionID{Package: "com.app", Type: "Service", Name: "doEncrypt#0"}
	cipherID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance#1"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			cryptoFnID.String(): {
				ID:         cryptoFnID,
				FilePath:   "Service.java",
				StartLine:  5,
				EndLine:    12,
				ReturnType: "void",
				Calls: []callgraph.FunctionCall{{
					Callee:    cipherID,
					FilePath:  "Service.java",
					Line:      8,
					Arguments: []string{`"AES"`},
				}},
			},
			cipherID.String(): {
				ID:         cipherID,
				FilePath:   "Cipher.java",
				StartLine:  1,
				EndLine:    3,
				ReturnType: "Cipher",
				Parameters: []callgraph.FunctionParameter{{Type: "String"}},
			},
		},
		Callers: map[string][]string{
			cipherID.String(): {cryptoFnID.String()},
		},
	}

	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test"},
		Findings: []entities.Finding{{
			FilePath: "Service.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 8,
				EndLine:   8,
				Match:     `Cipher.getInstance("AES")`,
				Rules:     []entities.RuleInfo{{ID: "java.crypto.cipher.getinstance"}},
				Metadata:  map[string]string{"api": "javax.crypto.Cipher.getInstance", "assetType": "algorithm", "algorithmFamily": "AES"},
				OID:       "2.16.840.1.101.3.4.1.2",
			}},
		}},
	}
	// Stamp finding IDs exactly as the scan pipeline does before export.
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	return &engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		ProjectRoot: t.TempDir(),
		RootModule:  "com.app:app",
		Ecosystem:   "java",
	}, ComponentKey{Purl: "pkg:maven/com.app/app", Version: "1.0.0"}
}

type ComponentKey = graphfrag.ComponentKey

// TestBuildAnnotateExport_CryptoAnnotationsByteIdenticalToFullScan is the
// load-bearing invariant test: a full --export-graph-fragment scan AND a
// re-annotate against that exported fragment MUST produce byte-identical
// crypto_annotations (same finding_id, function_key, oid, metadata, match,
// matched_operation, crypto_call). Consumers join assets↔chains by finding_id,
// so any drift breaks the join.
func TestBuildAnnotateExport_CryptoAnnotationsByteIdenticalToFullScan(t *testing.T) {
	t.Parallel()

	result, component := annotateGoldenFixture(t)

	// 1. Full scan path: build + export the graph fragment (callgraph present).
	full := BuildGraphFragmentExport(result)
	if len(full.CryptoAnnotations) == 0 {
		t.Fatal("full export produced no crypto annotations; fixture is broken")
	}

	// 2. Decode the exported fragment as a consumer would (this is the cached
	//    structural graph the annotate path imports).
	fragmentJSON, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal full export: %v", err)
	}
	fragment, err := graphfrag.DecodeFragment(component, fragmentJSON)
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}

	// 3. Annotate-only path: re-run annotation against the imported fragment,
	//    using the SAME detection report but NO live callgraph.
	annotate := BuildAnnotateExport(result.Report, fragment)

	// Invariant: crypto_annotations must be byte-identical.
	fullJSON, err := json.Marshal(full.CryptoAnnotations)
	if err != nil {
		t.Fatalf("marshal full annotations: %v", err)
	}
	annotateJSON, err := json.Marshal(annotate.CryptoAnnotations)
	if err != nil {
		t.Fatalf("marshal annotate annotations: %v", err)
	}
	if !bytes.Equal(fullJSON, annotateJSON) {
		t.Fatalf("crypto_annotations diverge.\n full:    %s\n annotate:%s", fullJSON, annotateJSON)
	}
}

// TestBuildAnnotateExport_DoesNotBuildCallgraph asserts the annotate path emits
// only scan_metadata + crypto_annotations and never reconstructs functions or
// edges (the expensive callgraph work it exists to skip).
func TestBuildAnnotateExport_DoesNotBuildCallgraph(t *testing.T) {
	t.Parallel()

	result, component := annotateGoldenFixture(t)
	full := BuildGraphFragmentExport(result)
	fragmentJSON, _ := json.Marshal(full)
	fragment, err := graphfrag.DecodeFragment(component, fragmentJSON)
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}

	annotate := BuildAnnotateExport(result.Report, fragment)

	if len(annotate.Functions) != 0 {
		t.Fatalf("annotate produced %d functions, want 0 (no callgraph)", len(annotate.Functions))
	}
	if len(annotate.InternalEdges) != 0 || len(annotate.ExternalCalls) != 0 {
		t.Fatalf("annotate produced edges (internal=%d external=%d), want 0",
			len(annotate.InternalEdges), len(annotate.ExternalCalls))
	}
	if len(annotate.CryptoAnnotations) == 0 {
		t.Fatal("annotate produced no crypto annotations")
	}
	// graph_algo_version is carried from the imported fragment so consumers can
	// keep their structural cache keyed on it.
	if annotate.ScanMetadata.GraphAlgoVersion != fragment.GraphAlgoVersion {
		t.Fatalf("graph_algo_version = %q, want %q (from imported fragment)",
			annotate.ScanMetadata.GraphAlgoVersion, fragment.GraphAlgoVersion)
	}
}

// TestBuildAnnotateExport_FunctionKeyFromImportedFragment verifies the
// function_key is recovered from the imported fragment's line ranges (not a
// live callgraph), matching what the full scan attached.
func TestBuildAnnotateExport_FunctionKeyFromImportedFragment(t *testing.T) {
	t.Parallel()

	result, component := annotateGoldenFixture(t)
	full := BuildGraphFragmentExport(result)
	fragmentJSON, _ := json.Marshal(full)
	fragment, err := graphfrag.DecodeFragment(component, fragmentJSON)
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}

	annotate := BuildAnnotateExport(result.Report, fragment)

	gotKeys := make([]string, len(annotate.CryptoAnnotations))
	for i, op := range annotate.CryptoAnnotations {
		gotKeys[i] = op.FunctionKey
	}
	wantKeys := make([]string, len(full.CryptoAnnotations))
	for i, op := range full.CryptoAnnotations {
		wantKeys[i] = op.FunctionKey
	}
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Fatalf("function keys diverge: got %v want %v", gotKeys, wantKeys)
	}
}
