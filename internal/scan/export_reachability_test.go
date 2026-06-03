package scan

import (
	"encoding/json"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestBuildCallGraphExportV6_CryptoEntryPointsAndSourceNodes(t *testing.T) {
	t.Parallel()

	entryID := callgraph.FunctionID{Package: "com.acme", Type: "App", Name: "entry#0"}
	serviceID := callgraph.FunctionID{Package: "com.acme", Type: "CryptoService", Name: "encrypt#1"}
	cipherID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance#1"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			entryID.String(): {
				ID:         entryID,
				FilePath:   "App.java",
				StartLine:  1,
				EndLine:    7,
				ReturnType: "void",
				Calls: []callgraph.FunctionCall{{
					Callee:    serviceID,
					FilePath:  "App.java",
					Line:      5,
					Raw:       "service.encrypt(\"AES\")",
					Arguments: []string{"\"AES\""},
					ArgumentSources: [][]callgraph.SourceNode{{
						{Type: sourceNodeTypeValue, Value: "\"AES\"", Location: &callgraph.SourceLocation{FilePath: "App.java", Line: 5}},
					}},
				}},
			},
			serviceID.String(): {
				ID:         serviceID,
				FilePath:   "CryptoService.java",
				StartLine:  10,
				EndLine:    24,
				ReturnType: "void",
				Parameters: []callgraph.FunctionParameter{{
					Type: "java.lang.String",
				}},
				Calls: []callgraph.FunctionCall{{
					Callee:    cipherID,
					FilePath:  "CryptoService.java",
					Line:      20,
					Raw:       "Cipher.getInstance(algorithm)",
					Arguments: []string{"algorithm"},
					ArgumentSources: [][]callgraph.SourceNode{{
						{Type: sourceNodeTypeParameter, Name: "algorithm", DeclaredType: "java.lang.String", ParameterIndex: 0},
					}},
				}},
			},
		},
		Callers: map[string][]string{
			serviceID.String(): {entryID.String()},
			cipherID.String():  {serviceID.String()},
		},
		ExternalMethodSignatures: map[string][]callgraph.ExternalMethodSignature{
			callgraph.ExternalMethodSignatureKey(cipherID): {{
				ParameterTypes: []string{"java.lang.String"},
				ReturnType:     "javax.crypto.Cipher",
			}},
		},
	}
	report := &entities.InterimReport{
		Tool: entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Findings: []entities.Finding{{
			FilePath: "CryptoService.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				FindingID: "aes-finding",
				StartLine: 20,
				EndLine:   20,
				Match:     "Cipher.getInstance(algorithm)",
				Rules:     []entities.RuleInfo{{ID: "java.jca.algorithm.ae.aes"}},
				Metadata:  map[string]string{"api": "javax.crypto.Cipher.getInstance", "assetType": "algorithm"},
			}},
		}},
	}

	payload := buildCallGraphExportV2(&engine.DepScanResult{
		Report:    report,
		CallGraph: graph,
		Ecosystem: "java",
	})

	if payload.SchemaVersion != "6.0" {
		t.Fatalf("SchemaVersion = %q, want 6.0", payload.SchemaVersion)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if _, ok := decoded["entry_point_index"]; ok {
		t.Fatal("entry_point_index is present; schema 6.0 must expose crypto_entry_points instead")
	}
	if _, ok := decoded["crypto_entry_points"]; !ok {
		t.Fatal("crypto_entry_points missing from schema 6.0 export")
	}
	if len(payload.CryptoEntryPoints) == 0 {
		t.Fatal("CryptoEntryPoints is empty, want API entrypoint reachability")
	}

	entry := findCallGraphCryptoEntryPoint(payload.CryptoEntryPoints, "com.acme.App.entry")
	if entry == nil {
		t.Fatalf("no crypto entrypoint for com.acme.App.entry: %#v", payload.CryptoEntryPoints)
	}
	if len(entry.ReachableFindings) != 1 || entry.ReachableFindings[0].FindingID != "aes-finding" {
		t.Fatalf("ReachableFindings = %#v, want aes-finding", entry.ReachableFindings)
	}

	chain := payload.FindingGraphs[0].CallChains[0]
	terminal := chain[len(chain)-1]
	if terminal.CryptoCall == nil || len(terminal.CryptoCall.Parameters) != 1 {
		t.Fatalf("terminal crypto_call parameters missing: %#v", terminal.CryptoCall)
	}
	param := terminal.CryptoCall.Parameters[0]
	if param.ResolvedValue != "\"AES\"" {
		t.Fatalf("crypto_call parameter resolved_value = %q, want \"AES\"", param.ResolvedValue)
	}
	if len(param.SourceNodes) == 0 || len(param.SourceNodes[0].SourceNodes) == 0 {
		t.Fatalf("crypto_call parameter source_nodes did not preserve upstream VALUE provenance: %#v", param.SourceNodes)
	}
}

func findCallGraphCryptoEntryPoint(entries []callGraphCryptoEntryPoint, function string) *callGraphCryptoEntryPoint {
	for i := range entries {
		if entries[i].FunctionName == function {
			return &entries[i]
		}
	}
	return nil
}

// TestBuildCallGraphExportV6_ReachabilityWithoutApiMetadata proves the headline
// guarantee of position-based anchoring: a finding whose call exists in the call
// graph is still classified as a call and still gets call chains even when the
// rule provides NO metadata.api. Previously a missing/wrong api downgraded the
// finding to kind "expression" and silently bypassed reachability.
func TestBuildCallGraphExportV6_ReachabilityWithoutApiMetadata(t *testing.T) {
	t.Parallel()

	entryID := callgraph.FunctionID{Package: "com.acme", Type: "App", Name: "run#0"}
	cipherID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance#1"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			entryID.String(): {
				ID:        entryID,
				FilePath:  "App.java",
				StartLine: 1,
				EndLine:   5,
				Calls: []callgraph.FunctionCall{{
					Callee:    cipherID,
					FilePath:  "App.java",
					Line:      3,
					Raw:       "Cipher.getInstance(\"AES\")",
					Arguments: []string{"\"AES\""},
				}},
			},
		},
		Callers: map[string][]string{cipherID.String(): {entryID.String()}},
	}
	report := &entities.InterimReport{
		Findings: []entities.Finding{{
			FilePath: "App.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				FindingID: "no-api",
				StartLine: 3,
				EndLine:   3,
				Match:     "Cipher.getInstance(\"AES\")",
				Rules:     []entities.RuleInfo{{ID: "java.jca.algorithm.ae.aes"}},
				// Deliberately NO "api" key — only assetType.
				Metadata: map[string]string{"assetType": "algorithm"},
			}},
		}},
	}

	payload := buildCallGraphExportV2(&engine.DepScanResult{
		Report:    report,
		CallGraph: graph,
		Ecosystem: "java",
	})

	if len(payload.FindingGraphs) != 1 {
		t.Fatalf("want 1 finding graph, got %d", len(payload.FindingGraphs))
	}
	fg := payload.FindingGraphs[0]
	if fg.MatchedOperation == nil || fg.MatchedOperation.Kind != matchedOperationCall {
		t.Fatalf("kind = %#v, want %q derived from source text (api absent)", fg.MatchedOperation, matchedOperationCall)
	}
	if len(fg.CallChains) == 0 {
		t.Fatal("call_chains empty with no api: reachability was wrongly gated by metadata.api")
	}
}
