package scan

import (
	"encoding/json"
	"sort"
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

	if payload.SchemaVersion != callGraphSchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", payload.SchemaVersion, callGraphSchemaVersion)
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

// TestBuildCallGraphExportV6_FindingGraphCarriesSupportingCallIDs pins the
// per-finding supporting_call_ids breadcrumb (schema 6.1): each finding_graph
// must list exactly the supporting_call ids derived for THAT finding, and every
// id must resolve to a top-level supporting_calls entry. This is the precise
// finding->supporting foreign key the served API surfaces per asset — it cannot
// be recovered downstream from the deduped top-level array (no finding_id there)
// nor from crypto_entry_points (entry-point granularity over-associates).
func TestBuildCallGraphExportV6_FindingGraphCarriesSupportingCallIDs(t *testing.T) {
	t.Parallel()
	graph, dir := buildSupportingGraph(t)
	report := reportForTerminal(t, 7, "a.finish()", "com.app.Maker.finish")

	payload := buildCallGraphExportV2(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java",
	})
	if len(payload.SupportingCalls) == 0 {
		t.Fatal("fixture produced no supporting calls; cannot test the breadcrumb")
	}

	wantFindingID := report.Findings[0].CryptographicAssets[0].FindingID
	fg := findFindingGraph(payload.FindingGraphs, wantFindingID)
	if fg == nil {
		t.Fatalf("no finding_graph for %q", wantFindingID)
	}
	if len(fg.SupportingCallIDs) == 0 {
		t.Fatal("finding_graph.supporting_call_ids is empty; per-finding FK not populated")
	}

	// supporting_call_ids must be sorted and unique (deterministic output).
	for i := 1; i < len(fg.SupportingCallIDs); i++ {
		if fg.SupportingCallIDs[i-1] >= fg.SupportingCallIDs[i] {
			t.Fatalf("supporting_call_ids not strictly sorted/unique: %v", fg.SupportingCallIDs)
		}
	}

	// Every id must resolve to a top-level supporting_calls entry (the FK invariant
	// equiv will also assert across the contract).
	top := make(map[string]bool, len(payload.SupportingCalls))
	for _, sc := range payload.SupportingCalls {
		top[sc.SupportingID] = true
	}
	for _, id := range fg.SupportingCallIDs {
		if !top[id] {
			t.Errorf("supporting_call_id %q does not resolve to any top-level supporting_calls entry", id)
		}
	}

	// Single-finding fixture: the top-level set IS this finding's set, so the
	// breadcrumb must equal the full deduped id list.
	wantIDs := make([]string, 0, len(top))
	for id := range top {
		wantIDs = append(wantIDs, id)
	}
	sort.Strings(wantIDs)
	if got := fg.SupportingCallIDs; !equalStringSlices(got, wantIDs) {
		t.Fatalf("supporting_call_ids = %v, want %v (the finding's full supporting set)", got, wantIDs)
	}
}

// TestBuildCallGraphExportV6_SupportingCallIDsAttributedPerFinding is the
// precision guarantee: when two independent crypto objects are each flagged, each
// finding_graph carries ONLY its own object's supporting calls — never the
// sibling's. This is what makes the per-asset breadcrumb trustworthy instead of
// the over-associating entry-point-intersection alternative.
func TestBuildCallGraphExportV6_SupportingCallIDsAttributedPerFinding(t *testing.T) {
	t.Parallel()
	graph, dir := buildSupportingGraph(t)

	// Flag BOTH terminals: object A (a.finish, line 7) and object B (b.execute, line 10).
	report := &entities.InterimReport{
		Tool: entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Findings: []entities.Finding{{
			FilePath: "Svc.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{
				{
					StartLine: 7, EndLine: 7, Match: "a.finish()",
					Rules:    []entities.RuleInfo{{ID: "test.rule"}},
					Metadata: map[string]string{"api": "com.app.Maker.finish", "assetType": "algorithm"},
				},
				{
					StartLine: 10, EndLine: 10, Match: "b.execute()",
					Rules:    []entities.RuleInfo{{ID: "test.rule"}},
					Metadata: map[string]string{"api": "com.app.Other.execute", "assetType": "algorithm"},
				},
			},
		}},
	}
	engine.EnsureFindingSources(report)
	engine.AssignFindingIDs(report)

	payload := buildCallGraphExportV2(&engine.DepScanResult{
		Report: report, CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java",
	})

	idA := report.Findings[0].CryptographicAssets[0].FindingID
	idB := report.Findings[0].CryptographicAssets[1].FindingID
	fgA := findFindingGraph(payload.FindingGraphs, idA)
	fgB := findFindingGraph(payload.FindingGraphs, idB)
	if fgA == nil || fgB == nil {
		t.Fatalf("missing finding graphs: A=%v B=%v", fgA != nil, fgB != nil)
	}
	if len(fgA.SupportingCallIDs) == 0 || len(fgB.SupportingCallIDs) == 0 {
		t.Fatalf("each finding must have its own supporting calls: A=%v B=%v", fgA.SupportingCallIDs, fgB.SupportingCallIDs)
	}

	// Disjoint: A's lifecycle calls must not leak into B and vice versa.
	bSet := make(map[string]bool, len(fgB.SupportingCallIDs))
	for _, id := range fgB.SupportingCallIDs {
		bSet[id] = true
	}
	for _, id := range fgA.SupportingCallIDs {
		if bSet[id] {
			t.Errorf("supporting_call_id %q attributed to BOTH findings; over-association leak", id)
		}
	}

	// Union of per-finding ids must equal the top-level supporting_calls set.
	union := make(map[string]bool)
	for _, id := range fgA.SupportingCallIDs {
		union[id] = true
	}
	for _, id := range fgB.SupportingCallIDs {
		union[id] = true
	}
	for _, sc := range payload.SupportingCalls {
		if !union[sc.SupportingID] {
			t.Errorf("top-level supporting_call %q is not referenced by any finding_graph", sc.SupportingID)
		}
		delete(union, sc.SupportingID)
	}
	if len(union) != 0 {
		t.Errorf("finding_graphs reference supporting ids absent from top-level supporting_calls: %v", union)
	}
}

func findFindingGraph(graphs []callGraphExportFinding, findingID string) *callGraphExportFinding {
	for i := range graphs {
		if graphs[i].FindingID == findingID {
			return &graphs[i]
		}
	}
	return nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
