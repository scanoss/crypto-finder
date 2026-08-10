// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"sort"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// mine-path equivalence harness (#215)
//
// Locks export quantity/quality for BuildGraphFragmentExport after the #214
// structural entry-point work. The oracle below is an independent reimplementation
// of the mine-path contract (not a call into materializeGraphFragmentCrypto):
//
//   - annotations: one per asset, supporting_call_ids from deriveSupportingCallsForFinding
//   - supporting_calls: deduped catalog across assets
//   - crypto_entry_points: unconditioned → structuralCallChains; conditioned →
//     full traceback+expand+filter (same as fragmentEntryPointChains)
//
// Any thinning or reachability drift fails the test. Depths and reachable IDs
// are compared, not only counts.

func TestMinePathFragment_EquivalenceOracle_ConditionedWrapperSelectors(t *testing.T) {
	t.Parallel()
	// Reuse the conditioned PGP wrapper fixture (AES vs DES call sites).
	result := conditionedPGPWrapperFixture(t)
	assertMinePathFragmentMatchesOracle(t, result)
}

func TestMinePathFragment_EquivalenceOracle_SelectorProvenance(t *testing.T) {
	t.Parallel()
	result := selectorProvenanceFixture()
	assertMinePathFragmentMatchesOracle(t, result)
}

func TestMinePathFragment_EquivalenceOracle_LifecycleSupportingCalls(t *testing.T) {
	t.Parallel()
	// Object-lifecycle supporting calls (fragment_reachability fixture shape).
	result := lifecycleSupportingCallsFixture()
	assertMinePathFragmentMatchesOracle(t, result)
}

func TestMinePathFragment_StructuralCompleteness(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		result *engine.DepScanResult
	}{
		{"conditioned_pgp", conditionedPGPWrapperFixture(t)},
		{"selector_provenance", selectorProvenanceFixture()},
		{"lifecycle_supporting", lifecycleSupportingCallsFixture()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			payload := BuildGraphFragmentExport(tc.result)
			assertFragmentStructuralCompleteness(t, &payload)
		})
	}
}

func assertMinePathFragmentMatchesOracle(t *testing.T, result *engine.DepScanResult) {
	t.Helper()
	got := BuildGraphFragmentExport(result)
	ctx := newExportBuildContext(result)
	wantAnn, wantSupp, wantEntry := oracleMinePathFragmentCrypto(ctx, result)

	assertCryptoAnnotationsEqual(t, got.CryptoAnnotations, wantAnn)
	assertSupportingCallsEqual(t, got.SupportingCalls, wantSupp)
	assertCryptoEntryPointsEqual(t, got.CryptoEntryPoints, wantEntry)
	assertFragmentStructuralCompleteness(t, &got)
}

// oracleMinePathFragmentCrypto independently implements the post-#214 mine-path
// contract for comparison against materializeGraphFragmentCrypto.
func oracleMinePathFragmentCrypto(
	ctx *exportBuildContext,
	result *engine.DepScanResult,
) (
	[]graphfrag.GraphFragmentCryptoOp,
	[]graphfrag.GraphFragmentSupporting,
	[]graphfrag.GraphFragmentCryptoEntryPoint,
) {
	if result == nil || result.Report == nil || result.CallGraph == nil {
		return nil, nil, nil
	}
	var annotations []graphfrag.GraphFragmentCryptoOp
	var supportingOut []graphfrag.GraphFragmentSupporting
	supportingSeen := make(map[string]bool)
	entries := make(map[string]*graphFragmentEntryPointData)

	for _, finding := range result.Report.Findings {
		for i := range finding.CryptographicAssets {
			asset := finding.CryptographicAssets[i]
			op := buildGraphFragmentCryptoAnnotation(ctx, finding, asset)
			supporting := deriveSupportingCallsForFinding(ctx, finding, asset)
			op.SupportingCallIDs = supportingCallIDsOf(supporting)
			annotations = append(annotations, op)

			for j := range supporting {
				sc := &supporting[j]
				if !supportingSeen[sc.SupportingID] {
					supportingSeen[sc.SupportingID] = true
					supportingOut = append(supportingOut, fragmentSupportingFromInternal(*sc))
				}
			}

			chains := oracleFragmentEntryPointChains(ctx, finding, asset)
			addGraphFragmentFindingReachability(entries, chains, asset.FindingID)
			for j := range supporting {
				addGraphFragmentSupportingReachability(entries, chains, supporting[j].SupportingID)
			}
		}
	}

	sort.SliceStable(annotations, func(i, j int) bool {
		if annotations[i].FunctionKey != annotations[j].FunctionKey {
			return annotations[i].FunctionKey < annotations[j].FunctionKey
		}
		if annotations[i].StartLine != annotations[j].StartLine {
			return annotations[i].StartLine < annotations[j].StartLine
		}
		return annotations[i].FindingID < annotations[j].FindingID
	})
	sort.SliceStable(supportingOut, func(i, j int) bool {
		return supportingOut[i].SupportingID < supportingOut[j].SupportingID
	})
	return annotations, supportingOut, flattenGraphFragmentEntryPoints(ctx.kb, entries)
}

// oracleFragmentEntryPointChains mirrors fragmentEntryPointChains without calling it.
func oracleFragmentEntryPointChains(
	ctx *exportBuildContext,
	finding entities.Finding,
	asset entities.CryptographicAsset,
) [][]callGraphChainNode {
	containingFn := ctx.findContainingFunctionByFinding(finding.FilePath, asset.StartLine)
	if containingFn == nil {
		return nil
	}
	if len(asset.ParameterConditions) == 0 {
		return cloneCallGraphChains(structuralCallChains(ctx, containingFn))
	}
	matchedOperation := buildMatchedOperation(asset)
	var cryptoCall *callGraphCalledFunction
	if matchedOperation != nil && matchedOperation.Kind == matchedOperationCall {
		cryptoCall = findCryptoCall(ctx, ctx.graph, containingFn, asset, asset.StartLine, asset.EndLine)
	}
	raw := structuralTracebackChains(ctx, containingFn)
	var chains [][]callGraphChainNode
	if len(raw) == 0 {
		node := buildChainNode(ctx, containingFn.ID, containingFn.FilePath)
		chains = [][]callGraphChainNode{{node}}
	} else {
		expanded := expandCallChainCallSites(ctx.graph, raw, callGraphExportMaxChains)
		chains = materializeCallChainNodes(ctx, expanded)
	}
	attachCryptoCall(chains, cryptoCall)
	return filterConditionedCallChains(chains, asset.ParameterConditions)
}

func assertCryptoAnnotationsEqual(t *testing.T, got, want []graphfrag.GraphFragmentCryptoOp) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("crypto_annotations len got=%d want=%d", len(got), len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.FindingID != w.FindingID || g.FunctionKey != w.FunctionKey || g.StartLine != w.StartLine || g.RuleID != w.RuleID {
			t.Fatalf("crypto_annotations[%d] identity got={%s %s %d %s} want={%s %s %d %s}",
				i, g.FindingID, g.FunctionKey, g.StartLine, g.RuleID, w.FindingID, w.FunctionKey, w.StartLine, w.RuleID)
		}
		if !stringSlicesEqual(g.SupportingCallIDs, w.SupportingCallIDs) {
			t.Fatalf("crypto_annotations[%d] supporting_call_ids got=%v want=%v", i, g.SupportingCallIDs, w.SupportingCallIDs)
		}
	}
}

func assertSupportingCallsEqual(t *testing.T, got, want []graphfrag.GraphFragmentSupporting) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("supporting_calls len got=%d want=%d", len(got), len(want))
	}
	for i := range want {
		if got[i].SupportingID != want[i].SupportingID || got[i].FunctionKey != want[i].FunctionKey || got[i].Category != want[i].Category {
			t.Fatalf("supporting_calls[%d] got={%s %s %s} want={%s %s %s}",
				i, got[i].SupportingID, got[i].FunctionKey, got[i].Category,
				want[i].SupportingID, want[i].FunctionKey, want[i].Category)
		}
	}
}

func assertCryptoEntryPointsEqual(t *testing.T, got, want []graphfrag.GraphFragmentCryptoEntryPoint) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("crypto_entry_points len got=%d want=%d", len(got), len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.FunctionKey != w.FunctionKey {
			t.Fatalf("crypto_entry_points[%d] function_key got=%s want=%s", i, g.FunctionKey, w.FunctionKey)
		}
		if !reachableFindingsEqual(g.ReachableFindings, w.ReachableFindings) {
			t.Fatalf("crypto_entry_points[%d] (%s) reachable_findings got=%v want=%v",
				i, g.FunctionKey, summarizeReachableFindings(g.ReachableFindings), summarizeReachableFindings(w.ReachableFindings))
		}
		if !reachableSupportingEqual(g.ReachableSupportingCalls, w.ReachableSupportingCalls) {
			t.Fatalf("crypto_entry_points[%d] (%s) reachable_supporting_calls got=%v want=%v",
				i, g.FunctionKey, summarizeReachableSupporting(g.ReachableSupportingCalls), summarizeReachableSupporting(w.ReachableSupportingCalls))
		}
	}
}

func reachableFindingsEqual(got, want []graphfrag.GraphFragmentReachableFinding) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i].FindingID != want[i].FindingID || got[i].ChainDepth != want[i].ChainDepth || got[i].FindingGraphRef != want[i].FindingGraphRef {
			return false
		}
	}
	return true
}

func reachableSupportingEqual(got, want []graphfrag.GraphFragmentReachableSupportingCall) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i].SupportingID != want[i].SupportingID || got[i].ChainDepth != want[i].ChainDepth || got[i].SupportingCallRef != want[i].SupportingCallRef {
			return false
		}
	}
	return true
}

func summarizeReachableFindings(in []graphfrag.GraphFragmentReachableFinding) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, r.FindingID+":"+itoa(r.ChainDepth))
	}
	return out
}

func summarizeReachableSupporting(in []graphfrag.GraphFragmentReachableSupportingCall) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, r.SupportingID+":"+itoa(r.ChainDepth))
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func stringSlicesEqual(a, b []string) bool {
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

// assertFragmentStructuralCompleteness locks quantity/quality invariants that
// must hold for any mine-path fragment, independent of the oracle.
func assertFragmentStructuralCompleteness(t *testing.T, payload *graphfrag.GraphFragmentExport) {
	t.Helper()
	if payload == nil {
		t.Fatal("payload is nil")
		return
	}
	fnKeys := make(map[string]bool, len(payload.Functions))
	for i := range payload.Functions {
		if key := payload.Functions[i].Key; key != "" {
			fnKeys[key] = true
		}
	}
	suppIDs := make(map[string]bool, len(payload.SupportingCalls))
	for i := range payload.SupportingCalls {
		sc := &payload.SupportingCalls[i]
		if sc.SupportingID == "" {
			t.Fatalf("supporting_calls entry missing supporting_id")
		}
		if suppIDs[sc.SupportingID] {
			t.Fatalf("duplicate supporting_id %s", sc.SupportingID)
		}
		suppIDs[sc.SupportingID] = true
	}

	annFindings := make(map[string]bool)
	for i := range payload.CryptoAnnotations {
		ann := &payload.CryptoAnnotations[i]
		if ann.FindingID == "" {
			t.Fatalf("crypto_annotation missing finding_id")
		}
		annFindings[ann.FindingID] = true
		if ann.FunctionKey != "" && !fnKeys[ann.FunctionKey] {
			t.Fatalf("annotation %s function_key %s not in functions[]", ann.FindingID, ann.FunctionKey)
		}
		for _, id := range ann.SupportingCallIDs {
			if !suppIDs[id] {
				t.Fatalf("annotation %s references unknown supporting_call_id %s", ann.FindingID, id)
			}
		}
	}

	// Every annotation finding must appear on at least one entry point with depth >= 1.
	foundOnEntry := make(map[string]int) // finding_id → min depth seen
	for i := range payload.CryptoEntryPoints {
		ep := &payload.CryptoEntryPoints[i]
		if ep.FunctionKey == "" {
			t.Fatalf("crypto_entry_point missing function_key")
		}
		for _, rf := range ep.ReachableFindings {
			if rf.FindingID == "" || rf.ChainDepth < 1 {
				t.Fatalf("entry %s has invalid reachable finding %#v", ep.FunctionKey, rf)
			}
			if d, ok := foundOnEntry[rf.FindingID]; !ok || rf.ChainDepth < d {
				foundOnEntry[rf.FindingID] = rf.ChainDepth
			}
		}
		for _, rs := range ep.ReachableSupportingCalls {
			if rs.SupportingID == "" || rs.ChainDepth < 1 {
				t.Fatalf("entry %s has invalid reachable supporting %#v", ep.FunctionKey, rs)
			}
			if !suppIDs[rs.SupportingID] {
				t.Fatalf("entry %s references unknown supporting_id %s", ep.FunctionKey, rs.SupportingID)
			}
		}
	}
	for id := range annFindings {
		if _, ok := foundOnEntry[id]; !ok {
			t.Fatalf("finding_id %s present in crypto_annotations but missing from all crypto_entry_points.reachable_findings", id)
		}
	}
}

// --- fixtures ---

func conditionedPGPWrapperFixture(t *testing.T) *engine.DepScanResult {
	t.Helper()
	rules := writeConditionedRules(t, `rules:
  - id: java.pgp.aes128
    message: AES-128 PGP
    severity: INFO
    pattern: new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_128)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: AES
        algorithmName: AES-128
        operation: encrypt
        parameterCondition: param[0]==SymmetricKeyAlgorithmTags.AES_128
        api: org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>
  - id: java.pgp.des
    message: DES PGP
    severity: INFO
    pattern: new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.DES)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: DES
        algorithmName: DES
        operation: encrypt
        parameterCondition: param[0]==SymmetricKeyAlgorithmTags.DES
        api: org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>
`)
	firstID := callgraph.FunctionID{Package: "example", Type: "PGPFlow", Name: "first#0"}
	secondID := callgraph.FunctionID{Package: "example", Type: "PGPFlow", Name: "second#0"}
	buildID := callgraph.FunctionID{Package: "example", Type: "PGPFlow", Name: "build#1"}
	ctorID := callgraph.FunctionID{Package: "org.bouncycastle.openpgp.operator.jcajce", Type: "JcePGPDataEncryptorBuilder", Name: "<init>#1"}
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			firstID.String():  {ID: firstID, FilePath: "PGPFlow.java", Calls: []callgraph.FunctionCall{{Callee: buildID, Arguments: []string{"SymmetricKeyAlgorithmTags.AES_128"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "SymmetricKeyAlgorithmTags.AES_128"}}}}}},
			secondID.String(): {ID: secondID, FilePath: "PGPFlow.java", Calls: []callgraph.FunctionCall{{Callee: buildID, Arguments: []string{"SymmetricKeyAlgorithmTags.DES"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "SymmetricKeyAlgorithmTags.DES"}}}}}},
			buildID.String(): {
				ID: buildID, FilePath: "PGPFlow.java", StartLine: 10, EndLine: 12,
				Parameters: []callgraph.FunctionParameter{{Name: "algorithm", Type: "int"}},
				Calls:      []callgraph.FunctionCall{{Callee: ctorID, FilePath: "PGPFlow.java", Line: 11, StartCol: 16, EndCol: 63, Arguments: []string{"algorithm"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "PARAMETER", Name: "algorithm", ParameterIndex: 0}}}}},
			},
		},
		Callers: map[string][]string{buildID.String(): {firstID.String(), secondID.String()}},
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: "PGPFlow.java", Language: "java", CryptographicAssets: []entities.CryptographicAsset{{
		StartLine: 11, EndLine: 11, StartCol: 16, EndCol: 63, Match: "new JcePGPDataEncryptorBuilder(algorithm)",
		Rules: []entities.RuleInfo{{ID: "java.pgp.dynamic"}}, Metadata: map[string]string{"api": "org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder.<init>"},
	}}}}}
	if got := MaterializeConditionedFindings(report, graph, []string{rules}, "java"); got != 2 {
		t.Fatalf("MaterializeConditionedFindings() = %d, want 2", got)
	}
	for i := range report.Findings[0].CryptographicAssets {
		asset := &report.Findings[0].CryptographicAssets[i]
		asset.FindingID = asset.Rules[0].ID
	}
	return &engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java"}
}

func selectorProvenanceFixture() *engine.DepScanResult {
	runID := callgraph.FunctionID{Package: "example", Type: "DigestFlow", Name: "run#0"}
	wrapID := callgraph.FunctionID{Package: "example", Type: "DigestFlow", Name: "wrap#1"}
	selectID := callgraph.FunctionID{Package: "example", Type: "DigestFlow", Name: "select#1"}
	helperID := callgraph.FunctionID{Package: "example", Type: "DigestFlow", Name: "algorithm#0"}
	digestID := callgraph.FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance#1"}
	graph := &callgraph.CallGraph{Functions: map[string]*callgraph.FunctionDecl{
		runID.String(): {
			ID: runID, FilePath: "DigestFlow.java", StartLine: 1, EndLine: 8,
			Calls: []callgraph.FunctionCall{
				{Callee: wrapID, Arguments: []string{"\"SHA-512\""}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "\"SHA-512\""}}}},
				{Callee: digestID, FilePath: "DigestFlow.java", Line: 6, Arguments: []string{"algorithm()"}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "CALL_RESULT", CallTarget: &helperID}}}},
			},
		},
		helperID.String(): {ID: helperID, ReturnSources: []callgraph.SourceNode{{Type: "VALUE", Value: "\"SHA-256\""}}},
		wrapID.String(): {
			ID: wrapID, Parameters: []callgraph.FunctionParameter{{Name: "algorithm", Type: "String"}},
			Calls: []callgraph.FunctionCall{{
				Callee: selectID, Arguments: []string{"algorithm"},
				ArgumentSources: [][]callgraph.SourceNode{{{Type: "PARAMETER", Name: "algorithm", ParameterIndex: 0}}},
			}},
			ReturnSources: []callgraph.SourceNode{{
				Type: "CALL_RESULT", CallTarget: &selectID,
				SourceNodes: []callgraph.SourceNode{{Type: "PARAMETER", Name: "algorithm", ParameterIndex: 0}},
			}},
		},
		selectID.String(): {
			ID: selectID, FilePath: "DigestFlow.java", StartLine: 20, EndLine: 22,
			Parameters: []callgraph.FunctionParameter{{Name: "algorithm", Type: "String"}},
			Calls: []callgraph.FunctionCall{{
				Callee: digestID, FilePath: "DigestFlow.java", Line: 21, Arguments: []string{"algorithm"},
				ArgumentSources: [][]callgraph.SourceNode{{{Type: "PARAMETER", Name: "algorithm", ParameterIndex: 0}}},
			}},
		},
	}}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "DigestFlow.java", Language: "java",
		CryptographicAssets: []entities.CryptographicAsset{
			{FindingID: "digest-return", StartLine: 6, EndLine: 6, Match: "MessageDigest.getInstance(algorithm())", Rules: []entities.RuleInfo{{ID: "java.digest.return"}}, Metadata: map[string]string{"api": "java.security.MessageDigest.getInstance"}},
			{FindingID: "digest-selector", StartLine: 21, EndLine: 21, Match: "MessageDigest.getInstance(algorithm)", Rules: []entities.RuleInfo{{ID: "java.digest.selector"}}, Metadata: map[string]string{"api": "java.security.MessageDigest.getInstance"}},
		},
	}}}
	return &engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java"}
}

func lifecycleSupportingCallsFixture() *engine.DepScanResult {
	// Minimal object-lifecycle shape: factory + operation on same receiver var.
	entryID := callgraph.FunctionID{Package: "example", Type: "Flow", Name: "run#0"}
	cipherID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance#1"}
	initID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "init#2"}
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			entryID.String(): {
				ID: entryID, FilePath: "Flow.java", StartLine: 1, EndLine: 20,
				Calls: []callgraph.FunctionCall{
					{Callee: cipherID, FilePath: "Flow.java", Line: 5, StartCol: 1, EndCol: 40, AssignedVar: "c", Arguments: []string{"\"AES\""}, ArgumentSources: [][]callgraph.SourceNode{{{Type: "VALUE", Value: "\"AES\""}}}},
					{Callee: initID, FilePath: "Flow.java", Line: 6, StartCol: 1, EndCol: 20, ReceiverVar: "c", Arguments: []string{"1", "key"}},
				},
			},
		},
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{
		FilePath: "Flow.java", Language: "java",
		CryptographicAssets: []entities.CryptographicAsset{{
			FindingID: "cipher-init", StartLine: 6, EndLine: 6, StartCol: 1, EndCol: 20,
			Match: "c.init(1, key)", Rules: []entities.RuleInfo{{ID: "java.cipher.init"}},
			Metadata: map[string]string{"api": "javax.crypto.Cipher.init"},
		}},
	}}}
	return &engine.DepScanResult{Report: report, CallGraph: graph, Ecosystem: "java"}
}
