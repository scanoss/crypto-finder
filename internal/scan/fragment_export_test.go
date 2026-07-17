package scan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

func TestExportGraphFragment_WritesDecodableNoEscapeJSON(t *testing.T) {
	t.Parallel()

	initID := callgraph.FunctionID{Package: "org.example", Type: "CipherFactory", Name: "<init>#0"}
	helperID := callgraph.FunctionID{Package: "org.example", Type: "CipherFactory", Name: "helper#0"}
	externalID := callgraph.FunctionID{Package: "net.crypto", Type: "Cipher", Name: "getInstance#1"}
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			initID.String(): {
				ID:        initID,
				FilePath:  "CipherFactory.java",
				StartLine: 1,
				EndLine:   3,
				Calls: []callgraph.FunctionCall{
					{Callee: helperID, FilePath: "CipherFactory.java", Line: 2},
					{Callee: externalID, FilePath: "CipherFactory.java", Line: 3},
				},
			},
			helperID.String(): {
				ID:        helperID,
				FilePath:  "CipherFactory.java",
				StartLine: 5,
				EndLine:   6,
			},
		},
		Callers: map[string][]string{
			helperID.String():   {initID.String()},
			externalID.String(): {initID.String()},
		},
	}
	path := filepath.Join(t.TempDir(), "fragment.json")

	if err := ExportGraphFragment(path, "json", &engine.DepScanResult{
		CallGraph:  graph,
		RootModule: "org.example:cipher-factory",
		Ecosystem:  "java",
	}); err != nil {
		t.Fatalf("ExportGraphFragment: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(data, []byte("<init>")) {
		t.Fatalf("export should preserve <init> without HTML escaping: %s", data)
	}
	if bytes.Contains(data, []byte(`\u003cinit\u003e`)) {
		t.Fatalf("export HTML-escaped <init>: %s", data)
	}
	var decoded graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v\n%s", err, data)
	}
	if got, want := decoded.ScanMetadata.FunctionCount, 2; got != want {
		t.Fatalf("function_count = %d, want %d", got, want)
	}
	if got, want := decoded.ScanMetadata.InternalEdges, 1; got != want {
		t.Fatalf("internal_edge_count = %d, want %d", got, want)
	}
	if got, want := decoded.ScanMetadata.ExternalCalls, 1; got != want {
		t.Fatalf("external_call_count = %d, want %d", got, want)
	}
	if got, want := len(decoded.CompactInternalEdges), 1; got != want {
		t.Fatalf("compact internal edges len = %d, want %d", got, want)
	}
	if got := len(decoded.InternalEdges); got != 0 {
		t.Fatalf("full internal edges len = %d, want 0 in compact export", got)
	}
	if got, want := decoded.Functions[0].Key, initID.String(); got != want {
		t.Fatalf("function key = %q, want %q", got, want)
	}
	fragment := decoded.ToFragment(graphfrag.ComponentKey{Purl: "pkg:maven/org.example/cipher-factory", Version: "1.0.0"})
	if got, want := len(fragment.InternalEdges), 1; got != want {
		t.Fatalf("decoded fragment internal edges len = %d, want %d", got, want)
	}
	if got, want := fragment.InternalEdges[0].Caller, initID.String(); got != want {
		t.Fatalf("decoded fragment caller = %q, want %q", got, want)
	}
	if got, want := fragment.InternalEdges[0].Callee, helperID.String(); got != want {
		t.Fatalf("decoded fragment callee = %q, want %q", got, want)
	}
	if fragment.InternalEdges[0].EntryCall == nil {
		t.Fatal("decoded fragment internal edge EntryCall is nil")
	}
	if got, want := fragment.InternalEdges[0].EntryCall.Line, 2; got != want {
		t.Fatalf("decoded fragment entry_call line = %d, want %d", got, want)
	}
}

func TestBuildGraphFragmentExport_SeparatesInternalAndExternalCalls(t *testing.T) {
	t.Parallel()

	bridgeID := callgraph.FunctionID{Package: "org.bridge", Type: "Bridge", Name: "bridge#0"}
	helperID := callgraph.FunctionID{Package: "org.bridge", Type: "Bridge", Name: "helper#0"}
	cryptoID := callgraph.FunctionID{Package: "net.crypto", Type: "CryptoSink", Name: "encrypt#0"}
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			bridgeID.String(): {
				ID:         bridgeID,
				FilePath:   "Bridge.java",
				StartLine:  4,
				EndLine:    8,
				ReturnType: "void",
				Calls: []callgraph.FunctionCall{
					{Callee: helperID, FilePath: "Bridge.java", Line: 5, Raw: "helper()"},
					{Callee: cryptoID, FilePath: "Bridge.java", Line: 6, Raw: "sink.encrypt()"},
				},
			},
			helperID.String(): {
				ID:         helperID,
				FilePath:   "Bridge.java",
				StartLine:  10,
				EndLine:    10,
				ReturnType: "void",
			},
		},
		Callers: map[string][]string{
			helperID.String(): {bridgeID.String()},
			cryptoID.String(): {bridgeID.String()},
		},
	}

	payload := BuildGraphFragmentExport(&engine.DepScanResult{
		CallGraph:  graph,
		RootModule: "org.bridge:b-bridge",
		Ecosystem:  "java",
	})

	if payload.SchemaVersion != graphfrag.SchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", payload.SchemaVersion, graphfrag.SchemaVersion)
	}
	if got, want := len(payload.Functions), 2; got != want {
		t.Fatalf("functions len = %d, want %d", got, want)
	}
	if got, want := len(payload.InternalEdges), 1; got != want {
		t.Fatalf("internal edges len = %d, want %d", got, want)
	}
	if payload.InternalEdges[0].CallerKey != bridgeID.String() || payload.InternalEdges[0].CalleeKey != helperID.String() {
		t.Fatalf("unexpected internal edge: %#v", payload.InternalEdges[0])
	}
	if got, want := len(payload.ExternalCalls), 1; got != want {
		t.Fatalf("external calls len = %d, want %d", got, want)
	}
	if payload.ExternalCalls[0].CallerKey != bridgeID.String() || payload.ExternalCalls[0].TargetKey != cryptoID.String() {
		t.Fatalf("unexpected external call: %#v", payload.ExternalCalls[0])
	}
}

func TestBuildGraphFragmentExport_FromJavaSourceZeroFindingBridge(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `package org.bridge;

import net.crypto.CryptoSink;

class Bridge {
    void bridge() {
        CryptoSink sink = new CryptoSink();
        sink.encrypt();
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "Bridge.java"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	builder := callgraph.NewBuilder(callgraph.NewJavaParser())
	graph, err := builder.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "org.bridge:b-bridge"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	payload := BuildGraphFragmentExport(&engine.DepScanResult{
		CallGraph:   graph,
		ProjectRoot: dir,
		RootModule:  "org.bridge:b-bridge",
		Ecosystem:   "java",
	})

	bridgeKey := callgraph.FunctionID{Package: "org.bridge", Type: "Bridge", Name: "bridge#0"}.String()
	if !hasFragmentFunction(&payload, bridgeKey) {
		t.Fatalf("expected function %q in exported fragment: %#v", bridgeKey, payload.Functions)
	}
	if !hasExternalTarget(&payload, "net.crypto.(CryptoSink).encrypt#0") {
		t.Fatalf("expected external call to CryptoSink.encrypt in exported fragment: %#v", payload.ExternalCalls)
	}
	if got := len(payload.CryptoAnnotations); got != 0 {
		t.Fatalf("crypto annotations len = %d, want 0 for zero-finding bridge", got)
	}
}

func TestBuildGraphFragmentExport_AttachesCryptoAnnotationToContainingFunction(t *testing.T) {
	t.Parallel()

	cryptoID := callgraph.FunctionID{Package: "net.crypto", Type: "CryptoSink", Name: "encrypt#0"}
	cipherID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance#1"}
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			cryptoID.String(): {
				ID:         cryptoID,
				FilePath:   "CryptoSink.java",
				StartLine:  4,
				EndLine:    8,
				ReturnType: "void",
				Calls: []callgraph.FunctionCall{{
					Callee:    cipherID,
					FilePath:  "CryptoSink.java",
					Line:      6,
					Raw:       "Cipher.getInstance(\"AES\")",
					Arguments: []string{"\"AES\""},
				}},
			},
		},
		Callers: map[string][]string{
			cipherID.String(): {cryptoID.String()},
		},
	}
	report := &entities.InterimReport{
		Tool:  entities.ToolInfo{Name: "crypto-finder", Version: "dev"},
		Rules: entities.RulesInfo{Version: "v-test-rules"},
		Findings: []entities.Finding{{
			FilePath: "CryptoSink.java",
			Language: "java",
			CryptographicAssets: []entities.CryptographicAsset{{
				StartLine: 6,
				EndLine:   6,
				Match:     "Cipher.getInstance(\"AES\")",
				FindingID: "beaecdb7",
				Rules:     []entities.RuleInfo{{ID: "java.crypto.cipher.getinstance"}},
				Metadata:  map[string]string{"api": "javax.crypto.Cipher.getInstance"},
			}},
		}},
	}

	payload := BuildGraphFragmentExport(&engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		ProjectRoot: t.TempDir(),
		RootModule:  "net.crypto:c-crypto",
		Ecosystem:   "java",
	})

	if got, want := len(payload.CryptoAnnotations), 1; got != want {
		t.Fatalf("crypto annotations len = %d, want %d", got, want)
	}
	op := payload.CryptoAnnotations[0]
	if op.FunctionKey != cryptoID.String() {
		t.Fatalf("FunctionKey = %q, want %q", op.FunctionKey, cryptoID.String())
	}
	if op.FindingID != "beaecdb7" || op.RuleID != "java.crypto.cipher.getinstance" {
		t.Fatalf("unexpected crypto annotation: %#v", op)
	}
	if op.Symbol != "javax.crypto.Cipher.getInstance" {
		t.Fatalf("Symbol = %q, want javax.crypto.Cipher.getInstance", op.Symbol)
	}
}

func TestBuildGraphFragmentExport_UsesResolvedCallerIndexEdges(t *testing.T) {
	t.Parallel()

	controllerID := callgraph.FunctionID{Package: "com.app", Type: "Controller", Name: "handle#0"}
	apiID := callgraph.FunctionID{Package: "com.dep", Type: "CryptoApi", Name: "encrypt#0"}
	implID := callgraph.FunctionID{Package: "com.dep.impl", Type: "CryptoImpl", Name: "encrypt#0"}
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			controllerID.String(): {
				ID:        controllerID,
				FilePath:  "Controller.java",
				StartLine: 1,
				EndLine:   5,
				Calls: []callgraph.FunctionCall{{
					Callee: apiID,
					Line:   3,
					Raw:    "api.encrypt()",
				}},
			},
			apiID.String(): {
				ID:        apiID,
				FilePath:  "CryptoApi.java",
				StartLine: 1,
				EndLine:   3,
			},
			implID.String(): {
				ID:        implID,
				FilePath:  "CryptoImpl.java",
				StartLine: 1,
				EndLine:   3,
			},
		},
		Callers: map[string][]string{
			apiID.String():  {controllerID.String()},
			implID.String(): {controllerID.String()},
		},
	}

	payload := BuildGraphFragmentExport(&engine.DepScanResult{CallGraph: graph, Ecosystem: "java"})

	if !hasInternalEdge(&payload, controllerID.String(), apiID.String()) {
		t.Fatalf("expected direct caller-index edge to API method: %#v", payload.InternalEdges)
	}
	if !hasInternalEdge(&payload, controllerID.String(), implID.String()) {
		t.Fatalf("expected resolved caller-index edge to implementation method: %#v", payload.InternalEdges)
	}
}

func TestBuildGraphFragmentExport_CarriesEdgeResolution(t *testing.T) {
	t.Parallel()

	controllerID := callgraph.FunctionID{Package: "app", Type: "Controller", Name: "handle#0"}
	ifaceID := callgraph.FunctionID{Package: "com.dep", Type: "Sink", Name: "run#0"}
	implID := callgraph.FunctionID{Package: "com.dep.impl", Type: "SinkImpl", Name: "run#0"}
	extID := callgraph.FunctionID{Package: "com.dep", Type: "Fluent", Name: "chain#0"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			controllerID.String(): {
				ID:        controllerID,
				FilePath:  "Controller.java",
				StartLine: 1,
				EndLine:   5,
				Calls: []callgraph.FunctionCall{
					{Callee: ifaceID, FilePath: "Controller.java", Line: 3, Raw: "sink.run()"},
				},
			},
			ifaceID.String(): {ID: ifaceID, FilePath: "Sink.java", StartLine: 1, EndLine: 2},
			implID.String():  {ID: implID, FilePath: "SinkImpl.java", StartLine: 1, EndLine: 4},
		},
		Callers: map[string][]string{
			ifaceID.String(): {controllerID.String()}, // internal, exact
			implID.String():  {controllerID.String()}, // internal, interface_dispatch
			extID.String():   {controllerID.String()}, // external (no decl), name_only
		},
		EdgeResolutions: map[string]callgraph.EdgeResolution{},
	}
	exactRes := callgraph.EdgeResolution{Kind: callgraph.EdgeKindExact, MethodName: "run", Arity: 0, CallSite: 3}
	ifaceRes := callgraph.EdgeResolution{Kind: callgraph.EdgeKindInterfaceDispatch, DeclaredType: "com.dep.Sink", MethodName: "run", Arity: 0, CallSite: 11}
	extRes := callgraph.EdgeResolution{Kind: callgraph.EdgeKindNameOnly, MethodName: "chain", Arity: 0, CallSite: 12}
	graph.EdgeResolutions[callgraph.EdgeResolutionKey(controllerID.String(), ifaceID.String(), exactRes)] = exactRes
	graph.EdgeResolutions[callgraph.EdgeResolutionKey(controllerID.String(), implID.String(), ifaceRes)] = ifaceRes
	graph.EdgeResolutions[callgraph.EdgeResolutionKey(controllerID.String(), extID.String(), extRes)] = extRes

	payload := BuildGraphFragmentExport(&engine.DepScanResult{CallGraph: graph, Ecosystem: "java"})

	exact := findInternalEdge(&payload, controllerID.String(), ifaceID.String())
	if exact == nil || exact.Resolution != string(callgraph.EdgeKindExact) {
		t.Fatalf("internal exact edge resolution = %#v, want exact", exact)
	}
	iface := findInternalEdge(&payload, controllerID.String(), implID.String())
	if iface == nil || iface.Resolution != string(callgraph.EdgeKindInterfaceDispatch) {
		t.Fatalf("internal interface edge = %#v, want interface_dispatch", iface)
	}
	if iface.DeclaredType != "com.dep.Sink" || iface.MethodName != "run" || iface.Arity != 0 {
		t.Fatalf("internal interface edge metadata = %#v, want declared com.dep.Sink/run/0", iface)
	}
	if iface.Line != 11 {
		t.Fatalf("internal interface edge line = %d, want recorded call site 11", iface.Line)
	}
	ext := findExternalCall(&payload, controllerID.String(), extID.String())
	if ext == nil || ext.Resolution != string(callgraph.EdgeKindNameOnly) {
		t.Fatalf("external name-only call resolution = %#v, want name_only", ext)
	}
	if ext.Line != 12 {
		t.Fatalf("external name-only call line = %d, want recorded call site 12", ext.Line)
	}
}

func TestBuildGraphFragmentExport_EntryCallUsesMatchingCallSiteLine(t *testing.T) {
	t.Parallel()

	callerID := callgraph.FunctionID{Package: "app", Type: "Controller", Name: "handle#0"}
	calleeID := callgraph.FunctionID{Package: "com.dep", Type: "Sink", Name: "run#1"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			callerID.String(): {
				ID:        callerID,
				FilePath:  "Controller.java",
				StartLine: 1,
				EndLine:   20,
				Calls: []callgraph.FunctionCall{
					{Callee: calleeID, FilePath: "Controller.java", Line: 3, Arguments: []string{"first"}, Raw: "sink.run(first)"},
					{Callee: calleeID, FilePath: "Controller.java", Line: 9, Arguments: []string{"second"}, Raw: "sink.run(second)"},
				},
			},
			calleeID.String(): {
				ID:         calleeID,
				FilePath:   "Sink.java",
				StartLine:  1,
				EndLine:    2,
				Parameters: []callgraph.FunctionParameter{{Type: "String"}},
			},
		},
		Callers: map[string][]string{
			calleeID.String(): {callerID.String()},
		},
		EdgeResolutions: map[string]callgraph.EdgeResolution{},
	}
	resLine3 := callgraph.EdgeResolution{Kind: callgraph.EdgeKindExact, MethodName: "run", Arity: 1, CallSite: 3}
	resLine9 := callgraph.EdgeResolution{Kind: callgraph.EdgeKindExact, MethodName: "run", Arity: 1, CallSite: 9}
	graph.EdgeResolutions[callgraph.EdgeResolutionKey(callerID.String(), calleeID.String(), resLine3)] = resLine3
	graph.EdgeResolutions[callgraph.EdgeResolutionKey(callerID.String(), calleeID.String(), resLine9)] = resLine9

	payload := BuildGraphFragmentExport(&engine.DepScanResult{CallGraph: graph, Ecosystem: "java"})

	gotByLine := make(map[int]*graphfrag.GraphFragmentCallSite)
	for i := range payload.InternalEdges {
		edge := payload.InternalEdges[i]
		if edge.CallerKey == callerID.String() && edge.CalleeKey == calleeID.String() {
			gotByLine[edge.Line] = edge.EntryCall
		}
	}
	for line, wantArg := range map[int]string{3: "first", 9: "second"} {
		entryCall := gotByLine[line]
		if entryCall == nil || len(entryCall.Parameters) != 1 {
			t.Fatalf("line %d EntryCall = %#v, want one parameter", line, entryCall)
		}
		if entryCall.Parameters[0].ArgumentExpression != wantArg {
			t.Fatalf("line %d ArgumentExpression = %q, want %q", line, entryCall.Parameters[0].ArgumentExpression, wantArg)
		}
	}
}

func findInternalEdge(payload *graphfrag.GraphFragmentExport, caller, callee string) *graphfrag.GraphFragmentEdge {
	for i := range payload.InternalEdges {
		if payload.InternalEdges[i].CallerKey == caller && payload.InternalEdges[i].CalleeKey == callee {
			return &payload.InternalEdges[i]
		}
	}
	return nil
}

func findExternalCall(payload *graphfrag.GraphFragmentExport, caller, target string) *graphfrag.GraphFragmentExternal {
	for i := range payload.ExternalCalls {
		if payload.ExternalCalls[i].CallerKey == caller && payload.ExternalCalls[i].TargetKey == target {
			return &payload.ExternalCalls[i]
		}
	}
	return nil
}

func hasFragmentFunction(payload *graphfrag.GraphFragmentExport, key string) bool {
	for i := range payload.Functions {
		fn := &payload.Functions[i]
		if fn.Key == key {
			return true
		}
	}
	return false
}

func hasExternalTarget(payload *graphfrag.GraphFragmentExport, target string) bool {
	for i := range payload.ExternalCalls {
		call := &payload.ExternalCalls[i]
		if call.TargetKey == target {
			return true
		}
	}
	return false
}

func hasInternalEdge(payload *graphfrag.GraphFragmentExport, caller, callee string) bool {
	for i := range payload.InternalEdges {
		edge := &payload.InternalEdges[i]
		if edge.CallerKey == caller && edge.CalleeKey == callee {
			return true
		}
	}
	return false
}

// ----------------------------------------------------------------------------
// Phase 3.1 — RED tests for graph-fragment-1.2 population
// ----------------------------------------------------------------------------

// TestBuildGraphFragmentExport_EdgeEntryCallEqualsBuiltParams verifies that an
// exported internal edge's entry_call.parameters equals what
// buildCallSiteParameters returns for the same FunctionCall.
func TestBuildGraphFragmentExport_EdgeEntryCallEqualsBuiltParams(t *testing.T) {
	t.Parallel()

	callerID := callgraph.FunctionID{Package: "com.app", Type: "Service", Name: "init#0"}
	calleeID := callgraph.FunctionID{Package: "com.lib", Type: "Cipher", Name: "getInstance#1"}

	callee := &callgraph.FunctionDecl{
		ID:         calleeID,
		FilePath:   "Cipher.java",
		StartLine:  1,
		EndLine:    3,
		Parameters: []callgraph.FunctionParameter{{Type: "String"}},
		ReturnType: "Cipher",
	}
	theCall := callgraph.FunctionCall{
		Callee:    calleeID,
		FilePath:  "Service.java",
		Line:      7,
		Arguments: []string{`"AES"`},
	}
	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			callerID.String(): {
				ID:        callerID,
				FilePath:  "Service.java",
				StartLine: 1,
				EndLine:   10,
				Calls:     []callgraph.FunctionCall{theCall},
			},
			calleeID.String(): callee,
		},
		Callers: map[string][]string{
			calleeID.String(): {callerID.String()},
		},
	}

	result := &engine.DepScanResult{
		CallGraph:   graph,
		ProjectRoot: t.TempDir(),
		RootModule:  "com.app:app",
		Ecosystem:   "java",
	}
	payload := BuildGraphFragmentExport(result)

	// Find the internal edge caller→callee.
	edge := findInternalEdge(&payload, callerID.String(), calleeID.String())
	if edge == nil {
		t.Fatal("internal edge callerID→calleeID not found in payload")
	}
	if edge.EntryCall == nil {
		t.Fatal("edge.EntryCall is nil; expected parameters to be populated (graph-fragment-1.2)")
	}

	// Build expected parameters via the helper.
	ctx := newExportBuildContext(result)
	want := buildCallSiteParameters(ctx, &theCall)

	if len(edge.EntryCall.Parameters) != len(want) {
		t.Fatalf("EntryCall.Parameters len = %d, want %d", len(edge.EntryCall.Parameters), len(want))
	}
	for i := range edge.EntryCall.Parameters {
		got := edge.EntryCall.Parameters[i]
		w := want[i]
		if got.ParameterIndex != w.ParameterIndex {
			t.Errorf("[%d] ParameterIndex = %d, want %d", i, got.ParameterIndex, w.ParameterIndex)
		}
		if got.ArgumentExpression != w.ArgumentExpression {
			t.Errorf("[%d] ArgumentExpression = %q, want %q", i, got.ArgumentExpression, w.ArgumentExpression)
		}
		if got.Type != w.Type {
			t.Errorf("[%d] Type = %q, want %q", i, got.Type, w.Type)
		}
	}
}

// TestBuildGraphFragmentExport_CryptoOpCryptoCallIdentityMatchesFunctionDecl
// verifies that the exported crypto_op.crypto_call identity fields
// (function_name) match the containing/crypto FunctionDecl.
func TestBuildGraphFragmentExport_CryptoOpCryptoCallIdentityMatchesFunctionDecl(t *testing.T) {
	t.Parallel()

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
				FindingID: "aabbccdd",
				Rules:     []entities.RuleInfo{{ID: "java.crypto.cipher.getinstance"}},
				Metadata:  map[string]string{"api": "javax.crypto.Cipher.getInstance", "assetType": "algorithm"},
				Source:    "direct",
			}},
		}},
	}

	payload := BuildGraphFragmentExport(&engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		ProjectRoot: t.TempDir(),
		RootModule:  "com.app:app",
		Ecosystem:   "java",
	})

	if len(payload.CryptoAnnotations) != 1 {
		t.Fatalf("CryptoAnnotations len = %d, want 1", len(payload.CryptoAnnotations))
	}
	op := payload.CryptoAnnotations[0]

	// (b) crypto_op.crypto_call identity fields must match the crypto FunctionDecl.
	if op.CryptoCall == nil {
		t.Fatal("CryptoCall is nil; expected it to be populated (graph-fragment-1.2)")
	}
	wantFunctionName := "javax.crypto.Cipher.getInstance"
	if op.CryptoCall.FunctionName != wantFunctionName {
		t.Errorf("CryptoCall.FunctionName = %q, want %q", op.CryptoCall.FunctionName, wantFunctionName)
	}
}

// TestBuildGraphFragmentExport_CryptoOpAssetMetadataPopulated verifies that
// crypto_op.oid, metadata, and source are populated from a known-asset fixture.
func TestBuildGraphFragmentExport_CryptoOpAssetMetadataPopulated(t *testing.T) {
	t.Parallel()

	cryptoFnID := callgraph.FunctionID{Package: "com.app", Type: "Service", Name: "doEncrypt#0"}
	cipherID := callgraph.FunctionID{Package: "javax.crypto", Type: "Cipher", Name: "getInstance#1"}

	graph := &callgraph.CallGraph{
		Functions: map[string]*callgraph.FunctionDecl{
			cryptoFnID.String(): {
				ID:        cryptoFnID,
				FilePath:  "Service.java",
				StartLine: 5,
				EndLine:   12,
				Calls: []callgraph.FunctionCall{{
					Callee:   cipherID,
					FilePath: "Service.java",
					Line:     8,
				}},
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
				FindingID: "aabbccdd",
				Rules:     []entities.RuleInfo{{ID: "java.crypto.cipher.getinstance"}},
				Metadata:  map[string]string{"api": "javax.crypto.Cipher.getInstance", "assetType": "algorithm", "algorithmFamily": "AES"},
				OID:       "2.16.840.1.101.3.4.1.2",
				Source:    "direct",
			}},
		}},
	}

	payload := BuildGraphFragmentExport(&engine.DepScanResult{
		Report:      report,
		CallGraph:   graph,
		ProjectRoot: t.TempDir(),
		RootModule:  "com.app:app",
		Ecosystem:   "java",
	})

	if len(payload.CryptoAnnotations) != 1 {
		t.Fatalf("CryptoAnnotations len = %d, want 1", len(payload.CryptoAnnotations))
	}
	op := payload.CryptoAnnotations[0]

	// (c) oid/metadata/source are populated for a known-asset fixture.
	if op.OID != "2.16.840.1.101.3.4.1.2" {
		t.Errorf("OID = %q, want 2.16.840.1.101.3.4.1.2", op.OID)
	}
	if op.Source != "direct" {
		t.Errorf("Source = %q, want direct", op.Source)
	}
	if len(op.Metadata) == 0 {
		t.Error("Metadata is empty; expected the asset metadata JSON to be stored")
	}
}

// TestBuildGraphFragmentExport_CarriesObjectIdentity guards the graph-fragment-1.4
// enrichment: edges must carry the call-site object identity (ReceiverVar /
// AssignedVar / ChainID) so object-lifecycle supporting calls can be re-derived
// from the cached fragment alone (the annotate path). It covers BOTH the
// receiver-var lifecycle (the dominant JCA idiom) and the fluent-chain case,
// whose intermediate links are unresolved in a standalone scan and must still
// recover their shared ChainID (regression guard for chainIDForLine).
func TestBuildGraphFragmentExport_CarriesObjectIdentity(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `package com.app;

class App {
    void run() {
        Foo f = new Foo();
        f.init();
        f.execute();
        Builder.start("x").configure().build();
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "App.java"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := callgraph.NewBuilder(callgraph.NewJavaParser()).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: "com.app:app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	payload := BuildGraphFragmentExport(&engine.DepScanResult{
		CallGraph: graph, ProjectRoot: dir, RootModule: "com.app:app", Ecosystem: "java",
	})

	// Receiver-var lifecycle: the constructor binds AssignedVar=f, and the
	// init/execute calls are invoked on ReceiverVar=f.
	var sawAssigned, sawReceiver bool
	for _, e := range payload.ExternalCalls {
		if e.AssignedVar == "f" {
			sawAssigned = true
		}
		if e.ReceiverVar == "f" {
			sawReceiver = true
		}
	}
	if !sawAssigned {
		t.Errorf("no edge carried AssignedVar=f (constructor object identity lost): %+v", payload.ExternalCalls)
	}
	if !sawReceiver {
		t.Errorf("no edge carried ReceiverVar=f (lifecycle object identity lost): %+v", payload.ExternalCalls)
	}

	// Fluent chain: all three links (start/configure/build) share one ChainID.
	// Before chainIDForLine recovery, only the head link carried it.
	byChain := map[string]int{}
	for _, e := range payload.ExternalCalls {
		if e.ChainID != "" {
			byChain[e.ChainID]++
		}
	}
	var maxGroup int
	for _, n := range byChain {
		if n > maxGroup {
			maxGroup = n
		}
	}
	if maxGroup < 3 {
		t.Errorf("expected a fluent chain group of >=3 edges sharing a ChainID, got groups %+v (chainIDForLine recovery regressed)", byChain)
	}
}

// TestChainIDForLine directly guards the fluent-chain ChainID recovery helper:
// when an edge's exact callee lookup fails (unresolved fluent intermediate in a
// standalone scan), the edge must still recover its group id from any chained
// call on the same line — they all share one ChainID. Reproducing the full
// key-divergence hermetically is unreliable, so this unit-tests the helper that
// the export's recovery fallback depends on.
func TestChainIDForLine(t *testing.T) {
	t.Parallel()

	fn := &callgraph.FunctionDecl{
		Calls: []callgraph.FunctionCall{
			{Callee: callgraph.FunctionID{Package: "com.x", Type: "B", Name: "start#1"}, Line: 8, ChainID: "167"},
			{Callee: callgraph.FunctionID{Package: "com.x", Type: "B", Name: "configure#0"}, Line: 8, ChainID: "167"},
			{Callee: callgraph.FunctionID{Package: "com.x", Type: "B", Name: "build#0"}, Line: 8, ChainID: "167"},
			{Callee: callgraph.FunctionID{Package: "com.x", Type: "C", Name: "noChain#0"}, Line: 12, ChainID: ""},
		},
	}
	if got := chainIDForLine(fn, 8); got != "167" {
		t.Errorf("chainIDForLine(line 8) = %q, want 167 (shared fluent chain id)", got)
	}
	if got := chainIDForLine(fn, 12); got != "" {
		t.Errorf("chainIDForLine(line 12) = %q, want empty (no chained call there)", got)
	}
	if got := chainIDForLine(nil, 8); got != "" {
		t.Errorf("chainIDForLine(nil) = %q, want empty", got)
	}
}

// TestFlattenGraphFragmentEntryPoints_PopulatesParameterRoles is the fragment
// side of the WU3 (issue-103) concrete target: a fragment crypto_entry_points
// entry whose function+arity matches a KB contract declaring parameter roles
// gets parameter_roles populated, mirroring the live-path behavior verified
// by TestBuildCryptoEntryPointsPopulatesParameterRoles.
func TestFlattenGraphFragmentEntryPoints_PopulatesParameterRoles(t *testing.T) {
	t.Parallel()

	kb := &contracts.KnowledgeBase{
		Contracts: map[string][]contracts.Contract{
			"org.bc.KeyParameter.<init>#1": {{
				Method: "org.bc.KeyParameter.<init>",
				Arity:  1,
				Return: contracts.ContractReturn{Type: "org.bc.KeyParameter", Confidence: "high"},
				Parameters: []contracts.ParameterContract{{
					Index: intPtr(0),
					Name:  "key",
					Role:  "metadata-contributing",
					Contributes: &contracts.Contribution{
						Property:   "keySize",
						Derivation: "argument_bit_length",
					},
				}},
			}},
		},
	}
	entries := map[string]*graphFragmentEntryPointData{
		"org.bc.KeyParameter.<init>#1": {
			functionKey:    "org.bc.KeyParameter.<init>#1",
			functionName:   "org.bc.KeyParameter.<init>",
			parameterTypes: []string{"byte[]"},
			findings:       make(map[string]graphfrag.GraphFragmentReachableFinding),
			supporting:     make(map[string]graphfrag.GraphFragmentReachableSupportingCall),
		},
	}

	out := flattenGraphFragmentEntryPoints(kb, entries)
	if len(out) != 1 {
		t.Fatalf("flattenGraphFragmentEntryPoints = %#v, want 1 entry", out)
	}
	if len(out[0].ParameterRoles) != 1 {
		t.Fatalf("ParameterRoles = %#v, want 1 entry", out[0].ParameterRoles)
	}
	pr := out[0].ParameterRoles[0]
	if pr.Index != 0 || pr.Role != "metadata-contributing" ||
		pr.Contributes == nil || pr.Contributes.Property != "keySize" || pr.Contributes.Derivation != "argument_bit_length" {
		t.Fatalf("ParameterRoles[0] = %#v, want index=0 metadata-contributing keySize/argument_bit_length", pr)
	}
}

func TestSortedFragmentEdges_PreserveSameLineColumnIdentity(t *testing.T) {
	t.Parallel()

	internal := sortedFragmentEdges([]graphfrag.GraphFragmentEdge{
		{CallerKey: "caller", CalleeKey: "callee", Line: 7, StartCol: 20, EndCol: 30, Resolution: string(graphfrag.ResolutionInterfaceDispatch)},
		{CallerKey: "caller", CalleeKey: "callee", Line: 7, StartCol: 4, EndCol: 14, Resolution: string(graphfrag.ResolutionInterfaceDispatch)},
	})
	if len(internal) != 2 || internal[0].StartCol != 4 || internal[1].StartCol != 20 {
		t.Fatalf("internal same-line identities lost or unstable: %+v", internal)
	}

	external := sortedFragmentExternalCalls([]graphfrag.GraphFragmentExternal{
		{CallerKey: "caller", TargetKey: "callee", Line: 7, StartCol: 20, EndCol: 30, Resolution: string(graphfrag.ResolutionInterfaceDispatch)},
		{CallerKey: "caller", TargetKey: "callee", Line: 7, StartCol: 4, EndCol: 14, Resolution: string(graphfrag.ResolutionInterfaceDispatch)},
	})
	if len(external) != 2 || external[0].StartCol != 4 || external[1].StartCol != 20 {
		t.Fatalf("external same-line identities lost or unstable: %+v", external)
	}
}
