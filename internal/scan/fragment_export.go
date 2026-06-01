package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// The graph-fragment export schema (GraphFragmentExport and friends) lives in
// the public package github.com/scanoss/crypto-finder/pkg/graphfrag: it is
// crypto-finder's contract with downstream consumers (the mining service, CI
// plugins). This file only BUILDS that schema from a callgraph.

func ExportGraphFragment(path, format string, result *engine.DepScanResult) error {
	if result == nil {
		return fmt.Errorf("cannot export graph fragment: dep scan result is nil")
	}
	if result.CallGraph == nil {
		return fmt.Errorf("cannot export graph fragment: result.CallGraph is nil")
	}
	if format != "json" {
		return fmt.Errorf("unsupported graph fragment format %q (supported: json)", format)
	}

	payload := BuildGraphFragmentExport(result)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("failed to serialize graph fragment export: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("failed to write graph fragment to %s: %w", path, err)
	}
	return nil
}

func BuildGraphFragmentExport(result *engine.DepScanResult) graphfrag.GraphFragmentExport {
	out := graphfrag.GraphFragmentExport{
		SchemaVersion: graphfrag.SchemaVersion,
		ScanMetadata: graphfrag.GraphFragmentScanMetadata{
			Ecosystem:  result.Ecosystem,
			RootModule: result.RootModule,
			ExportedAt: time.Now().UTC().Format(time.RFC3339),
		},
	}
	if result.Report != nil {
		out.ScanMetadata.ToolName = result.Report.Tool.Name
		out.ScanMetadata.ToolVersion = result.Report.Tool.Version
		out.ScanMetadata.RulesVersion = result.Report.Rules.Version
	}
	if result.CallGraph == nil {
		return out
	}

	functionKeys := make([]string, 0, len(result.CallGraph.Functions))
	for key := range result.CallGraph.Functions {
		functionKeys = append(functionKeys, key)
	}
	sort.Strings(functionKeys)

	for _, key := range functionKeys {
		decl := result.CallGraph.Functions[key]
		out.Functions = append(out.Functions, buildGraphFragmentFunction(result.CallGraph, decl.ID, decl))
	}
	out.InternalEdges, out.ExternalCalls = buildGraphFragmentResolvedEdges(result.CallGraph)

	out.CryptoAnnotations = buildGraphFragmentCryptoAnnotations(result)
	out.ScanMetadata.FunctionCount = len(out.Functions)
	out.ScanMetadata.InternalEdges = len(out.InternalEdges)
	out.ScanMetadata.ExternalCalls = len(out.ExternalCalls)
	out.ScanMetadata.CryptoOps = len(out.CryptoAnnotations)
	return out
}

func buildGraphFragmentResolvedEdges(graph *callgraph.CallGraph) ([]graphfrag.GraphFragmentEdge, []graphfrag.GraphFragmentExternal) {
	if graph == nil {
		return nil, nil
	}

	internalByKey := map[string]graphfrag.GraphFragmentEdge{}
	externalByKey := map[string]graphfrag.GraphFragmentExternal{}
	calleeKeys := make([]string, 0, len(graph.Callers))
	for calleeKey := range graph.Callers {
		calleeKeys = append(calleeKeys, calleeKey)
	}
	sort.Strings(calleeKeys)

	for _, calleeKey := range calleeKeys {
		callers := append([]string(nil), graph.Callers[calleeKey]...)
		sort.Strings(callers)
		for _, callerKey := range callers {
			callerDecl := graph.Functions[callerKey]
			if callerDecl == nil {
				continue
			}
			line := findFragmentCallLine(callerDecl, calleeKey)
			res := resolveFragmentEdge(graph, callerKey, calleeKey)
			if _, ok := graph.Functions[calleeKey]; ok {
				key := callerKey + "\x00" + calleeKey
				internalByKey[key] = graphfrag.GraphFragmentEdge{
					CallerKey:    callerKey,
					CalleeKey:    calleeKey,
					Line:         line,
					Resolution:   res.Resolution,
					DeclaredType: res.DeclaredType,
					MethodName:   res.MethodName,
					Arity:        res.Arity,
				}
				continue
			}

			external := graphfrag.GraphFragmentExternal{
				CallerKey:    callerKey,
				TargetKey:    calleeKey,
				Line:         line,
				Resolution:   res.Resolution,
				DeclaredType: res.DeclaredType,
				MethodName:   res.MethodName,
				Arity:        res.Arity,
			}
			if calleeID, err := callgraph.ParseFunctionID(calleeKey); err == nil {
				external.TargetFunctionName = fullFunctionName(calleeID)
			}
			if call := findCallForCallee(callerDecl, calleeKey); call != nil {
				external.Raw = call.Raw
				if external.TargetFunctionName == "" {
					external.TargetFunctionName = fullFunctionName(call.Callee)
				}
			}
			key := callerKey + "\x00" + calleeKey
			externalByKey[key] = external
		}
	}

	internalKeys := make([]string, 0, len(internalByKey))
	for key := range internalByKey {
		internalKeys = append(internalKeys, key)
	}
	sort.Strings(internalKeys)
	internal := make([]graphfrag.GraphFragmentEdge, 0, len(internalKeys))
	for _, key := range internalKeys {
		internal = append(internal, internalByKey[key])
	}

	externalKeys := make([]string, 0, len(externalByKey))
	for key := range externalByKey {
		externalKeys = append(externalKeys, key)
	}
	sort.Strings(externalKeys)
	external := make([]graphfrag.GraphFragmentExternal, 0, len(externalKeys))
	for _, key := range externalKeys {
		external = append(external, externalByKey[key])
	}

	return internal, external
}

type fragmentEdgeResolution struct {
	Resolution   string
	DeclaredType string
	MethodName   string
	Arity        int
}

// resolveFragmentEdge returns the resolution metadata for a caller->callee edge.
// An edge with no recorded resolution is an exact, directly-resolved source
// call (e.g. a typed re-resolution from the bytecode/type resolver), so it
// defaults to exact rather than the fail-closed "unknown" — the producer is the
// authority on resolution quality.
func resolveFragmentEdge(graph *callgraph.CallGraph, callerKey, calleeKey string) fragmentEdgeResolution {
	if graph != nil {
		if res, ok := graph.EdgeResolutions[callgraph.EdgeResolutionKey(callerKey, calleeKey)]; ok {
			return fragmentEdgeResolution{
				Resolution:   string(res.Kind),
				DeclaredType: res.DeclaredType,
				MethodName:   res.MethodName,
				Arity:        res.Arity,
			}
		}
	}
	return fragmentEdgeResolution{Resolution: string(callgraph.EdgeKindExact)}
}

func findFragmentCallLine(callerDecl *callgraph.FunctionDecl, calleeKey string) int {
	if callerDecl == nil {
		return 0
	}
	if call := findCallForCallee(callerDecl, calleeKey); call != nil {
		return call.Line
	}
	return callerDecl.StartLine
}

func findCallForCallee(callerDecl *callgraph.FunctionDecl, calleeKey string) *callgraph.FunctionCall {
	if callerDecl == nil {
		return nil
	}
	calleeID, err := callgraph.ParseFunctionID(calleeKey)
	for i := range callerDecl.Calls {
		call := &callerDecl.Calls[i]
		if call.Callee.String() == calleeKey {
			return call
		}
		if err == nil &&
			call.Callee.Package == calleeID.Package &&
			call.Callee.Type == calleeID.Type &&
			callgraph.BaseFunctionName(call.Callee.Name) == callgraph.BaseFunctionName(calleeID.Name) {
			return call
		}
	}
	return nil
}

func buildGraphFragmentFunction(graph *callgraph.CallGraph, id callgraph.FunctionID, decl *callgraph.FunctionDecl) graphfrag.GraphFragmentFunction {
	meta := buildExportFunctionMetadata(graph, id, decl)
	fn := graphfrag.GraphFragmentFunction{
		Key:                id.String(),
		FunctionName:       meta.FunctionName,
		CanonicalSignature: meta.CanonicalSignature,
		Package:            id.Package,
		Type:               id.Type,
		Name:               id.Name,
		ReturnType:         meta.ReturnType,
		ParameterTypes:     meta.ParameterTypes,
		Visibility:         meta.Visibility,
		OwnerVisibility:    meta.OwnerVisibility,
	}
	if decl != nil {
		fn.FilePath = decl.FilePath
		fn.StartLine = decl.StartLine
		fn.EndLine = decl.EndLine
	}
	return fn
}

func buildGraphFragmentCryptoAnnotations(result *engine.DepScanResult) []graphfrag.GraphFragmentCryptoOp {
	if result == nil || result.Report == nil || result.CallGraph == nil {
		return nil
	}
	ctx := newExportBuildContext(result)
	var out []graphfrag.GraphFragmentCryptoOp
	for _, finding := range result.Report.Findings {
		for i := range finding.CryptographicAssets {
			asset := finding.CryptographicAssets[i]
			out = append(out, buildGraphFragmentCryptoAnnotation(ctx, finding, asset))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].FunctionKey != out[j].FunctionKey {
			return out[i].FunctionKey < out[j].FunctionKey
		}
		if out[i].StartLine != out[j].StartLine {
			return out[i].StartLine < out[j].StartLine
		}
		return out[i].FindingID < out[j].FindingID
	})
	return out
}

func buildGraphFragmentCryptoAnnotation(ctx *exportBuildContext, finding entities.Finding, asset entities.CryptographicAsset) graphfrag.GraphFragmentCryptoOp {
	matched := buildMatchedOperation(asset)
	op := graphfrag.GraphFragmentCryptoOp{
		FindingID:  asset.FindingID,
		Expression: asset.Match,
		FilePath:   finding.FilePath,
		StartLine:  asset.StartLine,
		EndLine:    asset.EndLine,
	}
	if len(asset.Rules) > 0 {
		op.RuleID = asset.Rules[0].ID
	}
	if matched != nil {
		op.Symbol = matched.Symbol
		if op.Expression == "" {
			op.Expression = matched.Expression
		}
	}
	containingFn := ctx.findContainingFunctionByFinding(finding.FilePath, asset.StartLine)
	if containingFn != nil {
		op.FunctionKey = containingFn.ID.String()
		if matched != nil && matched.Kind == matchedOperationCall {
			if cryptoCall := findCryptoCall(ctx, ctx.graph, containingFn, asset, asset.StartLine, asset.EndLine); cryptoCall != nil {
				op.Symbol = cryptoCall.FunctionName
			}
		}
	}
	return op
}
