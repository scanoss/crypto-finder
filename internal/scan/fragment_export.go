package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
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

// ExportGraphFragment writes the dependency scan result's call graph as a
// graph-fragment export in the requested format.
func ExportGraphFragment(path, format string, result *engine.DepScanResult) error {
	if result == nil {
		return fmt.Errorf("scan: cannot export graph fragment: dep scan result is nil")
	}
	if result.CallGraph == nil {
		return fmt.Errorf("scan: cannot export graph fragment: result.CallGraph is nil")
	}
	if format != "json" {
		return fmt.Errorf("scan: unsupported graph fragment format %q (supported: json)", format)
	}

	payload := BuildGraphFragmentExport(result)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("scan: failed to serialize graph fragment export: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("scan: failed to write graph fragment to %s: %w", path, err)
	}
	return nil
}

// BuildGraphFragmentExport projects a dependency scan result onto the public
// graph-fragment export schema.
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
	for _, calleeKey := range sortedKeys(graph.Callers) {
		addResolvedFragmentEdges(graph, calleeKey, internalByKey, externalByKey)
	}

	return sortedFragmentEdges(internalByKey), sortedFragmentExternalCalls(externalByKey)
}

func addResolvedFragmentEdges(
	graph *callgraph.CallGraph,
	calleeKey string,
	internalByKey map[string]graphfrag.GraphFragmentEdge,
	externalByKey map[string]graphfrag.GraphFragmentExternal,
) {
	callers := append([]string(nil), graph.Callers[calleeKey]...)
	sort.Strings(callers)
	for _, callerKey := range callers {
		callerDecl := graph.Functions[callerKey]
		if callerDecl == nil {
			continue
		}
		resolutions := resolveFragmentEdges(graph, callerKey, calleeKey)
		for i := range resolutions {
			res := resolutions[i]
			edgeKey := callgraph.EdgeResolutionKey(callerKey, calleeKey, res.EdgeResolution)
			line := fragmentEdgeLine(callerDecl, calleeKey, res)
			if _, ok := graph.Functions[calleeKey]; ok {
				internalByKey[edgeKey] = buildFragmentInternalEdge(callerKey, calleeKey, line, res)
				continue
			}
			externalByKey[edgeKey] = buildFragmentExternalCall(callerDecl, callerKey, calleeKey, line, res)
		}
	}
}

func buildFragmentInternalEdge(callerKey, calleeKey string, line int, res fragmentEdgeResolution) graphfrag.GraphFragmentEdge {
	return graphfrag.GraphFragmentEdge{
		CallerKey:    callerKey,
		CalleeKey:    calleeKey,
		Line:         line,
		Resolution:   res.Resolution,
		DeclaredType: res.DeclaredType,
		MethodName:   res.MethodName,
		Arity:        res.Arity,
	}
}

func buildFragmentExternalCall(
	callerDecl *callgraph.FunctionDecl,
	callerKey string,
	calleeKey string,
	line int,
	res fragmentEdgeResolution,
) graphfrag.GraphFragmentExternal {
	external := graphfrag.GraphFragmentExternal{
		CallerKey:    callerKey,
		TargetKey:    calleeKey,
		Line:         line,
		Resolution:   res.Resolution,
		DeclaredType: res.DeclaredType,
		MethodName:   res.MethodName,
		Arity:        res.Arity,
	}
	external.TargetFunctionName = fragmentTargetFunctionName(callerDecl, calleeKey, &external)
	return external
}

func fragmentTargetFunctionName(
	callerDecl *callgraph.FunctionDecl,
	calleeKey string,
	external *graphfrag.GraphFragmentExternal,
) string {
	targetName := ""
	if calleeID, err := callgraph.ParseFunctionID(calleeKey); err == nil {
		targetName = fullFunctionName(calleeID)
	}
	if call := findCallForCallee(callerDecl, calleeKey); call != nil {
		external.Raw = call.Raw
		if targetName == "" {
			targetName = fullFunctionName(call.Callee)
		}
	}
	return targetName
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedFragmentEdges(values map[string]graphfrag.GraphFragmentEdge) []graphfrag.GraphFragmentEdge {
	keys := sortedKeys(values)
	out := make([]graphfrag.GraphFragmentEdge, 0, len(keys))
	for _, key := range keys {
		out = append(out, values[key])
	}
	return out
}

func sortedFragmentExternalCalls(values map[string]graphfrag.GraphFragmentExternal) []graphfrag.GraphFragmentExternal {
	keys := sortedKeys(values)
	out := make([]graphfrag.GraphFragmentExternal, 0, len(keys))
	for _, key := range keys {
		out = append(out, values[key])
	}
	return out
}

type fragmentEdgeResolution struct {
	callgraph.EdgeResolution
	Resolution string
}

// resolveFragmentEdges returns the resolution metadata for a caller->callee edge.
// An edge with no recorded resolution is an exact, directly-resolved source
// call (e.g. a typed re-resolution from the bytecode/type resolver), so it
// defaults to exact rather than the fail-closed "unknown" — the producer is the
// authority on resolution quality.
func resolveFragmentEdges(graph *callgraph.CallGraph, callerKey, calleeKey string) []fragmentEdgeResolution {
	if graph != nil {
		prefix := callgraph.EdgeResolutionKeyPrefix(callerKey, calleeKey)
		keys := make([]string, 0)
		for key := range graph.EdgeResolutions {
			if strings.HasPrefix(key, prefix) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		if len(keys) > 0 {
			out := make([]fragmentEdgeResolution, 0, len(keys))
			for _, key := range keys {
				out = append(out, newFragmentEdgeResolution(graph.EdgeResolutions[key]))
			}
			return out
		}
	}
	return []fragmentEdgeResolution{newFragmentEdgeResolution(callgraph.EdgeResolution{Kind: callgraph.EdgeKindExact})}
}

func newFragmentEdgeResolution(res callgraph.EdgeResolution) fragmentEdgeResolution {
	return fragmentEdgeResolution{
		EdgeResolution: res,
		Resolution:     string(res.Kind),
	}
}

func fragmentEdgeLine(callerDecl *callgraph.FunctionDecl, calleeKey string, res fragmentEdgeResolution) int {
	if res.CallSite != 0 {
		return res.CallSite
	}
	return findFragmentCallLine(callerDecl, calleeKey)
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
