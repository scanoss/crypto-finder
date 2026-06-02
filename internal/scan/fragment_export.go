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
			Ecosystem:        result.Ecosystem,
			RootModule:       result.RootModule,
			GraphAlgoVersion: graphfrag.GraphAlgoVersion,
			ExportedAt:       time.Now().UTC().Format(time.RFC3339),
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

	ctx := newExportBuildContext(result)

	functionKeys := make([]string, 0, len(result.CallGraph.Functions))
	for key := range result.CallGraph.Functions {
		functionKeys = append(functionKeys, key)
	}
	sort.Strings(functionKeys)

	for _, key := range functionKeys {
		decl := result.CallGraph.Functions[key]
		out.Functions = append(out.Functions, buildGraphFragmentFunction(result.CallGraph, decl.ID, decl))
	}
	out.InternalEdges, out.ExternalCalls = buildGraphFragmentResolvedEdges(ctx)

	out.CryptoAnnotations = buildGraphFragmentCryptoAnnotations(ctx, result)
	out.ScanMetadata.FunctionCount = len(out.Functions)
	out.ScanMetadata.InternalEdges = len(out.InternalEdges)
	out.ScanMetadata.ExternalCalls = len(out.ExternalCalls)
	out.ScanMetadata.CryptoOps = len(out.CryptoAnnotations)
	return out
}

func buildGraphFragmentResolvedEdges(ctx *exportBuildContext) ([]graphfrag.GraphFragmentEdge, []graphfrag.GraphFragmentExternal) {
	if ctx == nil || ctx.graph == nil {
		return nil, nil
	}

	internalByKey := map[string]graphfrag.GraphFragmentEdge{}
	externalByKey := map[string]graphfrag.GraphFragmentExternal{}
	for _, calleeKey := range sortedKeys(ctx.graph.Callers) {
		addResolvedFragmentEdges(ctx, calleeKey, internalByKey, externalByKey)
	}

	return sortedFragmentEdges(internalByKey), sortedFragmentExternalCalls(externalByKey)
}

func addResolvedFragmentEdges(
	ctx *exportBuildContext,
	calleeKey string,
	internalByKey map[string]graphfrag.GraphFragmentEdge,
	externalByKey map[string]graphfrag.GraphFragmentExternal,
) {
	graph := ctx.graph
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
			call := findCallForCalleeAtLine(callerDecl, calleeKey, line)
			if _, ok := graph.Functions[calleeKey]; ok {
				internalByKey[edgeKey] = buildFragmentInternalEdge(ctx, callerDecl, call, callerKey, calleeKey, line, res)
				continue
			}
			externalByKey[edgeKey] = buildFragmentExternalCall(ctx, callerDecl, call, callerKey, calleeKey, line, res)
		}
	}
}

// buildFragmentCallSiteEntryCall constructs the GraphFragmentCallSite for a
// call edge using buildCallSiteParameters when a matching FunctionCall is found
// in the callerDecl. Returns nil when the call cannot be located (e.g. the
// callee is reachable only through the caller index, not through a recorded
// FunctionCall in the source).
func buildFragmentCallSiteEntryCall(ctx *exportBuildContext, call *callgraph.FunctionCall) *graphfrag.GraphFragmentCallSite {
	if call == nil {
		return nil
	}
	params := buildCallSiteParameters(ctx, call)
	if len(params) == 0 && call.Line == 0 {
		return nil
	}
	cs := &graphfrag.GraphFragmentCallSite{
		Line: call.Line,
	}
	for _, p := range params {
		cs.Parameters = append(cs.Parameters, convertCallGraphParameterToFragment(p))
	}
	return cs
}

// convertCallGraphParameterToFragment converts an internal callGraphParameter
// (schema-5.x shape) into the equivalent GraphFragmentParameter for the
// graph-fragment-1.2 schema.
func convertCallGraphParameterToFragment(p callGraphParameter) graphfrag.GraphFragmentParameter {
	fp := graphfrag.GraphFragmentParameter{
		ParameterIndex:     p.ParameterIndex,
		Type:               p.Type,
		VariableName:       p.VariableName,
		ArgumentExpression: p.ArgumentExpression,
		ResolvedValue:      p.ResolvedValue,
	}
	for i := range p.SourceNodes {
		fp.SourceNodes = append(fp.SourceNodes, convertExportSourceNodeToFragment(p.SourceNodes[i]))
	}
	return fp
}

// convertExportSourceNodeToFragment converts an internal exportSourceNode into
// the equivalent GraphFragmentSourceNode (recursive).
func convertExportSourceNodeToFragment(n exportSourceNode) graphfrag.GraphFragmentSourceNode {
	fsn := graphfrag.GraphFragmentSourceNode{
		Type:         n.Type,
		Name:         n.Name,
		DeclaredType: n.DeclaredType,
		Value:        n.Value,
		CallTarget:   n.CallTarget,
	}
	if n.ParameterIndex != nil {
		idx := *n.ParameterIndex
		fsn.ParameterIndex = &idx
	}
	if n.Location != nil {
		fsn.Location = &graphfrag.GraphFragmentSourceLoc{
			FilePath: n.Location.FilePath,
			Line:     n.Location.Line,
		}
	}
	for i := range n.SourceNodes {
		fsn.SourceNodes = append(fsn.SourceNodes, convertExportSourceNodeToFragment(n.SourceNodes[i]))
	}
	return fsn
}

func buildFragmentInternalEdge(
	ctx *exportBuildContext,
	_ *callgraph.FunctionDecl,
	call *callgraph.FunctionCall,
	callerKey, calleeKey string,
	line int,
	res fragmentEdgeResolution,
) graphfrag.GraphFragmentEdge {
	return graphfrag.GraphFragmentEdge{
		CallerKey:    callerKey,
		CalleeKey:    calleeKey,
		Line:         line,
		Resolution:   res.Resolution,
		DeclaredType: res.DeclaredType,
		MethodName:   res.MethodName,
		Arity:        res.Arity,
		EntryCall:    buildFragmentCallSiteEntryCall(ctx, call),
	}
}

func buildFragmentExternalCall(
	ctx *exportBuildContext,
	callerDecl *callgraph.FunctionDecl,
	call *callgraph.FunctionCall,
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
		EntryCall:    buildFragmentCallSiteEntryCall(ctx, call),
	}
	external.TargetFunctionName = fragmentTargetFunctionName(callerDecl, calleeKey, &external)
	if call != nil {
		external.Raw = call.Raw
	}
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
	if call := findCallForCalleeAtLine(callerDecl, calleeKey, external.Line); call != nil {
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

func findCallForCalleeAtLine(callerDecl *callgraph.FunctionDecl, calleeKey string, line int) *callgraph.FunctionCall {
	if callerDecl == nil {
		return nil
	}
	var fallback *callgraph.FunctionCall
	for i := range callerDecl.Calls {
		call := &callerDecl.Calls[i]
		if !callMatchesCallee(call, calleeKey) {
			continue
		}
		if line > 0 && call.Line == line {
			return call
		}
		if fallback == nil {
			fallback = call
		}
	}
	return fallback
}

func findCallForCallee(callerDecl *callgraph.FunctionDecl, calleeKey string) *callgraph.FunctionCall {
	if callerDecl == nil {
		return nil
	}
	for i := range callerDecl.Calls {
		call := &callerDecl.Calls[i]
		if callMatchesCallee(call, calleeKey) {
			return call
		}
	}
	return nil
}

func callMatchesCallee(call *callgraph.FunctionCall, calleeKey string) bool {
	if call == nil {
		return false
	}
	calleeID, err := callgraph.ParseFunctionID(calleeKey)
	if call.Callee.String() == calleeKey {
		return true
	}
	return err == nil &&
		call.Callee.Package == calleeID.Package &&
		call.Callee.Type == calleeID.Type &&
		callgraph.BaseFunctionName(call.Callee.Name) == callgraph.BaseFunctionName(calleeID.Name)
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

func buildGraphFragmentCryptoAnnotations(ctx *exportBuildContext, result *engine.DepScanResult) []graphfrag.GraphFragmentCryptoOp {
	if result == nil || result.Report == nil || result.CallGraph == nil {
		return nil
	}
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
		OID:        asset.OID,
		Source:     asset.Source,
	}
	if len(asset.Rules) > 0 {
		op.RuleID = asset.Rules[0].ID
	}
	if matched != nil {
		op.Symbol = matched.Symbol
		if op.Expression == "" {
			op.Expression = matched.Expression
		}
		op.MatchedOperation = &graphfrag.GraphFragmentMatchedOp{
			Kind:       matched.Kind,
			Symbol:     matched.Symbol,
			Expression: matched.Expression,
			Line:       matched.Line,
		}
	}

	// Marshal the asset Metadata map into a raw JSON block for verbatim passthrough.
	if len(asset.Metadata) > 0 {
		if raw, err := json.Marshal(asset.Metadata); err == nil {
			op.Metadata = raw
		}
	}

	containingFn := ctx.findContainingFunctionByFinding(finding.FilePath, asset.StartLine)
	if containingFn != nil {
		op.FunctionKey = containingFn.ID.String()
		attachGraphFragmentCryptoCall(ctx, containingFn, matched, asset, &op)
	}
	return op
}

func attachGraphFragmentCryptoCall(
	ctx *exportBuildContext,
	containingFn *callgraph.FunctionDecl,
	matched *callGraphMatchedOperation,
	asset entities.CryptographicAsset,
	op *graphfrag.GraphFragmentCryptoOp,
) {
	if matched == nil || matched.Kind != matchedOperationCall {
		return
	}
	cryptoCall := findCryptoCall(ctx, ctx.graph, containingFn, asset, asset.StartLine, asset.EndLine)
	if cryptoCall == nil {
		return
	}
	op.Symbol = cryptoCall.FunctionName
	if op.MatchedOperation != nil {
		op.MatchedOperation.Symbol = cryptoCall.FunctionName
	}
	op.CryptoCall = buildGraphFragmentCryptoCall(cryptoCall)
}

// buildGraphFragmentCryptoCall converts an internal callGraphCalledFunction
// (the matched crypto invocation) into a GraphFragmentCryptoCall for the
// graph-fragment-1.2 schema. All parameter data-flow is carried verbatim.
func buildGraphFragmentCryptoCall(called *callGraphCalledFunction) *graphfrag.GraphFragmentCryptoCall {
	if called == nil {
		return nil
	}
	cc := &graphfrag.GraphFragmentCryptoCall{
		FunctionName:       called.FunctionName,
		CanonicalSignature: called.CanonicalSignature,
		ReturnType:         called.ReturnType,
		ParameterTypes:     append([]string(nil), called.ParameterTypes...),
		Line:               called.Line,
	}
	for _, p := range called.Parameters {
		cc.Parameters = append(cc.Parameters, convertCallGraphParameterToFragment(p))
	}
	return cc
}
