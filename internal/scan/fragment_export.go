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
// crypto-finder's contract with downstream consumers. This file only BUILDS
// that schema from a callgraph.

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
	out.SupportingCalls = buildGraphFragmentSupportingCalls(ctx, result)
	out.CryptoEntryPoints = buildGraphFragmentCryptoEntryPoints(ctx, result)
	out.ScanMetadata.FunctionCount = len(out.Functions)
	out.ScanMetadata.InternalEdges = len(out.InternalEdges)
	out.ScanMetadata.ExternalCalls = len(out.ExternalCalls)
	out.ScanMetadata.CryptoOps = len(out.CryptoAnnotations)
	out.ScanMetadata.SupportingCalls = len(out.SupportingCalls)
	out.ScanMetadata.CryptoEntryPoints = len(out.CryptoEntryPoints)
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
		resolutions := resolveFragmentEdges(ctx, callerKey, calleeKey)
		for i := range resolutions {
			res := resolutions[i]
			edgeKey := callgraph.EdgeResolutionKey(callerKey, calleeKey, res.EdgeResolution)
			line := fragmentEdgeLine(callerDecl, calleeKey, res)
			call := findCallForCalleeAtLine(callerDecl, calleeKey, line)
			if _, ok := graph.Functions[calleeKey]; ok {
				edge := buildFragmentInternalEdge(ctx, callerDecl, call, callerKey, calleeKey, line, res)
				if edge.ChainID == "" {
					edge.ChainID = chainIDForLine(callerDecl, line)
				}
				internalByKey[edgeKey] = edge
				continue
			}
			external := buildFragmentExternalCall(ctx, callerDecl, call, callerKey, calleeKey, line, res)
			if external.ChainID == "" {
				external.ChainID = chainIDForLine(callerDecl, line)
			}
			externalByKey[edgeKey] = external
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
	edge := graphfrag.GraphFragmentEdge{
		CallerKey:    callerKey,
		CalleeKey:    calleeKey,
		Line:         line,
		Resolution:   res.Resolution,
		DeclaredType: res.DeclaredType,
		MethodName:   res.MethodName,
		Arity:        res.Arity,
		EntryCall:    buildFragmentCallSiteEntryCall(ctx, call),
	}
	if call != nil {
		edge.ReceiverVar = call.ReceiverVar
		edge.AssignedVar = call.AssignedVar
		edge.ChainID = call.ChainID
	}
	return edge
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
		external.ReceiverVar = call.ReceiverVar
		external.AssignedVar = call.AssignedVar
		external.ChainID = call.ChainID
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
func resolveFragmentEdges(ctx *exportBuildContext, callerKey, calleeKey string) []fragmentEdgeResolution {
	if ctx != nil {
		if out := ctx.fragmentEdgeResolutions[fragmentEdgePairKey(callerKey, calleeKey)]; len(out) > 0 {
			return out
		}
	}
	return []fragmentEdgeResolution{newFragmentEdgeResolution(callgraph.EdgeResolution{Kind: callgraph.EdgeKindExact})}
}

func indexFragmentEdgeResolutions(graph *callgraph.CallGraph) map[string][]fragmentEdgeResolution {
	if graph == nil || len(graph.EdgeResolutions) == 0 {
		return nil
	}
	index := make(map[string][]fragmentEdgeResolution)
	keys := sortedKeys(graph.EdgeResolutions)
	for _, key := range keys {
		parts := strings.SplitN(key, "\x00", 3)
		if len(parts) < 3 {
			continue
		}
		pairKey := fragmentEdgePairKey(parts[0], parts[1])
		index[pairKey] = append(index[pairKey], newFragmentEdgeResolution(graph.EdgeResolutions[key]))
	}
	return index
}

func fragmentEdgePairKey(callerKey, calleeKey string) string {
	return callerKey + "\x00" + calleeKey
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

// chainIDForLine recovers the fluent-chain id for an edge whose exact callee
// lookup failed. The links of a fluent chain (e.g. Password.hash(p)
// .addRandomSalt().withBcrypt()) all share the same line AND the same ChainID,
// but the intermediate links are often left unresolved in a standalone scan, so
// the resolved edge key diverges from the underlying FunctionCall.Callee and the
// key-based lookup misses. Recovering by line is safe precisely because every
// chained call on that line carries the SAME ChainID — picking any of them
// yields the correct group id. Returns "" when no chained call sits on the line.
func chainIDForLine(fn *callgraph.FunctionDecl, line int) string {
	if fn == nil || line <= 0 {
		return ""
	}
	for i := range fn.Calls {
		if fn.Calls[i].Line == line && fn.Calls[i].ChainID != "" {
			return fn.Calls[i].ChainID
		}
	}
	return ""
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
		DisplaySymbol:      meta.DisplaySymbol,
		Aliases:            cloneStringSlice(meta.Aliases),
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
			if isSupportingCryptoAsset(asset) {
				continue
			}
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

func buildGraphFragmentSupportingCalls(ctx *exportBuildContext, result *engine.DepScanResult) []graphfrag.GraphFragmentSupporting {
	if result == nil || result.Report == nil || result.CallGraph == nil {
		return nil
	}
	var out []graphfrag.GraphFragmentSupporting
	seen := make(map[string]bool)
	for _, finding := range result.Report.Findings {
		for i := range finding.CryptographicAssets {
			asset := finding.CryptographicAssets[i]
			if isSupportingCryptoAsset(asset) {
				continue
			}
			supportingCalls := deriveSupportingCallsForFinding(ctx, finding, asset)
			for i := range supportingCalls {
				sc := &supportingCalls[i]
				if seen[sc.SupportingID] {
					continue
				}
				seen[sc.SupportingID] = true
				out = append(out, fragmentSupportingFromInternal(*sc))
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].SupportingID < out[j].SupportingID
	})
	return out
}

// fragmentSupportingFromInternal maps an internal call-graph supporting-call
// entry to its graph-fragment representation.
func fragmentSupportingFromInternal(internal callGraphSupportingCall) graphfrag.GraphFragmentSupporting {
	return graphfrag.GraphFragmentSupporting{
		SupportingID:       internal.SupportingID,
		FunctionKey:        internal.FunctionKey,
		FunctionName:       internal.FunctionName,
		CanonicalSignature: internal.CanonicalSignature,
		DisplaySymbol:      internal.DisplaySymbol,
		Aliases:            cloneStringSlice(internal.Aliases),
		Category:           internal.Category,
		FilePath:           internal.FilePath,
		StartLine:          internal.StartLine,
		EndLine:            internal.EndLine,
		MatchedOperation:   fragmentMatchedOperation(internal.MatchedOperation),
		SupportingCall:     buildGraphFragmentCryptoCall(internal.SupportingCall),
	}
}

func buildGraphFragmentCryptoEntryPoints(ctx *exportBuildContext, result *engine.DepScanResult) []graphfrag.GraphFragmentCryptoEntryPoint {
	if result == nil || result.CallGraph == nil || result.Report == nil {
		return nil
	}
	entries := make(map[string]*graphFragmentEntryPointData)
	for _, finding := range result.Report.Findings {
		for i := range finding.CryptographicAssets {
			asset := finding.CryptographicAssets[i]
			if isSupportingCryptoAsset(asset) {
				continue
			}
			containingFn := ctx.findContainingFunctionByFinding(finding.FilePath, asset.StartLine)
			chains := buildCallChains(ctx, containingFn, nil)
			addGraphFragmentFindingReachability(entries, chains, asset.FindingID)
			supportingCalls := deriveSupportingCallsForFinding(ctx, finding, asset)
			for i := range supportingCalls {
				sc := &supportingCalls[i]
				addGraphFragmentSupportingReachability(entries, chains, sc.SupportingID)
			}
		}
	}
	return flattenGraphFragmentEntryPoints(entries)
}

type graphFragmentEntryPointData struct {
	functionKey        string
	functionName       string
	canonicalSignature string
	displaySymbol      string
	aliases            []string
	returnType         string
	parameterTypes     []string
	visibility         string
	ownerVisibility    string
	findings           map[string]graphfrag.GraphFragmentReachableFinding
	supporting         map[string]graphfrag.GraphFragmentReachableSupportingCall
}

func addGraphFragmentFindingReachability(
	entries map[string]*graphFragmentEntryPointData,
	chains [][]callGraphChainNode,
	findingID string,
) {
	if findingID == "" {
		return
	}
	for _, chain := range chains {
		for pos := range chain {
			entry := ensureGraphFragmentEntryPoint(entries, &chain[pos])
			depth := len(chain) - pos
			existing, ok := entry.findings[findingID]
			if ok && depth >= existing.ChainDepth {
				continue
			}
			entry.findings[findingID] = graphfrag.GraphFragmentReachableFinding{
				FindingID:       findingID,
				ChainDepth:      depth,
				FindingGraphRef: findingID,
			}
		}
	}
}

func addGraphFragmentSupportingReachability(
	entries map[string]*graphFragmentEntryPointData,
	chains [][]callGraphChainNode,
	supportingID string,
) {
	if supportingID == "" {
		return
	}
	for _, chain := range chains {
		for pos := range chain {
			entry := ensureGraphFragmentEntryPoint(entries, &chain[pos])
			depth := len(chain) - pos
			existing, ok := entry.supporting[supportingID]
			if ok && depth >= existing.ChainDepth {
				continue
			}
			entry.supporting[supportingID] = graphfrag.GraphFragmentReachableSupportingCall{
				SupportingID:      supportingID,
				ChainDepth:        depth,
				SupportingCallRef: supportingID,
			}
		}
	}
}

func ensureGraphFragmentEntryPoint(entries map[string]*graphFragmentEntryPointData, node *callGraphChainNode) *graphFragmentEntryPointData {
	key := node.FunctionKey
	if key == "" {
		key = node.CanonicalSignature
	}
	if key == "" {
		key = node.FunctionName
	}
	if entry := entries[key]; entry != nil {
		return entry
	}
	entry := &graphFragmentEntryPointData{
		functionKey:        key,
		functionName:       node.FunctionName,
		canonicalSignature: node.CanonicalSignature,
		displaySymbol:      node.DisplaySymbol,
		aliases:            cloneStringSlice(node.Aliases),
		returnType:         node.ReturnType,
		parameterTypes:     cloneStringSlice(node.ParameterTypes),
		visibility:         node.Visibility,
		ownerVisibility:    node.OwnerVisibility,
		findings:           make(map[string]graphfrag.GraphFragmentReachableFinding),
		supporting:         make(map[string]graphfrag.GraphFragmentReachableSupportingCall),
	}
	entries[key] = entry
	return entry
}

func flattenGraphFragmentEntryPoints(entries map[string]*graphFragmentEntryPointData) []graphfrag.GraphFragmentCryptoEntryPoint {
	if len(entries) == 0 {
		return nil
	}
	keys := sortedKeys(entries)
	out := make([]graphfrag.GraphFragmentCryptoEntryPoint, 0, len(keys))
	for _, key := range keys {
		entry := entries[key]
		out = append(out, graphfrag.GraphFragmentCryptoEntryPoint{
			FunctionKey:              entry.functionKey,
			FunctionName:             entry.functionName,
			CanonicalSignature:       entry.canonicalSignature,
			DisplaySymbol:            entry.displaySymbol,
			Aliases:                  cloneStringSlice(entry.aliases),
			ReturnType:               entry.returnType,
			ParameterTypes:           cloneStringSlice(entry.parameterTypes),
			Visibility:               entry.visibility,
			OwnerVisibility:          entry.ownerVisibility,
			ReachableFindings:        flattenGraphFragmentReachableFindings(entry.findings),
			ReachableSupportingCalls: flattenGraphFragmentReachableSupporting(entry.supporting),
		})
	}
	return out
}

func flattenGraphFragmentReachableFindings(values map[string]graphfrag.GraphFragmentReachableFinding) []graphfrag.GraphFragmentReachableFinding {
	if len(values) == 0 {
		return nil
	}
	keys := sortedKeys(values)
	out := make([]graphfrag.GraphFragmentReachableFinding, 0, len(keys))
	for _, key := range keys {
		out = append(out, values[key])
	}
	return out
}

func flattenGraphFragmentReachableSupporting(values map[string]graphfrag.GraphFragmentReachableSupportingCall) []graphfrag.GraphFragmentReachableSupportingCall {
	if len(values) == 0 {
		return nil
	}
	keys := sortedKeys(values)
	out := make([]graphfrag.GraphFragmentReachableSupportingCall, 0, len(keys))
	for _, key := range keys {
		out = append(out, values[key])
	}
	return out
}

func buildGraphFragmentCryptoAnnotation(ctx *exportBuildContext, finding entities.Finding, asset entities.CryptographicAsset) graphfrag.GraphFragmentCryptoOp {
	matched := buildMatchedOperation(asset)
	op := buildBaseGraphFragmentCryptoAnnotation(finding, asset, matched)

	containingFn := ctx.findContainingFunctionByFinding(finding.FilePath, asset.StartLine)
	if containingFn != nil {
		op.FunctionKey = containingFn.ID.String()
		attachGraphFragmentCryptoCall(ctx, containingFn, matched, asset, &op)
	}
	return op
}

func fragmentMatchedOperation(op *callGraphMatchedOperation) *graphfrag.GraphFragmentMatchedOp {
	if op == nil {
		return nil
	}
	return &graphfrag.GraphFragmentMatchedOp{
		Kind:       op.Kind,
		Symbol:     op.Symbol,
		Expression: op.Expression,
		Line:       op.Line,
	}
}

// buildBaseGraphFragmentCryptoAnnotation builds the detection-derived portion of
// a crypto annotation — every field that depends only on the crypto finding
// (finding_id, rule_id, expression, file_path, line range, oid, source,
// metadata, matched_operation) and NOT on the call graph. It is shared by the
// full-scan exporter (which then adds function_key + crypto_call from the live
// graph) and the annotate-only path (which adds function_key from the imported
// fragment). Keeping this one function authoritative is what guarantees these
// fields are byte-identical across both paths for the same source + rules.
func buildBaseGraphFragmentCryptoAnnotation(
	finding entities.Finding,
	asset entities.CryptographicAsset,
	matched *callGraphMatchedOperation,
) graphfrag.GraphFragmentCryptoOp {
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
		DisplaySymbol:      called.DisplaySymbol,
		Aliases:            cloneStringSlice(called.Aliases),
		Line:               called.Line,
	}
	for _, p := range called.Parameters {
		cc.Parameters = append(cc.Parameters, convertCallGraphParameterToFragment(p))
	}
	return cc
}
