package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/callgraph/contracts"
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

	if err := writeGraphFragmentJSONFile(path, result); err != nil {
		return fmt.Errorf("scan: failed to write graph fragment to %s: %w", path, err)
	}
	return nil
}

func writeGraphFragmentJSONFile(path string, result *engine.DepScanResult) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	bw := bufio.NewWriterSize(file, 1<<20)
	writer := graphFragmentJSONWriter{w: bw}
	err = writer.writeResult(result)
	if flushErr := bw.Flush(); err == nil {
		err = flushErr
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

type graphFragmentJSONWriter struct {
	w         *bufio.Writer
	needComma bool
}

func (w *graphFragmentJSONWriter) writeResult(result *engine.DepScanResult) error {
	if _, err := w.w.WriteString("{\n"); err != nil {
		return err
	}
	if err := w.writeField("schema_version", graphfrag.SchemaVersion); err != nil {
		return err
	}

	ctx := newExportBuildContext(result)
	meta := buildGraphFragmentScanMetadata(result)
	var err error
	var functionIndex map[string]int
	functionIndex, meta.FunctionCount, err = w.writeFunctions(ctx)
	if err != nil {
		return err
	}
	meta.InternalEdges, meta.ExternalCalls, err = w.writeEdges(ctx, functionIndex)
	if err != nil {
		return err
	}

	cryptoAnnotations := buildGraphFragmentCryptoAnnotations(ctx, result)
	meta.CryptoOps = len(cryptoAnnotations)
	if err := writeGraphFragmentArrayField(w, "crypto_annotations", cryptoAnnotations, true); err != nil {
		return err
	}
	supportingCalls := buildGraphFragmentSupportingCalls(ctx, result)
	meta.SupportingCalls = len(supportingCalls)
	if err := writeGraphFragmentArrayField(w, "supporting_calls", supportingCalls, true); err != nil {
		return err
	}
	entryPoints := buildGraphFragmentCryptoEntryPoints(ctx, result)
	meta.CryptoEntryPoints = len(entryPoints)
	if err := writeGraphFragmentArrayField(w, "crypto_entry_points", entryPoints, true); err != nil {
		return err
	}
	if err := w.writeField("scan_metadata", meta); err != nil {
		return err
	}
	_, err = w.w.WriteString("\n}\n")
	return err
}

func (w *graphFragmentJSONWriter) writeFunctions(ctx *exportBuildContext) (map[string]int, int, error) {
	if err := w.startArrayField("functions"); err != nil {
		return nil, 0, err
	}
	functionIndex := make(map[string]int, len(ctx.graph.Functions))
	count := 0
	for _, key := range sortedKeys(ctx.graph.Functions) {
		decl := ctx.graph.Functions[key]
		if err := w.writeArrayElement(count, buildGraphFragmentFunction(ctx, decl.ID, decl)); err != nil {
			return nil, 0, err
		}
		functionIndex[key] = count
		count++
	}
	return functionIndex, count, w.endArrayField(count)
}

func (w *graphFragmentJSONWriter) writeEdges(ctx *exportBuildContext, functionIndex map[string]int) (int, int, error) {
	stringInterner := newFragmentStringInterner()
	if err := w.startArrayField("internal_edges_compact"); err != nil {
		return 0, 0, err
	}

	internalCount := 0
	var pending *graphfrag.GraphFragmentEdge
	var externalCalls []graphfrag.GraphFragmentExternal
	flush := func() error {
		if pending == nil {
			return nil
		}
		compact := compactGraphFragmentEdge(*pending, functionIndex, stringInterner)
		if err := w.writeArrayElement(internalCount, compact); err != nil {
			return err
		}
		internalCount++
		return nil
	}

	for _, calleeKey := range sortedKeys(ctx.graph.Callers) {
		calls, err := buildResolvedFragmentEdges(ctx, calleeKey, func(edge graphfrag.GraphFragmentEdge) error {
			if pending != nil && fragmentEdgeSameKey(*pending, edge) {
				*pending = edge
				return nil
			}
			if err := flush(); err != nil {
				return err
			}
			pending = &edge
			return nil
		})
		if err != nil {
			return 0, 0, err
		}
		externalCalls = append(externalCalls, calls...)
	}
	if err := flush(); err != nil {
		return 0, 0, err
	}
	if err := w.endArrayField(internalCount); err != nil {
		return 0, 0, err
	}
	if err := writeGraphFragmentArrayField(w, "internal_edge_strings", stringInterner.values, true); err != nil {
		return 0, 0, err
	}

	externalCalls = sortedFragmentExternalCalls(externalCalls)
	if err := writeGraphFragmentArrayField(w, "external_calls", externalCalls, true); err != nil {
		return 0, 0, err
	}
	return internalCount, len(externalCalls), nil
}

func (w *graphFragmentJSONWriter) startArrayField(name string) error {
	if err := w.startField(name); err != nil {
		return err
	}
	_, err := w.w.WriteString("[")
	return err
}

func (w *graphFragmentJSONWriter) writeArrayElement(index int, value any) error {
	if index == 0 {
		if _, err := w.w.WriteString("\n    "); err != nil {
			return err
		}
	} else if _, err := w.w.WriteString(",\n    "); err != nil {
		return err
	}
	return writeJSONValue(w.w, value)
}

func (w *graphFragmentJSONWriter) endArrayField(count int) error {
	if count == 0 {
		_, err := w.w.WriteString("]")
		return err
	}
	_, err := w.w.WriteString("\n  ]")
	return err
}

type fragmentStringInterner struct {
	values  []string
	indexes map[string]int
}

func newFragmentStringInterner() *fragmentStringInterner {
	return &fragmentStringInterner{
		values:  []string{""},
		indexes: map[string]int{"": 0},
	}
}

func (i *fragmentStringInterner) index(value string) int {
	if idx, ok := i.indexes[value]; ok {
		return idx
	}
	idx := len(i.values)
	i.values = append(i.values, value)
	i.indexes[value] = idx
	return idx
}

func compactGraphFragmentEdge(edge graphfrag.GraphFragmentEdge, functionIndex map[string]int, stringInterner *fragmentStringInterner) graphfrag.GraphFragmentCompactEdge {
	return graphfrag.GraphFragmentCompactEdge{
		Caller:               functionIndex[edge.CallerKey],
		Callee:               functionIndex[edge.CalleeKey],
		Line:                 edge.Line,
		Resolution:           stringInterner.index(edge.Resolution),
		DeclaredType:         stringInterner.index(edge.DeclaredType),
		MethodName:           stringInterner.index(edge.MethodName),
		Arity:                edge.Arity,
		ReceiverVar:          stringInterner.index(edge.ReceiverVar),
		AssignedVar:          stringInterner.index(edge.AssignedVar),
		ChainID:              stringInterner.index(edge.ChainID),
		StartCol:             edge.StartCol,
		EndCol:               edge.EndCol,
		ResolvedReceiverType: stringInterner.index(edge.ResolvedReceiverType),
		EntryCall:            edge.EntryCall,
	}
}

func (w *graphFragmentJSONWriter) writeField(name string, value any) error {
	if err := w.startField(name); err != nil {
		return err
	}
	return writeJSONValue(w.w, value)
}

func writeGraphFragmentArrayField[T any](w *graphFragmentJSONWriter, name string, values []T, omitEmpty bool) error {
	if omitEmpty && len(values) == 0 {
		return nil
	}
	if err := w.startArrayField(name); err != nil {
		return err
	}
	for i := range values {
		if err := w.writeArrayElement(i, values[i]); err != nil {
			return err
		}
	}
	return w.endArrayField(len(values))
}

func (w *graphFragmentJSONWriter) startField(name string) error {
	if w.needComma {
		if _, err := w.w.WriteString(",\n"); err != nil {
			return err
		}
	}
	w.needComma = true
	_, err := fmt.Fprintf(w.w, "  %q: ", name)
	return err
}

func writeJSONValue(dst io.Writer, value any) error {
	trimmer := trailingNewlineTrimmer{dst: dst}
	enc := json.NewEncoder(&trimmer)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return err
	}
	return trimmer.Flush()
}

type trailingNewlineTrimmer struct {
	dst     io.Writer
	held    byte
	hasHeld bool
}

func (w *trailingNewlineTrimmer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if w.hasHeld {
		if _, err := w.dst.Write([]byte{w.held}); err != nil {
			return 0, err
		}
		w.hasHeld = false
	}
	if len(p) > 1 {
		if _, err := w.dst.Write(p[:len(p)-1]); err != nil {
			return 0, err
		}
	}
	w.held = p[len(p)-1]
	w.hasHeld = true
	return len(p), nil
}

func (w *trailingNewlineTrimmer) Flush() error {
	if !w.hasHeld {
		return nil
	}
	if w.held == '\n' {
		w.hasHeld = false
		return nil
	}
	_, err := w.dst.Write([]byte{w.held})
	w.hasHeld = false
	return err
}

// BuildGraphFragmentExport projects a dependency scan result onto the public
// graph-fragment export schema.
func BuildGraphFragmentExport(result *engine.DepScanResult) graphfrag.GraphFragmentExport {
	out := graphfrag.GraphFragmentExport{
		SchemaVersion: graphfrag.SchemaVersion,
		ScanMetadata:  buildGraphFragmentScanMetadata(result),
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
		out.Functions = append(out.Functions, buildGraphFragmentFunction(ctx, decl.ID, decl))
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

func buildGraphFragmentScanMetadata(result *engine.DepScanResult) graphfrag.GraphFragmentScanMetadata {
	meta := graphfrag.GraphFragmentScanMetadata{
		Ecosystem:        result.Ecosystem,
		RootModule:       result.RootModule,
		GraphAlgoVersion: graphfrag.GraphAlgoVersion,
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	if result.Report != nil {
		meta.ToolName = result.Report.Tool.Name
		meta.ToolVersion = result.Report.Tool.Version
		meta.RulesVersion = result.Report.Rules.Version
	}
	return meta
}

func buildGraphFragmentResolvedEdges(ctx *exportBuildContext) ([]graphfrag.GraphFragmentEdge, []graphfrag.GraphFragmentExternal) {
	if ctx == nil || ctx.graph == nil {
		return nil, nil
	}

	internalEdges := make([]graphfrag.GraphFragmentEdge, 0, len(ctx.graph.EdgeResolutions))
	var externalCalls []graphfrag.GraphFragmentExternal
	for _, calleeKey := range sortedKeys(ctx.graph.Callers) {
		internalEdges, externalCalls = addResolvedFragmentEdges(ctx, calleeKey, internalEdges, externalCalls)
	}

	return sortedFragmentEdges(internalEdges), sortedFragmentExternalCalls(externalCalls)
}

func addResolvedFragmentEdges(
	ctx *exportBuildContext,
	calleeKey string,
	internalEdges []graphfrag.GraphFragmentEdge,
	externalCalls []graphfrag.GraphFragmentExternal,
) ([]graphfrag.GraphFragmentEdge, []graphfrag.GraphFragmentExternal) {
	calls, err := buildResolvedFragmentEdges(ctx, calleeKey, func(edge graphfrag.GraphFragmentEdge) error {
		internalEdges = append(internalEdges, edge)
		return nil
	})
	if err != nil {
		return internalEdges, externalCalls
	}
	externalCalls = append(externalCalls, calls...)
	return internalEdges, externalCalls
}

func buildResolvedFragmentEdges(
	ctx *exportBuildContext,
	calleeKey string,
	emitInternal func(graphfrag.GraphFragmentEdge) error,
) ([]graphfrag.GraphFragmentExternal, error) {
	graph := ctx.graph
	callers := append([]string(nil), graph.Callers[calleeKey]...)
	sort.Strings(callers)
	var externalCalls []graphfrag.GraphFragmentExternal
	for _, callerKey := range callers {
		callerDecl := graph.Functions[callerKey]
		if callerDecl == nil {
			continue
		}
		resolutions := resolveFragmentEdges(ctx, callerKey, calleeKey)
		for i := range resolutions {
			external, err := buildResolvedFragmentEdge(ctx, callerKey, callerDecl, calleeKey, resolutions[i], emitInternal)
			if err != nil {
				return nil, err
			}
			if external != nil {
				externalCalls = append(externalCalls, *external)
			}
		}
	}
	return externalCalls, nil
}

func buildResolvedFragmentEdge(
	ctx *exportBuildContext,
	callerKey string,
	callerDecl *callgraph.FunctionDecl,
	calleeKey string,
	res fragmentEdgeResolution,
	emitInternal func(graphfrag.GraphFragmentEdge) error,
) (*graphfrag.GraphFragmentExternal, error) {
	line := fragmentEdgeLine(ctx, callerKey, callerDecl, calleeKey, res)
	call := findCallForCalleeAtLine(ctx, callerKey, callerDecl, calleeKey, line)
	if call == nil {
		call = findDispatchCallAtLine(callerDecl, line, res.StartCol, res.EndCol, res.MethodName, res.Arity)
	}
	if _, ok := ctx.graph.Functions[calleeKey]; ok {
		edge := buildFragmentInternalEdge(ctx, callerDecl, call, callerKey, calleeKey, line, res)
		if edge.ChainID == "" {
			edge.ChainID = ctx.chainIDForLine(callerKey, callerDecl, line)
		}
		if err := emitInternal(edge); err != nil {
			return nil, fmt.Errorf("scan: emit fragment edge: %w", err)
		}
		return nil, nil
	}
	external := buildFragmentExternalCall(ctx, callerDecl, call, callerKey, calleeKey, line, res)
	if external.ChainID == "" {
		external.ChainID = ctx.chainIDForLine(callerKey, callerDecl, line)
	}
	return &external, nil
}

// findDispatchCallAtLine recovers the source invocation for a dispatch-expanded
// target whose concrete declaring type differs from the interface call recorded
// by the parser. It fails closed when the line contains more than one matching
// method+arity call.
func findDispatchCallAtLine(fn *callgraph.FunctionDecl, line, startCol, endCol int, method string, arity int) *callgraph.FunctionCall {
	if fn == nil || line <= 0 || method == "" {
		return nil
	}
	var match *callgraph.FunctionCall
	for i := range fn.Calls {
		call := &fn.Calls[i]
		if call.Line != line || (startCol > 0 && (call.StartCol != startCol || call.EndCol != endCol)) || callgraph.BaseFunctionName(call.Callee.Name) != method || len(call.Arguments) != arity {
			continue
		}
		if match != nil {
			return nil
		}
		match = call
	}
	return match
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
		CallerKey:            callerKey,
		CalleeKey:            calleeKey,
		Line:                 line,
		Resolution:           res.Resolution,
		DeclaredType:         res.DeclaredType,
		MethodName:           res.MethodName,
		Arity:                res.Arity,
		EntryCall:            buildFragmentCallSiteEntryCall(ctx, call),
		ResolvedReceiverType: res.ResolvedReceiverType,
		StartCol:             res.StartCol,
		EndCol:               res.EndCol,
	}
	if call != nil {
		edge.ReceiverVar = call.ReceiverVar
		edge.AssignedVar = call.AssignedVar
		edge.ChainID = call.ChainID
		if call.StartCol > 0 && call.EndCol > call.StartCol {
			edge.StartCol = call.StartCol
			edge.EndCol = call.EndCol
		}
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
		CallerKey:            callerKey,
		TargetKey:            calleeKey,
		Line:                 line,
		Resolution:           res.Resolution,
		DeclaredType:         res.DeclaredType,
		MethodName:           res.MethodName,
		Arity:                res.Arity,
		EntryCall:            buildFragmentCallSiteEntryCall(ctx, call),
		ResolvedReceiverType: res.ResolvedReceiverType,
		StartCol:             res.StartCol,
		EndCol:               res.EndCol,
	}
	external.TargetFunctionName = fragmentTargetFunctionName(ctx, callerKey, callerDecl, calleeKey, &external)
	if call != nil {
		external.Raw = call.Raw
		external.ReceiverVar = call.ReceiverVar
		external.AssignedVar = call.AssignedVar
		external.ChainID = call.ChainID
		if call.StartCol > 0 && call.EndCol > call.StartCol {
			external.StartCol = call.StartCol
			external.EndCol = call.EndCol
		}
	}
	return external
}

func fragmentTargetFunctionName(
	ctx *exportBuildContext,
	callerKey string,
	callerDecl *callgraph.FunctionDecl,
	calleeKey string,
	external *graphfrag.GraphFragmentExternal,
) string {
	targetName := ""
	if calleeID, err := callgraph.ParseFunctionID(calleeKey); err == nil {
		targetName = fullFunctionName(calleeID)
	}
	if call := findCallForCalleeAtLine(ctx, callerKey, callerDecl, calleeKey, external.Line); call != nil {
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

func sortedFragmentEdges(values []graphfrag.GraphFragmentEdge) []graphfrag.GraphFragmentEdge {
	if len(values) == 0 {
		return nil
	}
	sort.SliceStable(values, func(i, j int) bool {
		return fragmentEdgeLess(values[i], values[j])
	})
	out := values[:0]
	for i := range values {
		if i+1 < len(values) && fragmentEdgeSameKey(values[i], values[i+1]) {
			continue
		}
		out = append(out, values[i])
	}
	return out
}

func sortedFragmentExternalCalls(values []graphfrag.GraphFragmentExternal) []graphfrag.GraphFragmentExternal {
	if len(values) == 0 {
		return nil
	}
	sort.SliceStable(values, func(i, j int) bool {
		return fragmentExternalLess(values[i], values[j])
	})
	out := values[:0]
	for i := range values {
		if i+1 < len(values) && fragmentExternalSameKey(values[i], values[i+1]) {
			continue
		}
		out = append(out, values[i])
	}
	return out
}

func fragmentEdgeLess(a, b graphfrag.GraphFragmentEdge) bool {
	if a.CallerKey != b.CallerKey {
		return a.CallerKey < b.CallerKey
	}
	if a.CalleeKey != b.CalleeKey {
		return a.CalleeKey < b.CalleeKey
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.StartCol != b.StartCol {
		return a.StartCol < b.StartCol
	}
	if a.EndCol != b.EndCol {
		return a.EndCol < b.EndCol
	}
	if a.Resolution != b.Resolution {
		return a.Resolution < b.Resolution
	}
	if a.DeclaredType != b.DeclaredType {
		return a.DeclaredType < b.DeclaredType
	}
	if a.MethodName != b.MethodName {
		return a.MethodName < b.MethodName
	}
	return a.Arity < b.Arity
}

func fragmentEdgeSameKey(a, b graphfrag.GraphFragmentEdge) bool {
	return a.CallerKey == b.CallerKey &&
		a.CalleeKey == b.CalleeKey &&
		a.Line == b.Line &&
		a.StartCol == b.StartCol &&
		a.EndCol == b.EndCol &&
		a.Resolution == b.Resolution &&
		a.DeclaredType == b.DeclaredType &&
		a.MethodName == b.MethodName &&
		a.Arity == b.Arity
}

func fragmentExternalLess(a, b graphfrag.GraphFragmentExternal) bool {
	if a.CallerKey != b.CallerKey {
		return a.CallerKey < b.CallerKey
	}
	if a.TargetKey != b.TargetKey {
		return a.TargetKey < b.TargetKey
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.StartCol != b.StartCol {
		return a.StartCol < b.StartCol
	}
	if a.EndCol != b.EndCol {
		return a.EndCol < b.EndCol
	}
	if a.Resolution != b.Resolution {
		return a.Resolution < b.Resolution
	}
	if a.DeclaredType != b.DeclaredType {
		return a.DeclaredType < b.DeclaredType
	}
	if a.MethodName != b.MethodName {
		return a.MethodName < b.MethodName
	}
	return a.Arity < b.Arity
}

func fragmentExternalSameKey(a, b graphfrag.GraphFragmentExternal) bool {
	return a.CallerKey == b.CallerKey &&
		a.TargetKey == b.TargetKey &&
		a.Line == b.Line &&
		a.StartCol == b.StartCol &&
		a.EndCol == b.EndCol &&
		a.Resolution == b.Resolution &&
		a.DeclaredType == b.DeclaredType &&
		a.MethodName == b.MethodName &&
		a.Arity == b.Arity
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
	for key := range graph.EdgeResolutions {
		res := graph.EdgeResolutions[key]
		callerKey, calleeKey, ok := callgraph.EdgeResolutionEndpoints(key, res)
		if !ok {
			continue
		}
		pairKey := fragmentEdgePairKey(callerKey, calleeKey)
		index[pairKey] = append(index[pairKey], newFragmentEdgeResolution(res))
	}
	// Deterministic per-pair variant order: EdgeResolutions is a map, so
	// insertion order above is random. Downstream emission sorts its final
	// edge lists, but a stable index keeps intermediate behavior (e.g. which
	// variant a line-match picks first) reproducible run to run.
	for pairKey := range index {
		values := index[pairKey]
		sort.Slice(values, func(i, j int) bool { return fragmentEdgeResolutionLess(values[i], values[j]) })
	}
	return index
}

func fragmentEdgeResolutionLess(a, b fragmentEdgeResolution) bool {
	if a.CallSite != b.CallSite {
		return a.CallSite < b.CallSite
	}
	if a.StartCol != b.StartCol {
		return a.StartCol < b.StartCol
	}
	if a.EndCol != b.EndCol {
		return a.EndCol < b.EndCol
	}
	if a.DeclaredType != b.DeclaredType {
		return a.DeclaredType < b.DeclaredType
	}
	if a.MethodName != b.MethodName {
		return a.MethodName < b.MethodName
	}
	if a.Arity != b.Arity {
		return a.Arity < b.Arity
	}
	return a.Kind < b.Kind
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

func fragmentEdgeLine(ctx *exportBuildContext, callerKey string, callerDecl *callgraph.FunctionDecl, calleeKey string, res fragmentEdgeResolution) int {
	if res.CallSite != 0 {
		return res.CallSite
	}
	return findFragmentCallLine(ctx, callerKey, callerDecl, calleeKey)
}

func findFragmentCallLine(ctx *exportBuildContext, callerKey string, callerDecl *callgraph.FunctionDecl, calleeKey string) int {
	if callerDecl == nil {
		return 0
	}
	if call := findCallForCallee(ctx, callerKey, callerDecl, calleeKey); call != nil {
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

func (ctx *exportBuildContext) chainIDForLine(callerKey string, fn *callgraph.FunctionDecl, line int) string {
	if ctx == nil {
		return chainIDForLine(fn, line)
	}
	if ctx.chainIDsByCallerLine == nil {
		ctx.chainIDsByCallerLine = make(map[string]map[int]string)
	}
	lineIndex, ok := ctx.chainIDsByCallerLine[callerKey]
	if !ok {
		lineIndex = make(map[int]string)
		if fn != nil {
			for i := range fn.Calls {
				call := &fn.Calls[i]
				if call.Line > 0 && call.ChainID != "" {
					lineIndex[call.Line] = call.ChainID
				}
			}
		}
		ctx.chainIDsByCallerLine[callerKey] = lineIndex
	}
	return lineIndex[line]
}

// findCallForCalleeAtLine finds callerKey's FunctionCall matching calleeKey,
// preferring the specific call at line when more than one call in the body
// matches (overload/dispatch fan-out can put several resolved edges on the
// same caller function). ctx may be nil (falls back to an unindexed scan of
// callerDecl.Calls, used by tests that construct a FunctionDecl directly
// without a full exportBuildContext).
func findCallForCalleeAtLine(ctx *exportBuildContext, callerKey string, callerDecl *callgraph.FunctionDecl, calleeKey string, line int) *callgraph.FunctionCall {
	candidates := matchingCallsForCallee(ctx, callerKey, callerDecl, calleeKey)
	var fallback *callgraph.FunctionCall
	for _, call := range candidates {
		if line > 0 && call.Line == line {
			return call
		}
		if fallback == nil {
			fallback = call
		}
	}
	return fallback
}

func findCallForCallee(ctx *exportBuildContext, callerKey string, callerDecl *callgraph.FunctionDecl, calleeKey string) *callgraph.FunctionCall {
	candidates := matchingCallsForCallee(ctx, callerKey, callerDecl, calleeKey)
	if len(candidates) == 0 {
		return nil
	}
	return candidates[0]
}

// matchingCallsForCallee returns every FunctionCall in callerDecl whose
// Callee matches calleeKey under callMatchesCallee's original rule — an
// exact FunctionID.String() match OR the same (Package, Type,
// BaseFunctionName) tuple (an overload/dispatch-expanded alias of the same
// source call site). An exact string match always implies the tuple match
// (String() encodes Package/Type/Name, and BaseFunctionName is a pure
// function of Name), so grouping by the tuple alone is equivalent to the
// original two-branch OR — EXCEPT when calleeKey fails to parse, in which
// case the original code still honored an exact string match; that fallback
// path is preserved separately below since it can't use the tuple index.
// Order matches the original callerDecl.Calls order (stable — same as
// ranging callerDecl.Calls directly and filtering).
//
// When ctx is non-nil, this is backed by callSignatureIndexForCaller's cached
// per-caller index instead of a fresh linear scan: on graphs with heavy
// dispatch fan-out (bcprov's Digest/BlockCipher hierarchies), the same caller
// is looked up once per resolved edge, and a full callerDecl.Calls scan (plus
// a callgraph.ParseFunctionID reparse of calleeKey) on every one of those
// millions of edges was the dominant cost of BuildGraphFragmentExport.
func matchingCallsForCallee(ctx *exportBuildContext, callerKey string, callerDecl *callgraph.FunctionDecl, calleeKey string) []*callgraph.FunctionCall {
	if callerDecl == nil {
		return nil
	}
	sigKey, ok := calleeSignatureKey(ctx, calleeKey)
	if !ok {
		// calleeKey isn't parseable (should not happen for real graph keys,
		// which are always produced by FunctionID.String()); callMatchesCallee
		// still honored an exact string match in this case, so fall back to a
		// direct scan rather than silently returning nothing.
		var matches []*callgraph.FunctionCall
		for i := range callerDecl.Calls {
			call := &callerDecl.Calls[i]
			if call.Callee.String() == calleeKey {
				matches = append(matches, call)
			}
		}
		return matches
	}
	if ctx != nil {
		index := ctx.callSignatureIndexForCaller(callerKey, callerDecl)
		return index[sigKey]
	}

	var matches []*callgraph.FunctionCall
	for i := range callerDecl.Calls {
		call := &callerDecl.Calls[i]
		if callSignatureKey(call.Callee.Package, call.Callee.Type, callgraph.BaseFunctionName(call.Callee.Name)) == sigKey {
			matches = append(matches, call)
		}
	}
	return matches
}

func calleeSignatureKey(ctx *exportBuildContext, calleeKey string) (string, bool) {
	if ctx != nil {
		if ctx.calleeSignatureKeys == nil {
			ctx.calleeSignatureKeys = make(map[string]string)
		}
		if sigKey, ok := ctx.calleeSignatureKeys[calleeKey]; ok {
			return sigKey, sigKey != ""
		}
		calleeID, err := callgraph.ParseFunctionID(calleeKey)
		if err != nil {
			ctx.calleeSignatureKeys[calleeKey] = ""
			return "", false
		}
		sigKey := callSignatureKey(calleeID.Package, calleeID.Type, callgraph.BaseFunctionName(calleeID.Name))
		ctx.calleeSignatureKeys[calleeKey] = sigKey
		return sigKey, true
	}
	calleeID, err := callgraph.ParseFunctionID(calleeKey)
	if err != nil {
		return "", false
	}
	return callSignatureKey(calleeID.Package, calleeID.Type, callgraph.BaseFunctionName(calleeID.Name)), true
}

// callSignatureKey builds the (Package, Type, BaseFunctionName) grouping key
// callSignatureIndexForCaller and matchingCallsForCallee's unindexed fallback
// both use. This is a coarser key than a full FunctionID: it deliberately
// ignores arity/overload decoration, matching callMatchesCallee's fuzzy rule
// (a dispatch-expanded calleeKey targeting a different overload/arity of the
// same base method still resolves back to the ONE source call site).
func callSignatureKey(pkg, typ, baseName string) string {
	return pkg + "\x00" + typ + "\x00" + baseName
}

// callSignatureIndexForCaller returns callerKey's Calls grouped by
// callSignatureKey, building and caching the index on first use. See
// exportBuildContext.callsBySignature's doc comment.
func (ctx *exportBuildContext) callSignatureIndexForCaller(callerKey string, callerDecl *callgraph.FunctionDecl) map[string][]*callgraph.FunctionCall {
	if index, ok := ctx.callsBySignature[callerKey]; ok {
		return index
	}
	if ctx.callsBySignature == nil {
		ctx.callsBySignature = make(map[string]map[string][]*callgraph.FunctionCall)
	}
	index := make(map[string][]*callgraph.FunctionCall, len(callerDecl.Calls))
	for i := range callerDecl.Calls {
		call := &callerDecl.Calls[i]
		key := callSignatureKey(call.Callee.Package, call.Callee.Type, callgraph.BaseFunctionName(call.Callee.Name))
		index[key] = append(index[key], call)
	}
	ctx.callsBySignature[callerKey] = index
	return index
}

// buildGraphFragmentFunction projects one call-graph function onto its
// graph-fragment representation. The function's FilePath is relativized with the
// SAME normalization the live callgraph export applies to chain-node paths
// (normalizeExportPath -> relativeToRoot(projectRoot, ...)). This is load-bearing:
// the served reachability API surfaces a fragment function's FilePath verbatim as
// the chain-frame file_path, so storing the raw parser path (the ephemeral
// absolute scan/workspace path) would leak that path to downstream consumers and
// diverge from the live export. The synthetic <clinit> function flows through here
// too, so its path is relativized as well.
func buildGraphFragmentFunction(ctx *exportBuildContext, id callgraph.FunctionID, decl *callgraph.FunctionDecl) graphfrag.GraphFragmentFunction {
	meta := buildExportFunctionMetadata(ctx.graph, id, decl)
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
		fn.FilePath = normalizeExportPath(ctx, decl.FilePath).FilePath
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
			op := buildGraphFragmentCryptoAnnotation(ctx, finding, asset)
			// Capture the per-finding supporting->finding FK while object identity
			// still exists (graph-fragment 1.5). The top-level supporting_calls are
			// deduped across findings and lose it; the annotate path re-derives the
			// identical set from the cached edges.
			op.SupportingCallIDs = supportingCallIDsOf(deriveSupportingCallsForFinding(ctx, finding, asset))
			out = append(out, op)
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
	return flattenGraphFragmentEntryPoints(ctx.kb, entries)
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

func flattenGraphFragmentEntryPoints(kb *contracts.KnowledgeBase, entries map[string]*graphFragmentEntryPointData) []graphfrag.GraphFragmentCryptoEntryPoint {
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
			// issue-103 WU3: parameter_roles carried on the fragment so the
			// stitch/served path can pick them up via the by-function_key
			// carry-through (see pkg/graphfrag/ingest.go, stitch.go — the
			// merge/index side of that carry-through is a follow-up).
			ParameterRoles: toGraphFragmentParameterRoles(parameterRolesFromKB(kb, entry.functionName, len(entry.parameterTypes))),
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
		// issue-103 WU3: carries the supporting-call declaration's KB-derived
		// parameter_roles (populated in buildDerivedSupportingCall) into the
		// fragment, so it survives to the served path unchanged.
		ParameterRoles: toGraphFragmentParameterRoles(called.ParameterRoles),
	}
	for _, p := range called.Parameters {
		cc.Parameters = append(cc.Parameters, convertCallGraphParameterToFragment(p))
	}
	return cc
}

// toGraphFragmentParameterRoles converts the internal callGraphParameterRole
// shape to its graph-fragment mirror (issue-103 WU3).
func toGraphFragmentParameterRoles(src []callGraphParameterRole) []graphfrag.GraphFragmentParameterRole {
	if len(src) == 0 {
		return nil
	}
	out := make([]graphfrag.GraphFragmentParameterRole, len(src))
	for i, p := range src {
		out[i] = graphfrag.GraphFragmentParameterRole{Index: p.Index, Name: p.Name, Role: p.Role}
		if p.Contributes != nil {
			out[i].Contributes = &graphfrag.GraphFragmentContribution{
				Property:   p.Contributes.Property,
				Derivation: p.Contributes.Derivation,
			}
		}
	}
	return out
}
