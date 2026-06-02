// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package graphfrag — schema-5.x JSON converter.
//
// ToCallgraphExport projects a stitched Result into the schema-5.x JSON shape
// used by crypto-finder's customer-facing callgraph export (and consumed by the
// mining-service render layer). The schema-5.x structs are intentionally
// duplicated here as exported types: they are pkg/graphfrag's public contract
// for the serving path, keeping the package's schema+semantics together with
// their owner.
//
// Relationship to internal/scan/export.go: the unexported callGraphChainNode,
// callGraphEntryCall, etc. types in export.go share the same JSON field names
// and semantics. This file is the promoted copy for the stitched/serving path.
package graphfrag

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// ScanMeta carries the top-level metadata stamped onto a CallgraphExport.
type ScanMeta struct {
	// SchemaVersion is the schema_version value to emit (e.g. "5.3").
	SchemaVersion string
	// RootModule is the Maven/npm/etc. module string for the root component.
	RootModule string
	// Ecosystem identifies the language ecosystem (e.g. "java").
	Ecosystem string
}

// CallgraphExport is the schema-5.x JSON envelope produced by ToCallgraphExport.
// It mirrors the callGraphExportV2 shape in internal/scan/export.go.
type CallgraphExport struct {
	SchemaVersion   string               `json:"schema_version"`
	ScanMetadata    ExportScanMeta       `json:"scan_metadata"`
	FindingGraphs   []ExportFindingGraph `json:"finding_graphs"`
	EntryPointIndex []ExportEntryPoint   `json:"entry_point_index,omitempty"`
}

// ExportScanMeta is the scan_metadata block inside a CallgraphExport.
type ExportScanMeta struct {
	Ecosystem  string `json:"ecosystem,omitempty"`
	RootModule string `json:"root_module,omitempty"`
}

// ExportFindingGraph groups all surviving chains for one crypto finding.
type ExportFindingGraph struct {
	// FindingID is the crypto finding identifier.
	FindingID string `json:"finding_id"`
	// MatchedOperation carries the kind/symbol/expression of the matched crypto op.
	MatchedOperation *ExportMatchedOperation `json:"matched_operation,omitempty"`
	// CallChains is the set of surviving root-to-crypto paths for this finding.
	CallChains [][]ExportChainNode `json:"call_chains,omitempty"`
}

// ExportMatchedOperation mirrors the schema-5.x matched_operation shape.
type ExportMatchedOperation struct {
	Kind       string `json:"kind"`
	Symbol     string `json:"symbol,omitempty"`
	Expression string `json:"expression,omitempty"`
	Line       int    `json:"line,omitempty"`
}

// ExportDependencyInfo mirrors the schema-5.x dependency_info shape. It is
// stamped on non-root frames using the frame's Component module string.
type ExportDependencyInfo struct {
	Module  string `json:"module"`
	Version string `json:"version,omitempty"`
}

// ExportEntryCall is the schema-5.x entry_call shape on a chain node. It
// carries the caller's invocation detail for the edge that led to this frame.
type ExportEntryCall struct {
	// FunctionName is the fully qualified callee function name.
	FunctionName string `json:"function_name,omitempty"`
	// CanonicalSignature is the callee's canonical signature.
	CanonicalSignature string `json:"canonical_signature,omitempty"`
	// ReturnType is the callee's declared return type.
	ReturnType string `json:"return_type,omitempty"`
	// ParameterTypes lists the callee's declared parameter types.
	ParameterTypes []string `json:"parameter_types,omitempty"`
	// Line is the source line in the caller where the call is made.
	Line int `json:"line,omitempty"`
	// Parameters carries the resolved argument data-flow.
	Parameters []ExportParameter `json:"parameters,omitempty"`
}

// ExportCryptoCall is the schema-5.x crypto_call shape on the terminal node.
// It mirrors callGraphCalledFunction in internal/scan/export.go.
type ExportCryptoCall struct {
	// FunctionName is the fully qualified matched crypto function name.
	FunctionName string `json:"function_name"`
	// CanonicalSignature is the canonical signature.
	CanonicalSignature string `json:"canonical_signature,omitempty"`
	// ReturnType is the declared return type.
	ReturnType string `json:"return_type,omitempty"`
	// ParameterTypes lists the declared parameter types.
	ParameterTypes []string `json:"parameter_types,omitempty"`
	// Line is the source line of the matched crypto call.
	Line int `json:"line"`
	// Parameters carries the resolved argument data-flow.
	Parameters []ExportParameter `json:"parameters,omitempty"`
}

// ExportParameter is the schema-5.x callGraphParameter shape.
type ExportParameter struct {
	ParameterIndex     int                `json:"parameter_index"`
	Type               string             `json:"type,omitempty"`
	VariableName       string             `json:"variable_name,omitempty"`
	ArgumentExpression string             `json:"argument_expression,omitempty"`
	ResolvedValue      string             `json:"resolved_value,omitempty"`
	SourceNodes        []ExportSourceNode `json:"source_nodes,omitempty"`
}

// ExportSourceNode is the schema-5.x exportSourceNode shape. The SourceNodes
// field makes it recursive so PARAMETER→CALL_RESULT chains are preserved.
type ExportSourceNode struct {
	Type           string             `json:"type"`
	Name           string             `json:"name,omitempty"`
	DeclaredType   string             `json:"declared_type,omitempty"`
	Value          string             `json:"value,omitempty"`
	ParameterIndex *int               `json:"parameter_index,omitempty"`
	CallTarget     string             `json:"call_target,omitempty"`
	Location       *ExportSourceLoc   `json:"location,omitempty"`
	SourceNodes    []ExportSourceNode `json:"source_nodes,omitempty"`
}

// ExportSourceLoc is a source location reference.
type ExportSourceLoc struct {
	FilePath string `json:"file_path,omitempty"`
	Line     int    `json:"line,omitempty"`
}

// ExportChainNode is one node in a schema-5.x call chain. It mirrors
// callGraphChainNode in internal/scan/export.go.
type ExportChainNode struct {
	// FunctionName is the human-readable fully qualified function name.
	FunctionName string `json:"function_name"`
	// CanonicalSignature is the canonical function signature.
	CanonicalSignature string `json:"canonical_signature,omitempty"`
	// ReturnType is the declared return type.
	ReturnType string `json:"return_type,omitempty"`
	// ParameterTypes lists the declared parameter types.
	ParameterTypes []string `json:"parameter_types,omitempty"`
	// Visibility is the access modifier.
	Visibility string `json:"visibility,omitempty"`
	// OwnerVisibility is the access modifier of the enclosing type.
	OwnerVisibility string `json:"owner_visibility,omitempty"`
	// FilePath is the source file path.
	FilePath string `json:"file_path"`
	// StartLine is the first line of the function body.
	StartLine int `json:"start_line,omitempty"`
	// DependencyInfo is stamped for non-root frames. Nil for root-component frames.
	DependencyInfo *ExportDependencyInfo `json:"dependency_info,omitempty"`
	// EntryCall is the call-site data-flow for the edge that led to this frame.
	// Nil on the root frame and on frames derived from legacy 1.0/1.1 fragments.
	EntryCall *ExportEntryCall `json:"entry_call,omitempty"`
	// CryptoCall is the matched crypto invocation, present only on the terminal frame.
	CryptoCall *ExportCryptoCall `json:"crypto_call,omitempty"`
}

// ExportEntryPoint is one entry in the entry_point_index. It mirrors
// callGraphEntryPoint in internal/scan/export.go.
type ExportEntryPoint struct {
	// Function is the fully qualified function name.
	Function string `json:"function"`
	// CanonicalSignature is the canonical function signature.
	CanonicalSignature string `json:"canonical_signature,omitempty"`
	// Class is the enclosing class name.
	Class string `json:"class,omitempty"`
	// Method is the simple method name.
	Method string `json:"method"`
	// ReturnType is the declared return type.
	ReturnType string `json:"return_type,omitempty"`
	// ParameterTypes lists the declared parameter types.
	ParameterTypes []string `json:"parameter_types,omitempty"`
	// Visibility is the access modifier.
	Visibility string `json:"visibility,omitempty"`
	// OwnerVisibility is the access modifier of the enclosing type.
	OwnerVisibility string `json:"owner_visibility,omitempty"`
	// ReachableFindings lists all crypto findings reachable from this entry point.
	ReachableFindings []ExportReachableFinding `json:"reachable_findings"`
}

// ExportReachableFinding is one reachable crypto finding entry inside an
// ExportEntryPoint.
type ExportReachableFinding struct {
	// FindingID is the crypto finding identifier.
	FindingID string `json:"finding_id"`
	// MatchedOperation carries kind/symbol for the finding.
	MatchedOperation *ExportMatchedOperation `json:"matched_operation"`
	// ChainDepth is the number of frames from this entry point to the crypto sink.
	// Shallowest depth wins when the same finding is reachable via multiple chains.
	ChainDepth int `json:"chain_depth"`
	// FindingGraphRef is the finding_id cross-reference.
	FindingGraphRef string `json:"finding_graph_ref"`
}

// ToCallgraphExport converts the stitched Result into a schema-5.x JSON
// structure for root, stamped with meta. It groups chains by FindingID into
// finding_graphs[], stamps dependency_info on non-root frames, emits
// entry_call from frame.EntryCall and crypto_call on the terminal node, then
// builds the entry_point_index from all surviving chains.
//
// The output is resolution-corrected by construction: only chains that passed
// buildAdjacency's fail-closed policy are present in r.Chains.
func (r *Result) ToCallgraphExport(root ComponentKey, meta ScanMeta) CallgraphExport {
	out := CallgraphExport{
		SchemaVersion: meta.SchemaVersion,
		ScanMetadata: ExportScanMeta{
			Ecosystem:  meta.Ecosystem,
			RootModule: meta.RootModule,
		},
	}

	// Group chains by FindingID.
	type findingKey string
	type chainGroup struct {
		findingID  string
		matchedOp  *ExportMatchedOperation
		callChains [][]ExportChainNode
	}
	groupMap := make(map[findingKey]*chainGroup)
	var groupOrder []findingKey

	for i := range r.Chains {
		fc := &r.Chains[i]
		nodes, resolvedFindingID := buildExportChain(fc, root)
		// Use the resolved (potentially dep-prefixed) finding_id as the group key.
		// For root-component ops the resolved ID equals the original; for dep ops it
		// is recomputed with the "module@version/" prefix to match live --scan-dependencies.
		// When computeFindingID returned "" (legacy fragments with no FilePath/StartLine),
		// fall back to the original FindingChain.FindingID so the chain is still emitted.
		if resolvedFindingID == "" {
			resolvedFindingID = fc.FindingID
		}
		key := findingKey(resolvedFindingID)
		grp, exists := groupMap[key]
		if !exists {
			grp = &chainGroup{
				findingID: resolvedFindingID,
				matchedOp: chainMatchedOp(fc),
			}
			groupMap[key] = grp
			groupOrder = append(groupOrder, key)
		}
		if len(nodes) > 0 {
			grp.callChains = append(grp.callChains, nodes)
		}
	}

	sort.Slice(groupOrder, func(i, j int) bool {
		return string(groupOrder[i]) < string(groupOrder[j])
	})

	for _, key := range groupOrder {
		grp := groupMap[key]
		out.FindingGraphs = append(out.FindingGraphs, ExportFindingGraph{
			FindingID:        grp.findingID,
			MatchedOperation: grp.matchedOp,
			CallChains:       grp.callChains,
		})
	}

	out.EntryPointIndex = buildCallgraphEntryPointIndex(out.FindingGraphs)
	return out
}

// chainMatchedOp extracts the matched operation from the last frame's
// CryptoOperation (via the first chain that has it) or returns nil.
func chainMatchedOp(fc *FindingChain) *ExportMatchedOperation {
	if fc != nil && fc.CryptoOp != nil && fc.CryptoOp.MatchedOperation != nil {
		op := fc.CryptoOp.MatchedOperation
		return &ExportMatchedOperation{
			Kind:       op.Kind,
			Symbol:     op.Symbol,
			Expression: op.Expression,
			Line:       op.Line,
		}
	}
	if fc == nil || fc.Symbol == "" {
		return nil
	}
	// Legacy fallback: FindingChain carries only Symbol, so synthesize the
	// minimal schema-5.x call operation when no rich MatchedOperation exists.
	return &ExportMatchedOperation{
		Kind:   "call",
		Symbol: fc.Symbol,
	}
}

// buildExportChain converts one FindingChain into the ordered slice of
// ExportChainNodes, stamping dependency_info on non-root frames. It also
// returns the resolved finding_id for this chain: for dep-component terminal
// ops it is recomputed with the "module@version/" prefix (matching live
// `--scan-dependencies`); for root-component ops it is the original FindingID.
//
// The resolved finding_id is also applied to the terminal node's file_path,
// which is prefixed in the same way so the cross-reference between
// finding_graphs[].finding_id and the emitted chain node's file path is
// consistent with the live scanner output.
func buildExportChain(fc *FindingChain, root ComponentKey) ([]ExportChainNode, string) {
	nodes := make([]ExportChainNode, 0, len(fc.Frames))
	resolvedFindingID := fc.FindingID // default: use the stored (isolated-scan) ID

	for i := range fc.Frames {
		frame := fc.Frames[i]
		node := buildExportNode(frame, root)
		if i == len(fc.Frames)-1 && fc.CryptoOp != nil {
			resolvedFindingID = applyTerminalCryptoOp(&node, frame, fc.CryptoOp, root)
		}
		nodes = append(nodes, node)
	}
	return nodes, resolvedFindingID
}

func applyTerminalCryptoOp(node *ExportChainNode, frame CallFrame, op *CryptoOperation, root ComponentKey) string {
	if frame.Component != root {
		// Non-root: prefix file_path and recompute finding_id.
		module := moduleFromFrame(frame)
		version := frame.Component.Version
		prefixedPath := depPrefixedPath(op.FilePath, module, version)
		node.FilePath = prefixedPath
		if op.CryptoCall != nil {
			node.CryptoCall = exportCryptoCall(op.CryptoCall)
		}
		return computeFindingID(prefixedPath, op.StartLine, op.RuleID)
	}

	// Root component: finding_id is hash of the unprefixed path.
	if op.CryptoCall != nil {
		node.CryptoCall = exportCryptoCall(op.CryptoCall)
	}
	return computeFindingID(op.FilePath, op.StartLine, op.RuleID)
}

// depPrefixedPath returns "module@version/filePath" when module and version are
// non-empty, mirroring the original dep-prefixed path construction
// (stitch.go:302-304). Returns filePath unchanged when the component is root
// (module or version empty) or when filePath is already empty.
func depPrefixedPath(filePath, module, version string) string {
	if filePath == "" || module == "" || version == "" {
		return filePath
	}
	return module + "@" + version + "/" + filePath
}

// computeFindingID computes the 8-hex-char finding identifier, mirroring
// the canonical finding_id formula:
//
//	sha256(path + ":" + startLine + ":" + ruleID)[:8]
//
// The caller is responsible for prefixing path with "module@version/" when the
// finding belongs to a dep component (non-root). Returns the empty string when
// path, startLine, and ruleID are all zero/empty (legacy 1.0/1.1 fragments
// where FilePath/StartLine are not stored in CryptoOperation).
func computeFindingID(path string, startLine int, ruleID string) string {
	if path == "" && startLine == 0 && ruleID == "" {
		return ""
	}
	h := sha256.Sum256([]byte(path + ":" + strconv.Itoa(startLine) + ":" + ruleID))
	return hex.EncodeToString(h[:])[:8]
}

// buildExportNode converts one CallFrame to an ExportChainNode.
func buildExportNode(frame CallFrame, root ComponentKey) ExportChainNode {
	fn := frame.Function
	node := ExportChainNode{
		FunctionName:       fn.FunctionName,
		CanonicalSignature: fn.CanonicalSignature,
		ReturnType:         fn.ReturnType,
		ParameterTypes:     fn.ParameterTypes,
		Visibility:         fn.Visibility,
		OwnerVisibility:    fn.OwnerVisibility,
		FilePath:           fn.FilePath,
		StartLine:          fn.StartLine,
		EntryCall:          exportEntryCall(frame.EntryCall, fn),
	}
	// Stamp dependency_info on non-root frames (ADR-4). The module string comes
	// from the CallFrame.Module (Fragment.Module, set at stitch time), falling
	// back to the purl when absent.
	if frame.Component != root {
		node.DependencyInfo = &ExportDependencyInfo{
			Module:  moduleFromFrame(frame),
			Version: frame.Component.Version,
		}
	}
	return node
}

// moduleFromFrame derives the dependency_info.module string for a frame. It
// uses the Module field carried on the CallFrame (populated from Fragment.Module
// at stitch time). If the module is empty, it falls back to the purl string.
func moduleFromFrame(frame CallFrame) string {
	if frame.Module != "" {
		return frame.Module
	}
	return frame.Component.Purl
}

// exportEntryCall converts a *CallSite to an *ExportEntryCall. Returns nil if
// cs is nil.
func exportEntryCall(cs *CallSite, fn Function) *ExportEntryCall {
	if cs == nil {
		return nil
	}
	ec := &ExportEntryCall{
		FunctionName:       fn.FunctionName,
		CanonicalSignature: fn.CanonicalSignature,
		ReturnType:         fn.ReturnType,
		ParameterTypes:     append([]string(nil), fn.ParameterTypes...),
		Line:               cs.Line,
	}
	for i := range cs.Parameters {
		ec.Parameters = append(ec.Parameters, exportParameter(cs.Parameters[i]))
	}
	return ec
}

// exportCryptoCall converts a *CryptoCall to an *ExportCryptoCall.
func exportCryptoCall(cc *CryptoCall) *ExportCryptoCall {
	if cc == nil {
		return nil
	}
	ec := &ExportCryptoCall{
		FunctionName:       cc.FunctionName,
		CanonicalSignature: cc.CanonicalSignature,
		ReturnType:         cc.ReturnType,
		ParameterTypes:     cc.ParameterTypes,
		Line:               cc.Line,
	}
	for i := range cc.Parameters {
		ec.Parameters = append(ec.Parameters, exportParameter(cc.Parameters[i]))
	}
	return ec
}

// exportParameter converts a Parameter to an ExportParameter.
func exportParameter(p Parameter) ExportParameter {
	ep := ExportParameter{
		ParameterIndex:     p.ParameterIndex,
		Type:               p.Type,
		VariableName:       p.VariableName,
		ArgumentExpression: p.ArgumentExpression,
		ResolvedValue:      p.ResolvedValue,
	}
	for i := range p.SourceNodes {
		ep.SourceNodes = append(ep.SourceNodes, exportSourceNode(p.SourceNodes[i]))
	}
	return ep
}

// exportSourceNode recursively converts a SourceNode to an ExportSourceNode.
func exportSourceNode(sn SourceNode) ExportSourceNode {
	esn := ExportSourceNode{
		Type:           sn.Type,
		Name:           sn.Name,
		DeclaredType:   sn.DeclaredType,
		Value:          sn.Value,
		ParameterIndex: sn.ParameterIndex,
		CallTarget:     sn.CallTarget,
	}
	if sn.Location != nil {
		esn.Location = &ExportSourceLoc{FilePath: sn.Location.FilePath, Line: sn.Location.Line}
	}
	for i := range sn.SourceNodes {
		esn.SourceNodes = append(esn.SourceNodes, exportSourceNode(sn.SourceNodes[i]))
	}
	return esn
}

// --- Entry point index (mirrors export.go:buildEntryPointIndex) ---

type epFindingRef struct {
	findingID string
	matchedOp *ExportMatchedOperation
	depth     int
}

type epData struct {
	function           string
	canonicalSignature string
	class              string
	method             string
	returnType         string
	parameterTypes     []string
	visibility         string
	ownerVisibility    string
	findings           map[string]epFindingRef // findingID → shallowest ref
}

// buildCallgraphEntryPointIndex folds all surviving chains into an entry-point
// index keyed by canonical_signature (or function_name when canonical is
// empty). It mirrors the logic in internal/scan/export.go:buildEntryPointIndex.
func buildCallgraphEntryPointIndex(findingGraphs []ExportFindingGraph) []ExportEntryPoint {
	index := make(map[string]*epData)
	for i := range findingGraphs {
		addFindingGraphToEPI(index, &findingGraphs[i])
	}
	return flattenEPI(index)
}

func addFindingGraphToEPI(index map[string]*epData, fg *ExportFindingGraph) {
	if fg == nil || fg.MatchedOperation == nil {
		return
	}
	for _, chain := range fg.CallChains {
		addChainToEPI(index, fg, chain)
	}
}

func addChainToEPI(index map[string]*epData, fg *ExportFindingGraph, chain []ExportChainNode) {
	if len(chain) == 0 {
		return
	}
	for pos := range chain {
		node := &chain[pos]
		if node.FunctionName == "" {
			continue
		}
		ep := ensureEPData(index, node)
		recordEPFinding(ep, fg, len(chain)-pos)
	}
}

func ensureEPData(index map[string]*epData, node *ExportChainNode) *epData {
	key := node.CanonicalSignature
	if key == "" {
		key = node.FunctionName
	}
	if ep := index[key]; ep != nil {
		mergeEPData(ep, node)
		return ep
	}
	class, method := splitFnName(node.FunctionName)
	ep := &epData{
		function:           node.FunctionName,
		canonicalSignature: node.CanonicalSignature,
		class:              class,
		method:             method,
		returnType:         node.ReturnType,
		parameterTypes:     node.ParameterTypes,
		visibility:         node.Visibility,
		ownerVisibility:    node.OwnerVisibility,
		findings:           make(map[string]epFindingRef),
	}
	index[key] = ep
	return ep
}

func mergeEPData(ep *epData, node *ExportChainNode) {
	if ep.canonicalSignature == "" {
		ep.canonicalSignature = node.CanonicalSignature
	}
	if ep.returnType == "" {
		ep.returnType = node.ReturnType
	}
	if len(ep.parameterTypes) == 0 {
		ep.parameterTypes = node.ParameterTypes
	}
	if ep.visibility == "" {
		ep.visibility = node.Visibility
	}
	if ep.ownerVisibility == "" {
		ep.ownerVisibility = node.OwnerVisibility
	}
}

func recordEPFinding(ep *epData, fg *ExportFindingGraph, depth int) {
	if ep == nil || fg == nil || fg.MatchedOperation == nil {
		return
	}
	existing, exists := ep.findings[fg.FindingID]
	if exists && depth >= existing.depth {
		return
	}
	ep.findings[fg.FindingID] = epFindingRef{
		findingID: fg.FindingID,
		matchedOp: fg.MatchedOperation,
		depth:     depth,
	}
}

func flattenEPI(index map[string]*epData) []ExportEntryPoint {
	result := make([]ExportEntryPoint, 0, len(index))
	for _, ep := range index {
		findings := make([]ExportReachableFinding, 0, len(ep.findings))
		for _, ref := range ep.findings {
			findings = append(findings, ExportReachableFinding{
				FindingID:        ref.findingID,
				MatchedOperation: ref.matchedOp,
				ChainDepth:       ref.depth,
				FindingGraphRef:  ref.findingID,
			})
		}
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].FindingID < findings[j].FindingID
		})
		result = append(result, ExportEntryPoint{
			Function:           ep.function,
			CanonicalSignature: ep.canonicalSignature,
			Class:              ep.class,
			Method:             ep.method,
			ReturnType:         ep.returnType,
			ParameterTypes:     ep.parameterTypes,
			Visibility:         ep.visibility,
			OwnerVisibility:    ep.ownerVisibility,
			ReachableFindings:  findings,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Function < result[j].Function
	})
	return result
}

// splitFnName extracts class and method from a fully qualified function name.
func splitFnName(fn string) (class, method string) {
	idx := strings.LastIndex(fn, ".")
	if idx < 0 {
		return "", fn
	}
	return fn[:idx], fn[idx+1:]
}
