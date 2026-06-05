// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package graphfrag — schema-6.0 JSON converter.
//
// ToCallgraphExport projects a stitched Result into the schema-6.0 JSON shape
// used by crypto-finder's customer-facing callgraph export. The schema-6.0
// structs are intentionally duplicated here as exported types: they are
// pkg/graphfrag's public contract, keeping the package's schema+semantics
// together with their owner.
//
// Relationship to internal/scan/export.go: the unexported callGraphChainNode,
// callGraphEntryCall, etc. types in export.go share the same JSON field names
// and semantics. This file is the promoted copy for stitched graph results.
package graphfrag

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// CallgraphSchemaVersion is the canonical schema_version of the callgraph
// export envelope (the `--export-callgraph` / stitch reachability format). It is
// the single source of truth for both the live CLI export (internal/scan) and
// the graph-fragment stitch path (ToCallgraphExport), so the two can never drift
// — a consumer that serves stitched output stamps the SAME version a live
// `--scan-dependencies --export-callgraph` run produces.
const CallgraphSchemaVersion = "6.2"

// ScanMeta carries the top-level metadata stamped onto a CallgraphExport.
type ScanMeta struct {
	// SchemaVersion overrides the emitted schema_version. Normally left empty:
	// ToCallgraphExport stamps CallgraphSchemaVersion (the format owns its own
	// version). Set this only to force a non-canonical value (tests/migration).
	SchemaVersion string
	// RootModule is the Maven/npm/etc. module string for the root component.
	RootModule string
	// Ecosystem identifies the language ecosystem (e.g. "java").
	Ecosystem string
}

// CallgraphExport is the schema-6.0 JSON envelope produced by ToCallgraphExport.
// It mirrors the callGraphExportV2 shape in internal/scan/export.go.
type CallgraphExport struct {
	SchemaVersion     string                   `json:"schema_version"`
	ScanMetadata      ExportScanMeta           `json:"scan_metadata"`
	FindingGraphs     []ExportFindingGraph     `json:"finding_graphs"`
	SupportingCalls   []ExportSupportingCall   `json:"supporting_calls,omitempty"`
	CryptoEntryPoints []ExportCryptoEntryPoint `json:"crypto_entry_points,omitempty"`
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
	// SupportingCallIDs are the supporting_id values of this finding's
	// object-lifecycle supporting calls (6.1+) — the precise finding->supporting
	// foreign key, carried from the terminal CryptoOperation. Each id resolves to
	// a top-level supporting_calls entry. The served API surfaces these as a
	// per-asset breadcrumb.
	SupportingCallIDs []string `json:"supporting_call_ids,omitempty"`
	// CallChains is the set of surviving root-to-crypto paths for this finding.
	CallChains [][]ExportChainNode `json:"call_chains,omitempty"`
}

// ExportMatchedOperation mirrors the schema-6.0 matched_operation shape.
type ExportMatchedOperation struct {
	Kind   string `json:"kind"`
	Symbol string `json:"symbol,omitempty"`
	// DisplaySymbol is the customer-facing symbol, with constructor aliases
	// (ClassName.ClassName). Derived from Symbol; empty for non-constructors.
	DisplaySymbol string `json:"display_symbol,omitempty"`
	Expression    string `json:"expression,omitempty"`
	Line          int    `json:"line,omitempty"`
}

// ExportDependencyInfo mirrors the schema-6.0 dependency_info shape. It is
// stamped on non-root frames using the frame's Component module string.
type ExportDependencyInfo struct {
	Module  string `json:"module"`
	Version string `json:"version,omitempty"`
}

// ExportEntryCall is the schema-6.0 entry_call shape on a chain node. It
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
	// DisplaySymbol is the customer-facing symbol, with constructor aliases.
	DisplaySymbol string `json:"display_symbol,omitempty"`
	// Aliases are alternate customer-facing names.
	Aliases []string `json:"aliases,omitempty"`
	// Line is the source line in the caller where the call is made.
	Line int `json:"line,omitempty"`
	// Parameters carries the resolved argument data-flow.
	Parameters []ExportParameter `json:"parameters,omitempty"`
}

// ExportCryptoCall is the schema-6.0 crypto_call shape on the terminal node.
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
	// DisplaySymbol is the customer-facing symbol, with constructor aliases.
	DisplaySymbol string `json:"display_symbol,omitempty"`
	// Aliases are alternate customer-facing names.
	Aliases []string `json:"aliases,omitempty"`
	// Line is the source line of the matched crypto call.
	Line int `json:"line"`
	// Parameters carries the resolved argument data-flow.
	Parameters []ExportParameter `json:"parameters,omitempty"`
}

// ExportParameter is the schema-6.0 callGraphParameter shape.
type ExportParameter struct {
	ParameterIndex     int                `json:"parameter_index"`
	Type               string             `json:"type,omitempty"`
	VariableName       string             `json:"variable_name,omitempty"`
	ArgumentExpression string             `json:"argument_expression,omitempty"`
	ResolvedValue      string             `json:"resolved_value,omitempty"`
	SourceNodes        []ExportSourceNode `json:"source_nodes,omitempty"`
}

// ExportSourceNode is the schema-6.0 exportSourceNode shape. The SourceNodes
// field makes it recursive so PARAMETER→CALL_RESULT chains are preserved.
type ExportSourceNode struct {
	Type           string `json:"type"`
	Name           string `json:"name,omitempty"`
	DeclaredType   string `json:"declared_type,omitempty"`
	Value          string `json:"value,omitempty"`
	ParameterIndex *int   `json:"parameter_index,omitempty"`
	CallTarget     string `json:"call_target,omitempty"`
	// CallTargetDisplaySymbol is the customer-facing constructor alias
	// (ClassName.ClassName) of CallTarget when it is a constructor (<init>);
	// empty otherwise. Sibling of CallTarget, mirroring symbol/display_symbol.
	CallTargetDisplaySymbol string             `json:"call_target_display_symbol,omitempty"`
	Location                *ExportSourceLoc   `json:"location,omitempty"`
	SourceNodes             []ExportSourceNode `json:"source_nodes,omitempty"`
}

// ExportSourceLoc is a source location reference.
type ExportSourceLoc struct {
	FilePath string `json:"file_path,omitempty"`
	Line     int    `json:"line,omitempty"`
}

// ExportChainNode is one node in a schema-6.0 call chain. It mirrors
// callGraphChainNode in internal/scan/export.go.
type ExportChainNode struct {
	// FunctionKey is the canonical graph-fragment join key.
	FunctionKey string `json:"function_key,omitempty"`
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
	// DisplaySymbol is the customer-facing symbol, with constructor aliases.
	DisplaySymbol string `json:"display_symbol,omitempty"`
	// Aliases are alternate customer-facing names.
	Aliases []string `json:"aliases,omitempty"`
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

// ExportCryptoEntryPoint is one entry in crypto_entry_points.
type ExportCryptoEntryPoint struct {
	// FunctionKey is the canonical graph-fragment join key.
	FunctionKey string `json:"function_key"`
	// FunctionName is the fully qualified function name.
	FunctionName string `json:"function_name,omitempty"`
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
	// DisplaySymbol is the customer-facing symbol, with constructor aliases.
	DisplaySymbol string `json:"display_symbol,omitempty"`
	// Aliases are alternate customer-facing names.
	Aliases []string `json:"aliases,omitempty"`
	// ReachableFindings lists all crypto findings reachable from this entry point.
	ReachableFindings []ExportReachableFinding `json:"reachable_findings,omitempty"`
	// ReachableSupportingCalls lists non-finding context calls reachable from this entry point.
	ReachableSupportingCalls []ExportReachableSupportingCall `json:"reachable_supporting_calls,omitempty"`
}

// ExportEntryPoint is kept as a Go-level compatibility alias for callers that
// referenced the old type name; the JSON field is crypto_entry_points.
type ExportEntryPoint = ExportCryptoEntryPoint

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

// ExportReachableSupportingCall is one reachable supporting call entry inside
// an ExportCryptoEntryPoint.
type ExportReachableSupportingCall struct {
	SupportingID      string `json:"supporting_id"`
	ChainDepth        int    `json:"chain_depth"`
	SupportingCallRef string `json:"supporting_call_ref,omitempty"`
}

// ExportSupportingCall is one top-level non-finding crypto-adjacent call.
type ExportSupportingCall struct {
	SupportingID       string                  `json:"supporting_id"`
	FunctionKey        string                  `json:"function_key,omitempty"`
	FunctionName       string                  `json:"function_name,omitempty"`
	CanonicalSignature string                  `json:"canonical_signature,omitempty"`
	DisplaySymbol      string                  `json:"display_symbol,omitempty"`
	Aliases            []string                `json:"aliases,omitempty"`
	Category           string                  `json:"category,omitempty"`
	FilePath           string                  `json:"file_path,omitempty"`
	StartLine          int                     `json:"start_line,omitempty"`
	EndLine            int                     `json:"end_line,omitempty"`
	MatchedOperation   *ExportMatchedOperation `json:"matched_operation,omitempty"`
	SupportingCall     *ExportCryptoCall       `json:"supporting_call,omitempty"`
}

// ToCallgraphExport converts the stitched Result into a schema-6.0 JSON
// structure for root, stamped with meta. It groups chains by FindingID into
// finding_graphs[], stamps dependency_info on non-root frames, emits
// entry_call from frame.EntryCall and crypto_call on the terminal node, then
// builds crypto_entry_points from all surviving chains.
//
// The output is resolution-corrected by construction: only chains that passed
// buildAdjacency's fail-closed policy are present in r.Chains.
func (r *Result) ToCallgraphExport(root ComponentKey, meta ScanMeta) CallgraphExport {
	schemaVersion := meta.SchemaVersion
	if schemaVersion == "" {
		schemaVersion = CallgraphSchemaVersion
	}
	out := CallgraphExport{
		SchemaVersion: schemaVersion,
		ScanMetadata: ExportScanMeta{
			Ecosystem:  meta.Ecosystem,
			RootModule: meta.RootModule,
		},
	}

	// Group chains by FindingID.
	type findingKey string
	type chainGroup struct {
		findingID         string
		matchedOp         *ExportMatchedOperation
		supportingCallIDs []string
		callChains        [][]ExportChainNode
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
				findingID:         resolvedFindingID,
				matchedOp:         chainMatchedOp(fc),
				supportingCallIDs: chainSupportingCallIDs(fc),
			}
			groupMap[key] = grp
			groupOrder = append(groupOrder, key)
		}
		// All chains for one finding share the same terminal crypto op; fill the
		// FK from the first chain that carries it (legacy/empty fragments → nil).
		if len(grp.supportingCallIDs) == 0 {
			grp.supportingCallIDs = chainSupportingCallIDs(fc)
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
			FindingID:         grp.findingID,
			MatchedOperation:  grp.matchedOp,
			SupportingCallIDs: grp.supportingCallIDs,
			CallChains:        grp.callChains,
		})
	}

	out.SupportingCalls = exportSupportingCalls(r.SupportingCalls)
	out.CryptoEntryPoints = buildCallgraphCryptoEntryPoints(out.FindingGraphs, out.SupportingCalls)
	return out
}

// chainSupportingCallIDs returns the terminal crypto operation's supporting-call
// foreign key (6.1+), cloned. The stitcher populates FindingChain.CryptoOp from
// the fragment's CryptoOperation for the terminal node, so the precise
// finding->supporting ids persisted at annotate time ride straight through to the
// finding_graph here. Returns nil for legacy fragments with no crypto op.
func chainSupportingCallIDs(fc *FindingChain) []string {
	if fc == nil || fc.CryptoOp == nil || len(fc.CryptoOp.SupportingCallIDs) == 0 {
		return nil
	}
	return append([]string(nil), fc.CryptoOp.SupportingCallIDs...)
}

// chainMatchedOp extracts the matched operation from the last frame's
// CryptoOperation (via the first chain that has it) or returns nil.
func chainMatchedOp(fc *FindingChain) *ExportMatchedOperation {
	if fc != nil && fc.CryptoOp != nil && fc.CryptoOp.MatchedOperation != nil {
		op := fc.CryptoOp.MatchedOperation
		return &ExportMatchedOperation{
			Kind:          op.Kind,
			Symbol:        op.Symbol,
			DisplaySymbol: ConstructorDisplayFromSymbol(op.Symbol),
			Expression:    op.Expression,
			Line:          op.Line,
		}
	}
	if fc == nil || fc.Symbol == "" {
		return nil
	}
	// Legacy fallback: FindingChain carries only Symbol, so synthesize the
	// minimal schema-6.0 call operation when no rich MatchedOperation exists.
	return &ExportMatchedOperation{
		Kind:          "call",
		Symbol:        fc.Symbol,
		DisplaySymbol: ConstructorDisplayFromSymbol(fc.Symbol),
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
		frame := &fc.Frames[i]
		node := buildExportNode(frame, root)
		if i == len(fc.Frames)-1 && fc.CryptoOp != nil {
			resolvedFindingID = applyTerminalCryptoOp(&node, frame, fc.CryptoOp, root)
		}
		nodes = append(nodes, node)
	}
	return nodes, resolvedFindingID
}

func applyTerminalCryptoOp(node *ExportChainNode, frame *CallFrame, op *CryptoOperation, root ComponentKey) string {
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
func buildExportNode(frame *CallFrame, root ComponentKey) ExportChainNode {
	fn := frame.Function
	node := ExportChainNode{
		FunctionKey:        fn.Signature,
		FunctionName:       fn.FunctionName,
		CanonicalSignature: fn.CanonicalSignature,
		ReturnType:         fn.ReturnType,
		ParameterTypes:     fn.ParameterTypes,
		Visibility:         fn.Visibility,
		OwnerVisibility:    fn.OwnerVisibility,
		DisplaySymbol:      fn.DisplaySymbol,
		Aliases:            append([]string(nil), fn.Aliases...),
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
func moduleFromFrame(frame *CallFrame) string {
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
		DisplaySymbol:      fn.DisplaySymbol,
		Aliases:            append([]string(nil), fn.Aliases...),
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
		DisplaySymbol:      cc.DisplaySymbol,
		Aliases:            append([]string(nil), cc.Aliases...),
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
		Type:                    sn.Type,
		Name:                    sn.Name,
		DeclaredType:            sn.DeclaredType,
		Value:                   sn.Value,
		ParameterIndex:          sn.ParameterIndex,
		CallTarget:              sn.CallTarget,
		CallTargetDisplaySymbol: ConstructorDisplayFromSymbol(sn.CallTarget),
	}
	if sn.Location != nil {
		esn.Location = &ExportSourceLoc{FilePath: sn.Location.FilePath, Line: sn.Location.Line}
	}
	for i := range sn.SourceNodes {
		esn.SourceNodes = append(esn.SourceNodes, exportSourceNode(sn.SourceNodes[i]))
	}
	return esn
}

func exportSupportingCalls(src []SupportingCall) []ExportSupportingCall {
	if len(src) == 0 {
		return nil
	}
	out := make([]ExportSupportingCall, 0, len(src))
	for i := range src {
		s := src[i]
		out = append(out, ExportSupportingCall{
			SupportingID:       s.SupportingID,
			FunctionKey:        s.Function,
			FunctionName:       s.FunctionName,
			CanonicalSignature: s.CanonicalSignature,
			DisplaySymbol:      s.DisplaySymbol,
			Aliases:            append([]string(nil), s.Aliases...),
			Category:           s.Category,
			FilePath:           s.FilePath,
			StartLine:          s.StartLine,
			EndLine:            s.EndLine,
			MatchedOperation:   exportMatchedOp(s.MatchedOperation),
			SupportingCall:     exportCryptoCall(s.SupportingCall),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SupportingID < out[j].SupportingID
	})
	return out
}

func exportMatchedOp(op *MatchedOp) *ExportMatchedOperation {
	if op == nil {
		return nil
	}
	return &ExportMatchedOperation{
		Kind:          op.Kind,
		Symbol:        op.Symbol,
		DisplaySymbol: ConstructorDisplayFromSymbol(op.Symbol),
		Expression:    op.Expression,
		Line:          op.Line,
	}
}

// ConstructorDisplayFromSymbol derives the customer-facing constructor alias
// (ClassName.ClassName) from a fully-qualified symbol whose terminal segment is
// the JVM constructor marker "<init>". For
// "org.bouncycastle.crypto.params.AEADParameters.<init>" it returns
// "org.bouncycastle.crypto.params.AEADParameters.AEADParameters".
//
// It returns "" when the symbol is not a constructor or the type prefix is not a
// clean dotted identifier (fluent chains, generics, arity markers), so callers
// can rely on omitempty to drop the field for non-constructor targets. Deriving
// the alias from the symbol string — rather than threading a separate field
// through the fragment wire — keeps the live and annotate exporters byte-identical:
// both apply this transform to the same Symbol/CallTarget value.
func ConstructorDisplayFromSymbol(symbol string) string {
	const initSuffix = ".<init>"
	if !strings.HasSuffix(symbol, initSuffix) {
		return ""
	}
	prefix := symbol[:len(symbol)-len(initSuffix)]
	if prefix == "" || strings.ContainsAny(prefix, "(<> \t\r\n#") {
		return ""
	}
	simple := prefix
	if dot := strings.LastIndex(prefix, "."); dot >= 0 {
		simple = prefix[dot+1:]
	}
	if simple == "" {
		return ""
	}
	return prefix + "." + simple
}

// --- Crypto entry points (replaces entry_point_index) ---

type epFindingRef struct {
	findingID string
	matchedOp *ExportMatchedOperation
	depth     int
}

type epData struct {
	functionKey        string
	function           string
	canonicalSignature string
	class              string
	method             string
	returnType         string
	parameterTypes     []string
	visibility         string
	ownerVisibility    string
	displaySymbol      string
	aliases            []string
	findings           map[string]epFindingRef // findingID → shallowest ref
	supporting         map[string]ExportReachableSupportingCall
}

// buildCallgraphCryptoEntryPoints folds all surviving chains into an entry-point
// index keyed by canonical_signature (or function_name when canonical is
// empty). It replaces the legacy entry_point_index projection.
func buildCallgraphCryptoEntryPoints(findingGraphs []ExportFindingGraph, supportingCalls []ExportSupportingCall) []ExportCryptoEntryPoint {
	index := make(map[string]*epData)
	for i := range findingGraphs {
		addFindingGraphToEPI(index, &findingGraphs[i])
	}
	for i := range supportingCalls {
		addSupportingCallToEPI(index, supportingCalls[i])
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
	key := node.FunctionKey
	if key == "" {
		key = node.CanonicalSignature
	}
	if key == "" {
		key = node.FunctionName
	}
	if ep := index[key]; ep != nil {
		mergeEPData(ep, node)
		return ep
	}
	class, method := splitFnName(node.FunctionName)
	ep := &epData{
		functionKey:        key,
		function:           node.FunctionName,
		canonicalSignature: node.CanonicalSignature,
		class:              class,
		method:             method,
		returnType:         node.ReturnType,
		parameterTypes:     node.ParameterTypes,
		visibility:         node.Visibility,
		ownerVisibility:    node.OwnerVisibility,
		displaySymbol:      node.DisplaySymbol,
		aliases:            append([]string(nil), node.Aliases...),
		findings:           make(map[string]epFindingRef),
		supporting:         make(map[string]ExportReachableSupportingCall),
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
	if ep.displaySymbol == "" {
		ep.displaySymbol = node.DisplaySymbol
	}
	if len(ep.aliases) == 0 {
		ep.aliases = append([]string(nil), node.Aliases...)
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

func addSupportingCallToEPI(index map[string]*epData, support ExportSupportingCall) {
	key := support.FunctionKey
	if key == "" {
		key = support.CanonicalSignature
	}
	if key == "" {
		key = support.FunctionName
	}
	if key == "" || support.SupportingID == "" {
		return
	}
	ep := index[key]
	if ep == nil {
		class, method := splitFnName(support.FunctionName)
		ep = &epData{
			functionKey:        key,
			function:           support.FunctionName,
			canonicalSignature: support.CanonicalSignature,
			class:              class,
			method:             method,
			displaySymbol:      support.DisplaySymbol,
			aliases:            append([]string(nil), support.Aliases...),
			findings:           make(map[string]epFindingRef),
			supporting:         make(map[string]ExportReachableSupportingCall),
		}
		index[key] = ep
	}
	ep.supporting[support.SupportingID] = ExportReachableSupportingCall{
		SupportingID:      support.SupportingID,
		ChainDepth:        1,
		SupportingCallRef: support.SupportingID,
	}
}

func flattenEPI(index map[string]*epData) []ExportCryptoEntryPoint {
	result := make([]ExportCryptoEntryPoint, 0, len(index))
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
		supporting := flattenReachableSupporting(ep.supporting)
		result = append(result, ExportCryptoEntryPoint{
			FunctionKey:              ep.functionKey,
			FunctionName:             ep.function,
			CanonicalSignature:       ep.canonicalSignature,
			Class:                    ep.class,
			Method:                   ep.method,
			ReturnType:               ep.returnType,
			ParameterTypes:           ep.parameterTypes,
			Visibility:               ep.visibility,
			OwnerVisibility:          ep.ownerVisibility,
			DisplaySymbol:            ep.displaySymbol,
			Aliases:                  append([]string(nil), ep.aliases...),
			ReachableFindings:        findings,
			ReachableSupportingCalls: supporting,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].FunctionKey < result[j].FunctionKey
	})
	return result
}

func flattenReachableSupporting(values map[string]ExportReachableSupportingCall) []ExportReachableSupportingCall {
	if len(values) == 0 {
		return nil
	}
	out := make([]ExportReachableSupportingCall, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SupportingID < out[j].SupportingID
	})
	return out
}

// splitFnName extracts class and method from a fully qualified function name.
func splitFnName(fn string) (class, method string) {
	idx := strings.LastIndex(fn, ".")
	if idx < 0 {
		return "", fn
	}
	return fn[:idx], fn[idx+1:]
}
