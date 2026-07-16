// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// SchemaVersion is the current graph-fragment export schema version.
//
// 1.1 added per-edge resolution metadata (resolution / declared_type /
// method_name / arity) on internal_edges and external_calls. The fields are
// additive: a 1.0 fragment decodes with an empty resolution, which the stitcher
// treats as untrusted (fail-closed).
//
// 1.2 adds per-edge call-site data-flow (entry_call on internal_edges and
// external_calls) and full crypto-call identity + asset metadata on
// crypto_annotations. All additions are additive: a 1.1 fragment decodes with
// nil entry_call / nil CryptoCall fields, which the stitcher degrades to
// structural-only chains (safe fail-closed behavior).
//
// 1.3 adds customer-facing reachability projections: crypto_entry_points,
// supporting_calls, and display aliases for constructor symbols. Canonical
// function keys still use the internal <init> identity for joins.
//
// 1.6 adds resolved_receiver_type on internal_edges/external_calls: the
// concrete receiver type the producer's KB-contract/return-type inference
// resolved for an interface-dispatch call site, when available. The stitcher
// uses it to disambiguate a dispatch group that has more than one candidate
// target in closure, without changing the fail-closed default for call sites
// inference did not resolve. Additive: a 1.5 fragment decodes with an empty
// resolved_receiver_type, which the stitcher treats exactly as before.
//
// 1.7 adds internal_edges_compact plus internal_edge_strings. It carries the
// same internal edge fields as internal_edges, but indexes repeated strings and
// function keys to keep large dependency fragments small.
const SchemaVersion = "graph-fragment-1.8"

// GraphAlgoVersion identifies the callgraph-CONSTRUCTION algorithm version. It
// is independent of the binary version (cf_version) and the wire schema
// (SchemaVersion): it bumps ONLY when callgraph/inference construction changes
// in a way that alters the structural graph. Consumers key their cached
// structural graphs on this so a routine binary release does not invalidate the
// cache — only a graph-affecting change does. Stamped into scan_metadata.
const GraphAlgoVersion = "graph-algo-1"

// GraphFragmentExport is the on-the-wire JSON shape emitted by
// `crypto-finder scan --export-graph-fragment` for a single component. It is
// crypto-finder's public contract; the scanner (internal/scan) builds it from a
// callgraph, and any consumer decodes it into a Fragment via DecodeFragment.
type GraphFragmentExport struct {
	SchemaVersion        string                          `json:"schema_version"`
	ScanMetadata         GraphFragmentScanMetadata       `json:"scan_metadata"`
	Functions            []GraphFragmentFunction         `json:"functions"`
	InternalEdges        []GraphFragmentEdge             `json:"internal_edges,omitempty"`
	InternalEdgeStrings  []string                        `json:"internal_edge_strings,omitempty"`
	CompactInternalEdges []GraphFragmentCompactEdge      `json:"internal_edges_compact,omitempty"`
	ExternalCalls        []GraphFragmentExternal         `json:"external_calls,omitempty"`
	CryptoAnnotations    []GraphFragmentCryptoOp         `json:"crypto_annotations,omitempty"`
	SupportingCalls      []GraphFragmentSupporting       `json:"supporting_calls,omitempty"`
	CryptoEntryPoints    []GraphFragmentCryptoEntryPoint `json:"crypto_entry_points,omitempty"`
}

// GraphFragmentCompactEdge is the graph-fragment-1.7 compact form of
// GraphFragmentEdge. JSON is a positional array:
// [caller_fn, callee_fn, line, resolution_s, declared_type_s, method_s, arity,
//
//	receiver_var_s, assigned_var_s, chain_id_s, start_col, end_col,
//	resolved_receiver_type_s, entry_call].
//
// Function indexes address GraphFragmentExport.Functions; string indexes
// address GraphFragmentExport.InternalEdgeStrings.
type GraphFragmentCompactEdge struct {
	Caller, Callee                       int
	Line                                 int
	Resolution, DeclaredType, MethodName int
	Arity                                int
	ReceiverVar, AssignedVar, ChainID    int
	StartCol, EndCol                     int
	ResolvedReceiverType                 int
	EntryCall                            *GraphFragmentCallSite
}

// MarshalJSON encodes the compact edge as a positional JSON array.
func (e GraphFragmentCompactEdge) MarshalJSON() ([]byte, error) {
	values := []int{
		e.Caller, e.Callee, e.Line, e.Resolution, e.DeclaredType, e.MethodName,
		e.Arity, e.ReceiverVar, e.AssignedVar, e.ChainID, e.StartCol, e.EndCol,
		e.ResolvedReceiverType,
	}
	last := len(values) - 1
	for last >= 0 && values[last] == 0 {
		last--
	}
	if e.EntryCall != nil {
		last = len(values)
	}
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i := 0; i <= last; i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		if i == len(values) {
			data, err := json.Marshal(e.EntryCall)
			if err != nil {
				return nil, err
			}
			buf.Write(data)
			continue
		}
		buf.WriteString(strconv.Itoa(values[i]))
	}
	buf.WriteByte(']')
	return buf.Bytes(), nil
}

// UnmarshalJSON decodes the compact positional edge array.
func (e *GraphFragmentCompactEdge) UnmarshalJSON(data []byte) error {
	var values []json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	ints := []*int{
		&e.Caller, &e.Callee, &e.Line, &e.Resolution, &e.DeclaredType, &e.MethodName,
		&e.Arity, &e.ReceiverVar, &e.AssignedVar, &e.ChainID, &e.StartCol, &e.EndCol,
		&e.ResolvedReceiverType,
	}
	if len(values) > len(ints)+1 {
		return fmt.Errorf("graphfrag: compact edge has %d fields, want at most %d", len(values), len(ints)+1)
	}
	for i := 0; i < len(values) && i < len(ints); i++ {
		if err := json.Unmarshal(values[i], ints[i]); err != nil {
			return fmt.Errorf("graphfrag: compact edge field %d: %w", i, err)
		}
	}
	if len(values) == len(ints)+1 && len(values[len(ints)]) > 0 && string(values[len(ints)]) != "null" {
		var call GraphFragmentCallSite
		if err := json.Unmarshal(values[len(ints)], &call); err != nil {
			return fmt.Errorf("graphfrag: compact edge entry_call: %w", err)
		}
		e.EntryCall = &call
	}
	return nil
}

// GraphFragmentScanMetadata summarizes the scan that produced a graph-fragment
// export and the payload counts emitted for that component.
type GraphFragmentScanMetadata struct {
	Ecosystem   string `json:"ecosystem,omitempty"`
	RootModule  string `json:"root_module,omitempty"`
	ToolName    string `json:"tool_name,omitempty"`
	ToolVersion string `json:"tool_version,omitempty"`
	// GraphAlgoVersion is the callgraph-construction algorithm version (see the
	// GraphAlgoVersion const). Consumers cache structural graphs keyed on it.
	GraphAlgoVersion  string `json:"graph_algo_version,omitempty"`
	RulesVersion      string `json:"rules_version,omitempty"`
	ExportedAt        string `json:"exported_at"`
	FunctionCount     int    `json:"function_count"`
	InternalEdges     int    `json:"internal_edge_count"`
	ExternalCalls     int    `json:"external_call_count"`
	CryptoOps         int    `json:"crypto_operation_count"`
	SupportingCalls   int    `json:"supporting_call_count,omitempty"`
	CryptoEntryPoints int    `json:"crypto_entry_point_count,omitempty"`
}

// GraphFragmentFunction is one function declaration included in a component's
// graph-fragment export.
type GraphFragmentFunction struct {
	Key                string          `json:"key"`
	FunctionName       string          `json:"function_name"`
	CanonicalSignature string          `json:"canonical_signature,omitempty"`
	Package            string          `json:"package,omitempty"`
	Type               string          `json:"type,omitempty"`
	Name               string          `json:"name,omitempty"`
	FilePath           string          `json:"file_path,omitempty"`
	StartLine          int             `json:"start_line,omitempty"`
	EndLine            int             `json:"end_line,omitempty"`
	ReturnType         string          `json:"return_type,omitempty"`
	ParameterTypes     []string        `json:"parameter_types,omitempty"`
	Visibility         string          `json:"visibility,omitempty"`
	OwnerVisibility    string          `json:"owner_visibility,omitempty"`
	DisplaySymbol      string          `json:"display_symbol,omitempty"`
	Aliases            []string        `json:"aliases,omitempty"`
	InferredReturn     json.RawMessage `json:"-"`
}

// GraphFragmentCallSite carries the per-edge call-site invocation detail: the
// arguments the caller passed to the callee at this edge, mirroring the
// schema-6.0 entry_call shape. It lives on the edge (not the function) because
// entry_call describes the caller→callee invocation.
type GraphFragmentCallSite struct {
	// Line is the source line of the call expression in the caller.
	Line int `json:"line,omitempty"`
	// Parameters carries the resolved argument data-flow for each positional
	// argument in the call.
	Parameters []GraphFragmentParameter `json:"parameters,omitempty"`
}

// GraphFragmentParameter mirrors the schema-6.0 callGraphParameter shape so the
// stitcher can emit entry_call.parameters[] verbatim.
type GraphFragmentParameter struct {
	// ParameterIndex is the 0-based position of this argument in the call.
	ParameterIndex int `json:"parameter_index"`
	// Type is the declared parameter type in the callee's signature.
	Type string `json:"type,omitempty"`
	// VariableName is the local variable name if the argument was a simple identifier.
	VariableName string `json:"variable_name,omitempty"`
	// ArgumentExpression is the raw source text of the argument expression.
	ArgumentExpression string `json:"argument_expression,omitempty"`
	// ResolvedValue is a simplified literal value when it can be statically resolved.
	ResolvedValue string `json:"resolved_value,omitempty"`
	// SourceNodes carries the data-flow provenance for this argument.
	SourceNodes []GraphFragmentSourceNode `json:"source_nodes,omitempty"`
}

// GraphFragmentSourceNode is the recursive data-flow provenance node, mirroring
// the schema-6.0 exportSourceNode shape. The SourceNodes field makes this type
// recursive so PARAMETER→CALL_RESULT chains are fully preserved.
type GraphFragmentSourceNode struct {
	// Type classifies the origin: VALUE, VARIABLE, FIELD, PARAMETER, CALL_RESULT, EXPRESSION.
	Type string `json:"type"`
	// Name is the variable/field/parameter name.
	Name string `json:"name,omitempty"`
	// DeclaredType is the type if known.
	DeclaredType string `json:"declared_type,omitempty"`
	// Value is the actual value for VALUE nodes.
	Value string `json:"value,omitempty"`
	// ParameterIndex is set for PARAMETER nodes.
	ParameterIndex *int `json:"parameter_index,omitempty"`
	// CallTarget is set for CALL_RESULT nodes — the function that produced the value.
	CallTarget string `json:"call_target,omitempty"`
	// Location is where this source is defined.
	Location *GraphFragmentSourceLoc `json:"location,omitempty"`
	// SourceNodes traces where THIS node's value came from (recursive).
	SourceNodes []GraphFragmentSourceNode `json:"source_nodes,omitempty"`
}

// GraphFragmentSourceLoc identifies a position in source code.
type GraphFragmentSourceLoc struct {
	FilePath string `json:"file_path,omitempty"`
	Line     int    `json:"line,omitempty"`
}

// GraphFragmentCryptoCall carries the identity and argument data-flow of the
// matched crypto invocation, mirroring the schema-6.0 callGraphCalledFunction
// shape. It is a dedicated type (not reusing GraphFragmentCallSite) so it can
// carry function identity fields alongside the call-site parameters.
type GraphFragmentCryptoCall struct {
	// FunctionName is the fully qualified function name of the matched crypto call.
	FunctionName string `json:"function_name,omitempty"`
	// CanonicalSignature is the canonical function signature.
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
	Line int `json:"line,omitempty"`
	// Parameters carries the resolved argument data-flow for each positional argument.
	Parameters []GraphFragmentParameter `json:"parameters,omitempty"`
	// ParameterRoles is the issue-103 (WU3) contracts-KB-derived per-parameter
	// role/contribution list, index-aligned with ParameterTypes.
	ParameterRoles []GraphFragmentParameterRole `json:"parameter_roles,omitempty"`
}

// GraphFragmentRoleProvenance explains where a method_role came from: a
// direct contract match, or inherited from same-class sibling assets
// (issue-103 WU2).
type GraphFragmentRoleProvenance struct {
	Kind               string                      `json:"kind,omitempty"`
	ContractMethod     string                      `json:"contract_method,omitempty"`
	InheritedFrom      string                      `json:"inherited_from,omitempty"`
	Inherited          *GraphFragmentInheritedRole `json:"inherited,omitempty"`
	InheritedAmbiguous bool                        `json:"inherited_ambiguous,omitempty"`
}

// GraphFragmentInheritedRole carries the algorithm_family/primitive a
// synthesized operation entry point inherited from a same-class sibling asset.
type GraphFragmentInheritedRole struct {
	AlgorithmFamily string `json:"algorithm_family,omitempty"`
	Primitive       string `json:"primitive,omitempty"`
}

// GraphFragmentParameterRole is one index-aligned parameter role/contribution
// entry (issue-103 WU3).
type GraphFragmentParameterRole struct {
	Index       int                        `json:"index"`
	Name        string                     `json:"name,omitempty"`
	Role        string                     `json:"role"`
	Contributes *GraphFragmentContribution `json:"contributes,omitempty"`
}

// GraphFragmentContribution names the property a parameter contributes to
// and the derivation strategy a downstream consumer applies.
type GraphFragmentContribution struct {
	Property   string `json:"property,omitempty"`
	Derivation string `json:"derivation,omitempty"`
}

// GraphFragmentMatchedOp records the matched operation kind, symbol, and
// expression for a crypto finding — the same fields carried by the schema-6.0
// matched_operation shape.
type GraphFragmentMatchedOp struct {
	// Kind is the operation kind: "call", "type_usage", or "expression".
	Kind string `json:"kind,omitempty"`
	// Symbol is the fully qualified API symbol (e.g., "javax.crypto.Cipher.getInstance").
	Symbol string `json:"symbol,omitempty"`
	// Expression is the raw source expression that matched.
	Expression string `json:"expression,omitempty"`
	// Line is the source line of the matched expression.
	Line int `json:"line,omitempty"`
}

// GraphFragmentEdge is one internal (intra-component) call edge plus the
// resolution metadata that lets a consumer decide whether to traverse it.
type GraphFragmentEdge struct {
	CallerKey    string `json:"caller_key"`
	CalleeKey    string `json:"callee_key"`
	Line         int    `json:"line,omitempty"`
	Resolution   string `json:"resolution"`
	DeclaredType string `json:"declared_type,omitempty"`
	MethodName   string `json:"method_name,omitempty"`
	Arity        int    `json:"arity,omitempty"`
	// ReceiverVar/AssignedVar/ChainID carry the call-site object identity (1.4+)
	// for cache-side object-lifecycle re-derivation. Empty on schema < 1.4.
	ReceiverVar string `json:"receiver_var,omitempty"`
	AssignedVar string `json:"assigned_var,omitempty"`
	ChainID     string `json:"chain_id,omitempty"`
	// StartCol/EndCol carry the 1-based call-expression columns (start inclusive,
	// end exclusive) so the annotate path runs the same column-intersection
	// terminal selection as the live exporter (1.4+). 0 on schema < 1.4.
	StartCol int `json:"start_col,omitempty"`
	EndCol   int `json:"end_col,omitempty"`
	// EntryCall carries the call-site argument data-flow for this edge (1.2+).
	// Nil on fragments exported with schema < 1.2.
	EntryCall *GraphFragmentCallSite `json:"entry_call,omitempty"`
	// ResolvedReceiverType is the concrete receiver type resolved by KB-contract
	// or return-type inference for this call site (1.6+). Empty when inference
	// did not resolve a concrete type, or on fragments exported with schema < 1.6.
	ResolvedReceiverType string `json:"resolved_receiver_type,omitempty"`
}

// GraphFragmentExternal is one external (cross-component) call edge plus its
// resolution metadata.
type GraphFragmentExternal struct {
	CallerKey          string `json:"caller_key"`
	TargetKey          string `json:"target_key"`
	TargetFunctionName string `json:"target_function_name,omitempty"`
	Raw                string `json:"raw,omitempty"`
	Line               int    `json:"line,omitempty"`
	Resolution         string `json:"resolution"`
	DeclaredType       string `json:"declared_type,omitempty"`
	MethodName         string `json:"method_name,omitempty"`
	Arity              int    `json:"arity,omitempty"`
	// ReceiverVar/AssignedVar/ChainID carry the call-site object identity (1.4+)
	// for cache-side object-lifecycle re-derivation. Empty on schema < 1.4.
	ReceiverVar string `json:"receiver_var,omitempty"`
	AssignedVar string `json:"assigned_var,omitempty"`
	ChainID     string `json:"chain_id,omitempty"`
	// StartCol/EndCol carry the 1-based call-expression columns (start inclusive,
	// end exclusive) so the annotate path runs the same column-intersection
	// terminal selection as the live exporter (1.4+). 0 on schema < 1.4.
	StartCol int `json:"start_col,omitempty"`
	EndCol   int `json:"end_col,omitempty"`
	// EntryCall carries the call-site argument data-flow for this edge (1.2+).
	// Nil on fragments exported with schema < 1.2.
	EntryCall *GraphFragmentCallSite `json:"entry_call,omitempty"`
	// ResolvedReceiverType is the concrete receiver type resolved by KB-contract
	// or return-type inference for this call site (1.6+). Empty when inference
	// did not resolve a concrete type, or on fragments exported with schema < 1.6.
	ResolvedReceiverType string `json:"resolved_receiver_type,omitempty"`
}

// GraphFragmentCryptoOp is one crypto finding annotation attached to a function
// in the exported graph fragment.
type GraphFragmentCryptoOp struct {
	FunctionKey string `json:"function_key,omitempty"`
	FindingID   string `json:"finding_id,omitempty"`
	RuleID      string `json:"rule_id,omitempty"`
	Symbol      string `json:"symbol,omitempty"`
	Expression  string `json:"expression,omitempty"`
	FilePath    string `json:"file_path,omitempty"`
	StartLine   int    `json:"start_line,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
	// CryptoCall carries the identity and argument data-flow of the matched
	// crypto invocation (1.2+). Nil on fragments exported with schema < 1.2.
	CryptoCall *GraphFragmentCryptoCall `json:"crypto_call,omitempty"`
	// OID is the Object Identifier for the cryptographic algorithm (1.2+).
	OID string `json:"oid,omitempty"`
	// Metadata is the raw asset metadata block from the scanner (1.2+).
	// It is stored verbatim so the stitcher can pass it through to the render
	// layer without re-serialization.
	Metadata json.RawMessage `json:"metadata,omitempty"`
	// Source indicates how the finding was discovered: "direct" or "indirect" (1.2+).
	Source string `json:"source,omitempty"`
	// MatchedOperation records the kind/symbol/expression of the matched crypto
	// operation (1.2+). Mirrors the schema-6.0 matched_operation shape.
	MatchedOperation *GraphFragmentMatchedOp `json:"matched_operation,omitempty"`
	// SupportingCallIDs are the supporting_id values of THIS finding's
	// object-lifecycle supporting calls (1.5+) — the precise finding->supporting
	// foreign key. Sorted, de-duplicated. Each id resolves to a top-level
	// supporting_calls entry; the stitch-built callgraph surfaces these as
	// finding_graph.supporting_call_ids and the served API as a per-asset
	// breadcrumb.
	SupportingCallIDs []string `json:"supporting_call_ids,omitempty"`
}

// GraphFragmentSupporting is a non-finding crypto-adjacent call such as
// builder/config/lifecycle/context setup. It is useful for reachability context
// but must not inflate crypto finding counts.
type GraphFragmentSupporting struct {
	SupportingID       string                   `json:"supporting_id"`
	FunctionKey        string                   `json:"function_key,omitempty"`
	FunctionName       string                   `json:"function_name,omitempty"`
	CanonicalSignature string                   `json:"canonical_signature,omitempty"`
	DisplaySymbol      string                   `json:"display_symbol,omitempty"`
	Aliases            []string                 `json:"aliases,omitempty"`
	Category           string                   `json:"category,omitempty"`
	FilePath           string                   `json:"file_path,omitempty"`
	StartLine          int                      `json:"start_line,omitempty"`
	EndLine            int                      `json:"end_line,omitempty"`
	MatchedOperation   *GraphFragmentMatchedOp  `json:"matched_operation,omitempty"`
	SupportingCall     *GraphFragmentCryptoCall `json:"supporting_call,omitempty"`
	Metadata           json.RawMessage          `json:"metadata,omitempty"`
}

// GraphFragmentCryptoEntryPoint is the catalog/customer stitch index: if a
// caller reaches this function key (or one of its aliases), these findings and
// supporting calls become reachable.
type GraphFragmentCryptoEntryPoint struct {
	FunctionKey              string                                 `json:"function_key"`
	FunctionName             string                                 `json:"function_name,omitempty"`
	CanonicalSignature       string                                 `json:"canonical_signature,omitempty"`
	DisplaySymbol            string                                 `json:"display_symbol,omitempty"`
	Aliases                  []string                               `json:"aliases,omitempty"`
	ReturnType               string                                 `json:"return_type,omitempty"`
	ParameterTypes           []string                               `json:"parameter_types,omitempty"`
	Visibility               string                                 `json:"visibility,omitempty"`
	OwnerVisibility          string                                 `json:"owner_visibility,omitempty"`
	ReachableFindings        []GraphFragmentReachableFinding        `json:"reachable_findings,omitempty"`
	ReachableSupportingCalls []GraphFragmentReachableSupportingCall `json:"reachable_supporting_calls,omitempty"`
	// MethodRole, RoleProvenance, ParameterRoles are issue-103 (WU2/WU3)
	// additions carried through the fragment so the stitch/served path can
	// enrich the reachability-projected crypto_entry_points entry by
	// function_key (see stitch.go indexOperationEntryPoints).
	MethodRole     string                       `json:"method_role,omitempty"`
	RoleProvenance *GraphFragmentRoleProvenance `json:"role_provenance,omitempty"`
	ParameterRoles []GraphFragmentParameterRole `json:"parameter_roles,omitempty"`
}

// GraphFragmentReachableFinding is a finding reachable from an entrypoint.
type GraphFragmentReachableFinding struct {
	FindingID       string `json:"finding_id"`
	ChainDepth      int    `json:"chain_depth"`
	FindingGraphRef string `json:"finding_graph_ref,omitempty"`
}

// GraphFragmentReachableSupportingCall is a supporting call reachable from an
// entrypoint.
type GraphFragmentReachableSupportingCall struct {
	SupportingID      string `json:"supporting_id"`
	ChainDepth        int    `json:"chain_depth"`
	SupportingCallRef string `json:"supporting_call_ref,omitempty"`
}
