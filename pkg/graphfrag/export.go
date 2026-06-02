// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package graphfrag

import "encoding/json"

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
const SchemaVersion = "graph-fragment-1.2"

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
	SchemaVersion     string                    `json:"schema_version"`
	ScanMetadata      GraphFragmentScanMetadata `json:"scan_metadata"`
	Functions         []GraphFragmentFunction   `json:"functions"`
	InternalEdges     []GraphFragmentEdge       `json:"internal_edges,omitempty"`
	ExternalCalls     []GraphFragmentExternal   `json:"external_calls,omitempty"`
	CryptoAnnotations []GraphFragmentCryptoOp   `json:"crypto_annotations,omitempty"`
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
	GraphAlgoVersion string `json:"graph_algo_version,omitempty"`
	RulesVersion     string `json:"rules_version,omitempty"`
	ExportedAt       string `json:"exported_at"`
	FunctionCount    int    `json:"function_count"`
	InternalEdges    int    `json:"internal_edge_count"`
	ExternalCalls    int    `json:"external_call_count"`
	CryptoOps        int    `json:"crypto_operation_count"`
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
	InferredReturn     json.RawMessage `json:"-"`
}

// GraphFragmentCallSite carries the per-edge call-site invocation detail: the
// arguments the caller passed to the callee at this edge, mirroring the
// schema-5.x entry_call shape. It lives on the edge (not the function) because
// entry_call describes the caller→callee invocation.
type GraphFragmentCallSite struct {
	// Line is the source line of the call expression in the caller.
	Line int `json:"line,omitempty"`
	// Parameters carries the resolved argument data-flow for each positional
	// argument in the call.
	Parameters []GraphFragmentParameter `json:"parameters,omitempty"`
}

// GraphFragmentParameter mirrors the schema-5.x callGraphParameter shape so the
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
// the schema-5.x exportSourceNode shape. The SourceNodes field makes this type
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
// matched crypto invocation, mirroring the schema-5.x callGraphCalledFunction
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
	// Line is the source line of the matched crypto call.
	Line int `json:"line,omitempty"`
	// Parameters carries the resolved argument data-flow for each positional argument.
	Parameters []GraphFragmentParameter `json:"parameters,omitempty"`
}

// GraphFragmentMatchedOp records the matched operation kind, symbol, and
// expression for a crypto finding — the same fields carried by the schema-5.x
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
	// EntryCall carries the call-site argument data-flow for this edge (1.2+).
	// Nil on fragments exported with schema < 1.2.
	EntryCall *GraphFragmentCallSite `json:"entry_call,omitempty"`
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
	// EntryCall carries the call-site argument data-flow for this edge (1.2+).
	// Nil on fragments exported with schema < 1.2.
	EntryCall *GraphFragmentCallSite `json:"entry_call,omitempty"`
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
	// operation (1.2+). Mirrors the schema-5.x matched_operation shape.
	MatchedOperation *GraphFragmentMatchedOp `json:"matched_operation,omitempty"`
}
