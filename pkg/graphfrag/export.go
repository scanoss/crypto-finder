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
const SchemaVersion = "graph-fragment-1.1"

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
	Ecosystem     string `json:"ecosystem,omitempty"`
	RootModule    string `json:"root_module,omitempty"`
	ToolName      string `json:"tool_name,omitempty"`
	ToolVersion   string `json:"tool_version,omitempty"`
	RulesVersion  string `json:"rules_version,omitempty"`
	ExportedAt    string `json:"exported_at"`
	FunctionCount int    `json:"function_count"`
	InternalEdges int    `json:"internal_edge_count"`
	ExternalCalls int    `json:"external_call_count"`
	CryptoOps     int    `json:"crypto_operation_count"`
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
}
