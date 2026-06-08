// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package graphfrag is crypto-finder's public contract for reusable component
// graph fragments: the structural call-graph + rules-versioned crypto
// annotations that `crypto-finder scan --export-graph-fragment` emits for a
// single component, plus the pure stitcher that composes a dependency closure
// of those fragments into root-to-crypto reachability chains.
//
// Why this lives in crypto-finder: the graph fragment schema and the
// resolution-quality semantics are crypto-finder's public contract — the
// scanner produces them, so the rules for consuming them (which edges may
// extend a chain) belong with the contract owner.
//
// The package is intentionally dependency-light: it does NOT import the scanner
// or callgraph builder, read storage, or gzip. Inputs are exported fragments
// (or decoded Fragments); the caller fetches and decompresses them.
package graphfrag

import (
	"encoding/json"
	"strings"
)

// ComponentKey identifies one mined component version.
type ComponentKey struct {
	Purl    string
	Version string
}

func (k ComponentKey) String() string {
	if k.Version == "" {
		return k.Purl
	}
	return k.Purl + "@" + k.Version
}

// DependencyGraph is the authoritative component-version graph resolved from
// build metadata. Stitching only crosses into components reachable through this
// graph, even if extra fragments are available in storage.
type DependencyGraph map[ComponentKey][]ComponentKey

// Fragment is one reusable structural graph fragment plus rules-versioned
// crypto annotations for a single component version. The production storage
// layer may split this into structural graph blobs and separate crypto
// annotation blobs, but the stitcher consumes the combined view.
type Fragment struct {
	Component ComponentKey
	Module    string
	// GraphAlgoVersion is the callgraph-construction algorithm version that
	// produced this structural graph (from scan_metadata). Consumers cache the
	// structure keyed on it so it survives binary releases that don't change
	// graph construction.
	GraphAlgoVersion string

	// RulesVersion is the rules_version of the crypto annotation attached to this
	// fragment (the version under which CryptoOperations/SupportingCalls were
	// computed). Empty for purely structural fragments (code graph with no
	// annotation attached). Consumers that stitch a set mined under heterogeneous
	// rules versions use it to report the highest contributing version.
	RulesVersion string

	Functions         []Function
	InternalEdges     []InternalEdge
	ExternalCalls     []ExternalCall
	CryptoOperations  []CryptoOperation
	SupportingCalls   []SupportingCall
	CryptoEntryPoints []CryptoEntryPoint
}

// Function identifies one callable node inside a component graph.
//
// The Signature field (the fragment's function key, e.g. "org.bridge.(Bridge).bridge#0")
// is the join key for edge resolution. The richer identity fields below are
// populated from graph-fragment-1.2+ exports so the stitcher can emit them
// verbatim in the schema-6.0 output (callgraph_export.go). They are zero-value
// on legacy 1.0/1.1 fragments — graceful degradation.
type Function struct {
	// Signature is the fragment's function key used by edges (e.g. "org.bridge.(Bridge).bridge#0").
	Signature string
	// FunctionName is the fully-qualified human-readable function name (e.g. "org.bridge.Bridge.bridge").
	FunctionName string
	// CanonicalSignature is the canonical function signature (1.2+).
	CanonicalSignature string
	// ReturnType is the declared return type (1.2+).
	ReturnType string
	// ParameterTypes lists the declared parameter types in order (1.2+).
	ParameterTypes []string
	// Visibility is the declared access modifier of the function (1.2+).
	Visibility string
	// OwnerVisibility is the declared access modifier of the enclosing type (1.2+).
	OwnerVisibility string
	// StartLine is the first source line of the function body (1.2+).
	StartLine int
	// EndLine is the last source line of the function body (1.2+). With
	// StartLine it gives the line range used to map a crypto finding to its
	// containing function during annotate-only (no AST available then).
	EndLine int
	// FilePath is the source file path, relative to the component root.
	FilePath string
	// DisplaySymbol is the customer-facing symbol. Constructors use
	// ClassName.ClassName while Signature/CanonicalSignature retain <init>.
	DisplaySymbol string
	// Aliases contains alternate customer-facing names for this function.
	Aliases []string
}

// CallSite carries the per-edge call-site invocation detail: the line number and
// the resolved argument data-flow for each positional argument passed by the
// caller at this edge. Mirrors the schema-6.0 entry_call shape.
type CallSite struct {
	// Line is the source line of the call expression in the caller.
	Line int
	// Parameters carries the resolved argument data-flow for each positional argument.
	Parameters []Parameter
}

// Parameter is one positional argument at a call site, including any resolved
// data-flow provenance. Mirrors the schema-6.0 callGraphParameter shape.
type Parameter struct {
	// ParameterIndex is the 0-based position of this argument.
	ParameterIndex int
	// Type is the declared parameter type in the callee's signature.
	Type string
	// VariableName is the local variable name if the argument was a simple identifier.
	VariableName string
	// ArgumentExpression is the raw source text of the argument expression.
	ArgumentExpression string
	// ResolvedValue is a simplified literal value when statically resolvable.
	ResolvedValue string
	// SourceNodes carries the data-flow provenance for this argument (recursive).
	SourceNodes []SourceNode
}

// SourceNode is one node in the data-flow provenance graph. The SourceNodes
// field makes this type recursive so PARAMETER→CALL_RESULT chains are fully
// preserved. Mirrors the schema-6.0 exportSourceNode shape.
type SourceNode struct {
	// Type classifies the origin: VALUE, VARIABLE, FIELD, PARAMETER, CALL_RESULT, EXPRESSION.
	Type string
	// Name is the variable/field/parameter name.
	Name string
	// DeclaredType is the type if known.
	DeclaredType string
	// Value is the actual value for VALUE nodes.
	Value string
	// ParameterIndex is set for PARAMETER nodes.
	ParameterIndex *int
	// CallTarget is set for CALL_RESULT nodes — the function that produced the value.
	CallTarget string
	// Location is where this source is defined.
	Location *SourceLocation
	// SourceNodes traces where THIS node's value came from (recursive).
	SourceNodes []SourceNode
}

// SourceLocation identifies a position in source code.
type SourceLocation struct {
	FilePath string
	Line     int
}

// CryptoCall carries the identity and call-site argument data-flow of a matched
// crypto invocation. It is stored on CryptoOperation (1.2+) and mirrors the
// schema-6.0 callGraphCalledFunction shape.
type CryptoCall struct {
	// FunctionName is the fully qualified function name of the matched crypto call.
	FunctionName string
	// CanonicalSignature is the canonical function signature.
	CanonicalSignature string
	// ReturnType is the declared return type.
	ReturnType string
	// ParameterTypes lists the declared parameter types.
	ParameterTypes []string
	// DisplaySymbol is the customer-facing symbol, with constructor aliases.
	DisplaySymbol string
	// Aliases are alternate customer-facing names.
	Aliases []string
	// Line is the source line of the matched crypto call.
	Line int
	// Parameters carries the resolved argument data-flow.
	Parameters []Parameter
}

// MatchedOp records the matched operation kind, symbol, and expression for a
// crypto finding — the same fields carried by the schema-6.0 matched_operation.
type MatchedOp struct {
	// Kind is the operation kind: "call", "type_usage", or "expression".
	Kind string
	// Symbol is the fully qualified API symbol.
	Symbol string
	// Expression is the raw source expression that matched.
	Expression string
	// Line is the source line of the matched expression.
	Line int
}

// InternalEdge connects two functions inside the same component fragment.
//
// Internal edges carry the same resolution metadata as ExternalCall: an
// interface or fluent call resolved by name+arity can land on a co-located
// implementation just as easily as a cross-component one, so it must be gated
// by the same policy. The dispatch-group identity (Caller + CallSite +
// MethodName + Arity) is shared with ExternalCall so that siblings of one call
// site that span the component boundary are judged together.
type InternalEdge struct {
	Caller string
	Callee string

	// Resolution classifies how the producer resolved Callee. Zero value
	// (ResolutionUnknown) is fail-closed.
	Resolution ResolutionKind

	// DeclaredType, MethodName, Arity, CallSite mirror ExternalCall and identify
	// the dispatched method / call site for ambiguity grouping.
	DeclaredType string
	MethodName   string
	Arity        int
	CallSite     int

	// ReceiverVar, AssignedVar, ChainID carry the call-site object identity
	// (1.4+). They let object-lifecycle supporting calls be re-derived from a
	// cached fragment alone — no live callgraph — which is what lets the annotate
	// path recompute supporting_calls for findings a new rule introduces. Empty
	// on fragments exported with schema < 1.4.
	ReceiverVar string
	AssignedVar string
	ChainID     string

	// StartCol, EndCol carry the 1-based call-expression columns (start inclusive,
	// end exclusive — the opengrep/tree-sitter convention). They let the annotate
	// path run the SAME column-intersection terminal selection as the live exporter
	// (findCryptoCallNode) instead of a line-only heuristic, so cache-derived
	// supporting calls match a live scan on multi-call/fluent-chain lines. 0 on
	// fragments exported with schema < 1.4 — selection falls back to line-only.
	StartCol int
	EndCol   int

	// EntryCall carries the call-site argument data-flow for this edge (1.2+).
	// Nil on fragments exported with schema < 1.2.
	EntryCall *CallSite
}

// ResolutionKind classifies how confidently the producer resolved a call to its
// target. The stitcher uses this to decide whether an edge is allowed to extend
// a reachability chain. The zero value is ResolutionUnknown, which is treated as
// untrusted: the stitcher fails closed rather than guessing.
//
// This is the central guard against over-broad dispatch false positives. An
// interface or fluent call resolved purely by method name + arity (no receiver
// type anchor) must never be presented as typed reachability proof.
type ResolutionKind string

const (
	// ResolutionUnknown is the zero value: the producer did not classify the
	// edge. Treated as untrusted and never traversed. Its presence usually means
	// a producer bug (an edge exported without a resolution kind).
	ResolutionUnknown ResolutionKind = ""

	// ResolutionExact means the receiver's static type was known and the method
	// resolved to a unique declared target on that type (or an overload set on
	// that exact type). Always traversed.
	ResolutionExact ResolutionKind = "exact"

	// ResolutionInterfaceDispatch means the target was found by expanding an
	// interface/abstract method to concrete implementations matching name+arity
	// within a namespace root. Trusted ONLY when exactly one implementation is
	// present in the current component's direct dependencies; ambiguous (>1)
	// call sites fail closed.
	ResolutionInterfaceDispatch ResolutionKind = "interface_dispatch"

	// ResolutionNameOnly means the target was guessed by method name + arity
	// (plus namespace heuristics) with no receiver type anchor — e.g. fluent
	// fallback. Never traversed.
	ResolutionNameOnly ResolutionKind = "name_only"
)

// ExternalCall is a call from this component to a function whose implementation
// may live in another component from the dependency graph.
type ExternalCall struct {
	Caller          string
	TargetSignature string

	// Raw is the source call expression (e.g. "gen.init"). Carried so the
	// annotate path can reproduce a supporting call's matched_operation.expression
	// from the cached fragment. Empty on fragments exported with schema < 1.4.
	Raw string

	// Resolution classifies how the producer resolved TargetSignature. The zero
	// value (ResolutionUnknown) is fail-closed: the stitcher will not traverse it.
	Resolution ResolutionKind

	// DeclaredType is the static/interface type observed at the call site (e.g.
	// the interface whose method was dispatched). Provenance plus part of the
	// dispatch-group identity used to detect ambiguous interface dispatch.
	DeclaredType string

	// MethodName and Arity identify the invoked method independently of the
	// resolved target, so sibling candidates of one ambiguous call site can be
	// grouped together.
	MethodName string
	Arity      int

	// CallSite is the source line of the call expression. Together with Caller,
	// MethodName, and Arity it discriminates distinct call sites that happen to
	// share a method name within the same caller.
	CallSite int

	// ReceiverVar, AssignedVar, ChainID carry the call-site object identity
	// (1.4+). They let object-lifecycle supporting calls be re-derived from a
	// cached fragment alone — no live callgraph — which is what lets the annotate
	// path recompute supporting_calls for findings a new rule introduces. Empty
	// on fragments exported with schema < 1.4.
	ReceiverVar string
	AssignedVar string
	ChainID     string

	// StartCol, EndCol carry the 1-based call-expression columns (start inclusive,
	// end exclusive). See InternalEdge.StartCol. 0 on fragments exported with
	// schema < 1.4 — selection falls back to line-only.
	StartCol int
	EndCol   int

	// EntryCall carries the call-site argument data-flow for this edge (1.2+).
	// Nil on fragments exported with schema < 1.2.
	EntryCall *CallSite
}

// CryptoOperation is a crypto finding attached to a function.
//
// The rich fields (CryptoCall, OID, Metadata, Source, MatchedOperation) are
// populated from graph-fragment-1.2+ exports. They are zero/nil on legacy
// fragments — the stitcher still emits structural chains, just without
// data-flow / asset metadata (safe degradation).
type CryptoOperation struct {
	Function  string
	FindingID string
	RuleID    string
	Symbol    string

	// FilePath is the source file path (relative to the component root) where
	// the crypto finding was detected. Used by the callgraph exporter to recompute
	// finding_id with a dep-prefix when the op belongs to a non-root component.
	// Populated from graph-fragment-1.2+ exports; empty on legacy fragments.
	FilePath string
	// StartLine is the source line of the crypto finding. Together with FilePath
	// and RuleID it is the input to the finding_id hash:
	//   sha256(path + ":" + startLine + ":" + ruleID)[:8]
	// where path is prefixed with "module@version/" for dep components.
	StartLine int
	// EndLine is the last source line of the crypto finding (often == StartLine
	// for single-line detections). Carried through so renderers can emit the
	// findings.json `end_line` field. Populated from graph-fragment-1.2+.
	EndLine int
	// Match is the exact source expression that triggered the detection (the
	// findings.json `match` field), e.g. `Cipher.getInstance("AES")`. Carried
	// through so renderers can emit it. Populated from graph-fragment-1.2+.
	Match string

	// CryptoCall carries the identity and argument data-flow of the matched
	// crypto invocation (1.2+).
	CryptoCall *CryptoCall
	// OID is the Object Identifier for the cryptographic algorithm (1.2+).
	OID string
	// Metadata is the raw asset metadata block from the scanner (1.2+).
	// Stored verbatim so renderers can pass it through without re-serialization.
	Metadata json.RawMessage
	// Source indicates how the finding was discovered: "direct" or "indirect" (1.2+).
	Source string
	// MatchedOperation records the kind/symbol/expression of the matched crypto
	// operation (1.2+).
	MatchedOperation *MatchedOp
	// SupportingCallIDs are the supporting_id values of THIS finding's
	// object-lifecycle supporting calls (graph-fragment 1.5+). It is the precise
	// finding->supporting foreign key, captured at derivation time where object
	// identity still exists. The top-level supporting_calls array is deduped
	// across findings and carries no finding_id, so this is the only place the
	// per-finding association survives persistence and stitch — the served
	// callgraph's finding_graph.supporting_call_ids is sourced from here.
	SupportingCallIDs []string
}

// SupportingCall is a non-finding crypto-adjacent call carried as context for
// reachability. It is intentionally separate from CryptoOperation so config and
// lifecycle calls do not inflate finding counts.
type SupportingCall struct {
	Function           string
	SupportingID       string
	Category           string
	FilePath           string
	StartLine          int
	EndLine            int
	FunctionName       string
	CanonicalSignature string
	DisplaySymbol      string
	Aliases            []string
	SupportingCall     *CryptoCall
	Metadata           json.RawMessage
	MatchedOperation   *MatchedOp
}

// CryptoEntryPoint is the decoded entrypoint/stitch projection from
// graph-fragment-1.3.
type CryptoEntryPoint struct {
	FunctionKey              string
	FunctionName             string
	CanonicalSignature       string
	DisplaySymbol            string
	Aliases                  []string
	ReturnType               string
	ParameterTypes           []string
	Visibility               string
	OwnerVisibility          string
	ReachableFindings        []ReachableFinding
	ReachableSupportingCalls []ReachableSupportingCall
}

// ReachableFinding links an entrypoint to a reachable terminal finding.
type ReachableFinding struct {
	FindingID       string
	ChainDepth      int
	FindingGraphRef string
}

// ReachableSupportingCall links an entrypoint to a reachable supporting call.
type ReachableSupportingCall struct {
	SupportingID      string
	ChainDepth        int
	SupportingCallRef string
}

// ConfidenceHigh is the confidence of every chain emitted under the default
// fail-closed policy (only exact and unique-implementation interface edges are
// traversed). The constant exists so a future opt-in mode can surface
// lower-confidence chains explicitly.
const ConfidenceHigh = "high"

// Suppression reasons recorded on a SuppressedEdge.
const (
	// SuppressReasonUnknown: an edge had no resolution kind (producer bug or an
	// intentionally untrusted edge).
	SuppressReasonUnknown = "unknown_resolution"
	// SuppressReasonNameOnly: a name+arity guess with no receiver type anchor.
	SuppressReasonNameOnly = "name_only"
	// SuppressReasonAmbiguousDispatch: an interface call site with more than one
	// concrete implementation present in the current component's direct dependencies.
	SuppressReasonAmbiguousDispatch = "interface_dispatch_ambiguous"
)

// Result is the stitched reachability output in its minimal semantic form.
// Rendering into crypto-finder's customer-facing callgraph schema is a later
// adapter concern.
type Result struct {
	Chains          []FindingChain
	SupportingCalls []SupportingCall

	// Suppressed records call edges the policy refused to traverse. It is the
	// audit trail for fail-closed decisions and the data source for a future
	// opt-in "show me the uncertain paths too" mode. It never affects Chains.
	Suppressed []SuppressedEdge
}

// FindingChain is one root-to-crypto path.
type FindingChain struct {
	FindingID string
	RuleID    string
	Symbol    string
	Frames    []CallFrame

	// Confidence is the weakest-link confidence of the traversed edges. Under
	// the default policy this is always ConfidenceHigh.
	Confidence string

	// CryptoOp carries the full crypto operation from the terminal frame (1.2+).
	// Populated by the stitcher from the fragment's CryptoOperation for the
	// terminal node so the converter can emit crypto_call without re-reading the
	// fragments.
	CryptoOp *CryptoOperation
}

// SuppressedEdge is one call edge (or grouped call site) the stitcher declined
// to traverse, with the reason and the candidate targets it would have reached.
type SuppressedEdge struct {
	Caller     CallFrame
	MethodName string
	Arity      int
	Reason     string
	Candidates []ComponentKey
}

// CallFrame is one frame in a stitched path.
//
// Signature is the fragment key used internally for graph traversal (matches
// Function.Signature on the resolved node). Function carries the full identity
// of the resolved node (1.2+; zero-value on legacy fragments). EntryCall is
// the call-site argument data-flow for the edge traversed to ARRIVE at this
// frame from the previous frame (nil on the root frame and on legacy fragments).
// Module is the Maven/npm/etc. module string for the component (from
// Fragment.Module), carried here so dependency_info can be stamped at
// projection time without re-reading the original fragment.
type CallFrame struct {
	Component ComponentKey
	// Signature is the function key (fragment edge join key).
	Signature string
	// Function carries the full rich identity of this node (1.2+).
	Function Function
	// EntryCall is the call-site data-flow for the edge that led to this frame (1.2+).
	EntryCall *CallSite
	// Module is the fragment's root module string (e.g. "net.crypto:lib"), used
	// to stamp dependency_info.module at projection time.
	Module string
}

// ErrMissingFragment means the dependency closure references components whose
// graph fragments are absent. The stitcher fails closed instead of returning a
// partial graph.
type ErrMissingFragment struct {
	Components []ComponentKey
}

func (e *ErrMissingFragment) Error() string {
	if e == nil || len(e.Components) == 0 {
		return "graphfrag: missing graph fragments"
	}
	parts := make([]string, len(e.Components))
	for i, c := range e.Components {
		parts[i] = c.String()
	}
	return "graphfrag: missing graph fragments for " + strings.Join(parts, ", ")
}
