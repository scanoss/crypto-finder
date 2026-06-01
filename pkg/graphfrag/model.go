// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package graphfrag is crypto-finder's public contract for reusable component
// graph fragments: the structural call-graph + rules-versioned crypto
// annotations that `crypto-finder scan --export-graph-fragment` emits for a
// single component, plus the pure stitcher that composes a dependency closure
// of those fragments into root-to-crypto reachability chains.
//
// Why this lives in crypto-finder (not a downstream service): the graph
// fragment schema and the resolution-quality semantics are crypto-finder's
// public contract — the scanner produces them, so the rules for consuming them
// (which edges may extend a chain) belong with the contract owner. A
// reimplementation in a downstream catalog/mining service would drift the
// moment the schema bumps. Mirrors the rationale of pkg/stitch.
//
// The package is intentionally dependency-light: it does NOT import the scanner
// or callgraph builder, read storage, or gzip. Inputs are exported fragments
// (or decoded Fragments); the caller fetches and decompresses them.
package graphfrag

import "strings"

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

	Functions        []Function
	InternalEdges    []InternalEdge
	ExternalCalls    []ExternalCall
	CryptoOperations []CryptoOperation
}

// Function identifies one callable node inside a component graph.
type Function struct {
	Signature string
	FilePath  string
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
	// present in the dependency closure; ambiguous (>1) call sites fail closed.
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
}

// CryptoOperation is a crypto finding attached to a function.
type CryptoOperation struct {
	Function  string
	FindingID string
	RuleID    string
	Symbol    string
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
	// concrete implementation present in the dependency closure.
	SuppressReasonAmbiguousDispatch = "interface_dispatch_ambiguous"
)

// Result is the stitched reachability output in its minimal semantic form.
// Rendering into crypto-finder's customer-facing callgraph schema is a later
// adapter concern.
type Result struct {
	Chains []FindingChain

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
type CallFrame struct {
	Component ComponentKey
	Function  string
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
