// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package graphfrag is crypto-finder's public contract for reusable component
// graph fragments: the structural call-graph + rules-versioned crypto
// annotations that `crypto-finder scan --export-graph-fragment` emits for a
// single component, plus the pure stitcher that composes a dependency closure
// of those fragments into root-to-crypto reachability chains.
//
// It forwards to github.com/scanoss/static-engine/graphfrag, which holds the
// implementation; the names here are aliases so both paths share one type.
package graphfrag

import (
	enginegraphfrag "github.com/scanoss/static-engine/graphfrag"
)

type (
	// ScanMeta carries the top-level metadata stamped onto a CallgraphExport.
	ScanMeta = enginegraphfrag.ScanMeta
	// CallgraphExport is the schema-6.0 JSON envelope produced by ToCallgraphExport.
	// It mirrors the callGraphExportV2 shape in internal/scan/export.go.
	CallgraphExport = enginegraphfrag.CallgraphExport
	// ExportScanMeta is the scan_metadata block inside a CallgraphExport.
	ExportScanMeta = enginegraphfrag.ExportScanMeta
	// ExportEcosystem describes one call graph a live export analyzed.
	ExportEcosystem = enginegraphfrag.ExportEcosystem
	// ExportFindingGraph groups all surviving chains for one crypto finding occurrence.
	ExportFindingGraph = enginegraphfrag.ExportFindingGraph
	// ExportFindingAnalysis reports how complete the analysis behind one finding
	// graph is (6.8+). CallChains is partial when any search cap was hit or when
	// ambiguous forward calls with partial completeness exist. Parameters is
	// complete when every exported parameter resolves, partial when only some do,
	// unavailable when none do.
	ExportFindingAnalysis = enginegraphfrag.ExportFindingAnalysis
	// ExportForwardClosure is the projected forward call graph from one finding
	// anchor (6.3+). Nodes are deduped forward-reachable functions (depth >= 1);
	// edges are the traversed call sites (endpoints in {anchor} ∪ nodes). MaxDepth
	// echoes the depth CAP applied (the budget), not the deepest node reached;
	// Truncated is true whenever any cap (depth/node/edge) cut the walk short.
	ExportForwardClosure = enginegraphfrag.ExportForwardClosure
	// ExportAmbiguousForwardCall is one fail-closed interface-dispatch call site.
	// Its candidates are evidence, never traversed forward edges.
	ExportAmbiguousForwardCall = enginegraphfrag.ExportAmbiguousForwardCall
	// ExportAmbiguousCallSite identifies the source invocation shared by every
	// candidate in an ambiguous dispatch group.
	ExportAmbiguousCallSite = enginegraphfrag.ExportAmbiguousCallSite
	// ExportAmbiguousForwardCandidate is one possible target for an ambiguous
	// dispatch. EntryCall carries the candidate-aligned argument/provenance data.
	ExportAmbiguousForwardCandidate = enginegraphfrag.ExportAmbiguousForwardCandidate
	// ExportForwardAnchor is the lean identity of the forward closure's root: the
	// finding's own function. File path and dependency identity already live on
	// the finding itself and are not repeated here.
	ExportForwardAnchor = enginegraphfrag.ExportForwardAnchor
	// ExportForwardNode is one forward-reachable function in the closure.
	ExportForwardNode = enginegraphfrag.ExportForwardNode
	// ExportForwardEdge is one traversed caller→callee call site. EntryCall
	// carries the call-site argument data-flow (resolved values, source nodes)
	// in the same shape as chain-node entry_call.
	ExportForwardEdge = enginegraphfrag.ExportForwardEdge
	// ExportMatchedOperation mirrors the schema-6.0 matched_operation shape.
	ExportMatchedOperation = enginegraphfrag.ExportMatchedOperation
	// ExportDependencyInfo mirrors the schema-6.0 dependency_info shape. It is
	// stamped on non-root frames using the frame's Component module string.
	ExportDependencyInfo = enginegraphfrag.ExportDependencyInfo
	// ExportFindingDependency is finding_graphs[].dependency: the dependency a
	// finding sits in, with its package URL, and how the application reaches it
	// in the resolved dependency graph (not in the call graph).
	ExportFindingDependency = enginegraphfrag.ExportFindingDependency
	// ExportDependencyPathStep is one dependency on a finding's dependency path.
	ExportDependencyPathStep = enginegraphfrag.ExportDependencyPathStep
	// ExportEntryCall is the schema-6.0 entry_call shape on a chain node. It
	// carries the caller's invocation detail for the edge that led to this frame.
	ExportEntryCall = enginegraphfrag.ExportEntryCall
	// ExportCryptoCall is the schema-6.0 crypto_call shape on the terminal node.
	// It mirrors callGraphCalledFunction in internal/scan/export.go.
	ExportCryptoCall = enginegraphfrag.ExportCryptoCall
	// ExportRoleProvenance explains where a method_role came from: a direct
	// contract match, or inherited from same-class sibling assets (issue-103 WU2).
	ExportRoleProvenance = enginegraphfrag.ExportRoleProvenance
	// ExportInheritedRole carries the algorithm_family/primitive a synthesized
	// operation entry point inherited from a same-class sibling asset.
	ExportInheritedRole = enginegraphfrag.ExportInheritedRole
	// ExportParameterRole is one index-aligned parameter role/contribution entry
	// (issue-103 WU3).
	ExportParameterRole = enginegraphfrag.ExportParameterRole
	// ExportContribution names the property a parameter contributes to and the
	// derivation strategy a downstream consumer applies.
	ExportContribution = enginegraphfrag.ExportContribution
	// ExportParameter is the schema-6.0 callGraphParameter shape.
	ExportParameter = enginegraphfrag.ExportParameter
	// ExportSourceNode is the schema-6.0 exportSourceNode shape. The SourceNodes
	// field makes it recursive so PARAMETER→CALL_RESULT chains are preserved.
	ExportSourceNode = enginegraphfrag.ExportSourceNode
	// ExportSourceLoc is a source location reference.
	ExportSourceLoc = enginegraphfrag.ExportSourceLoc
	// ExportChainNode is one node in a schema-6.0 call chain. It mirrors
	// callGraphChainNode in internal/scan/export.go.
	ExportChainNode = enginegraphfrag.ExportChainNode
	// ExportExcerpt is a short window of the source the analysis read, centered on
	// the frame's focus line: the call that leads to the next frame, or the crypto
	// call on the last frame. Lines are verbatim, without trailing newline.
	ExportExcerpt = enginegraphfrag.ExportExcerpt
	// ExportCryptoEntryPoint is one entry in crypto_entry_points.
	ExportCryptoEntryPoint = enginegraphfrag.ExportCryptoEntryPoint
	// ExportEntryPoint is kept as a Go-level compatibility alias for callers that
	// referenced the old type name; the JSON field is crypto_entry_points.
	ExportEntryPoint = enginegraphfrag.ExportEntryPoint
	// ExportReachableFinding is one reachable crypto finding entry inside an
	// ExportEntryPoint.
	ExportReachableFinding = enginegraphfrag.ExportReachableFinding
	// ExportReachableSupportingCall is one reachable supporting call entry inside
	// an ExportCryptoEntryPoint.
	ExportReachableSupportingCall = enginegraphfrag.ExportReachableSupportingCall
	// ExportSupportingCall is one top-level non-finding crypto-adjacent call.
	ExportSupportingCall = enginegraphfrag.ExportSupportingCall
	// GraphFragmentExport is the on-the-wire JSON shape emitted by
	// `crypto-finder scan --export-graph-fragment` for a single component. It is
	// crypto-finder's public contract; the scanner (internal/scan) builds it from a
	// callgraph, and any consumer decodes it into a Fragment via DecodeFragment.
	GraphFragmentExport = enginegraphfrag.GraphFragmentExport
	// GraphFragmentCompactEdge is the graph-fragment-1.7 compact form of
	// GraphFragmentEdge. JSON is a positional array:
	// [caller_fn, callee_fn, line, resolution_s, declared_type_s, method_s, arity,
	//
	//	receiver_var_s, assigned_var_s, chain_id_s, start_col, end_col,
	//	resolved_receiver_type_s, entry_call].
	//
	// Function indexes address GraphFragmentExport.Functions; string indexes
	// address GraphFragmentExport.InternalEdgeStrings.
	GraphFragmentCompactEdge = enginegraphfrag.GraphFragmentCompactEdge
	// GraphFragmentScanMetadata summarizes the scan that produced a graph-fragment
	// export and the payload counts emitted for that component.
	GraphFragmentScanMetadata = enginegraphfrag.GraphFragmentScanMetadata
	// GraphFragmentFunction is one function declaration included in a component's
	// graph-fragment export.
	GraphFragmentFunction = enginegraphfrag.GraphFragmentFunction
	// GraphFragmentCallSite carries the per-edge call-site invocation detail: the
	// arguments the caller passed to the callee at this edge, mirroring the
	// schema-6.0 entry_call shape. It lives on the edge (not the function) because
	// entry_call describes the caller→callee invocation.
	GraphFragmentCallSite = enginegraphfrag.GraphFragmentCallSite
	// GraphFragmentParameter mirrors the schema-6.0 callGraphParameter shape so the
	// stitcher can emit entry_call.parameters[] verbatim.
	GraphFragmentParameter = enginegraphfrag.GraphFragmentParameter
	// GraphFragmentSourceNode is the recursive data-flow provenance node, mirroring
	// the schema-6.0 exportSourceNode shape. The SourceNodes field makes this type
	// recursive so PARAMETER→CALL_RESULT chains are fully preserved.
	GraphFragmentSourceNode = enginegraphfrag.GraphFragmentSourceNode
	// GraphFragmentSourceLoc identifies a position in source code.
	GraphFragmentSourceLoc = enginegraphfrag.GraphFragmentSourceLoc
	// GraphFragmentCryptoCall carries the identity and argument data-flow of the
	// matched crypto invocation, mirroring the schema-6.0 callGraphCalledFunction
	// shape. It is a dedicated type (not reusing GraphFragmentCallSite) so it can
	// carry function identity fields alongside the call-site parameters.
	GraphFragmentCryptoCall = enginegraphfrag.GraphFragmentCryptoCall
	// GraphFragmentRoleProvenance explains where a method_role came from: a
	// direct contract match, or inherited from same-class sibling assets
	// (issue-103 WU2).
	GraphFragmentRoleProvenance = enginegraphfrag.GraphFragmentRoleProvenance
	// GraphFragmentInheritedRole carries the algorithm_family/primitive a
	// synthesized operation entry point inherited from a same-class sibling asset.
	GraphFragmentInheritedRole = enginegraphfrag.GraphFragmentInheritedRole
	// GraphFragmentParameterRole is one index-aligned parameter role/contribution
	// entry (issue-103 WU3).
	GraphFragmentParameterRole = enginegraphfrag.GraphFragmentParameterRole
	// GraphFragmentContribution names the property a parameter contributes to
	// and the derivation strategy a downstream consumer applies.
	GraphFragmentContribution = enginegraphfrag.GraphFragmentContribution
	// GraphFragmentMatchedOp records the matched operation kind, symbol, and
	// expression for a crypto finding — the same fields carried by the schema-6.0
	// matched_operation shape.
	GraphFragmentMatchedOp = enginegraphfrag.GraphFragmentMatchedOp
	// GraphFragmentEdge is one internal (intra-component) call edge plus the
	// resolution metadata that lets a consumer decide whether to traverse it.
	GraphFragmentEdge = enginegraphfrag.GraphFragmentEdge
	// GraphFragmentExternal is one external (cross-component) call edge plus its
	// resolution metadata.
	GraphFragmentExternal = enginegraphfrag.GraphFragmentExternal
	// GraphFragmentCryptoOp is one crypto finding annotation attached to a function
	// in the exported graph fragment.
	GraphFragmentCryptoOp = enginegraphfrag.GraphFragmentCryptoOp
	// GraphFragmentSupporting is a non-finding crypto-adjacent call such as
	// builder/config/lifecycle/context setup. It is useful for reachability context
	// but must not inflate crypto finding counts.
	GraphFragmentSupporting = enginegraphfrag.GraphFragmentSupporting
	// GraphFragmentCryptoEntryPoint is the catalog/customer stitch index: if a
	// caller reaches this function key (or one of its aliases), these findings and
	// supporting calls become reachable.
	GraphFragmentCryptoEntryPoint = enginegraphfrag.GraphFragmentCryptoEntryPoint
	// GraphFragmentReachableFinding is a finding reachable from an entrypoint.
	GraphFragmentReachableFinding = enginegraphfrag.GraphFragmentReachableFinding
	// GraphFragmentReachableSupportingCall is a supporting call reachable from an
	// entrypoint.
	GraphFragmentReachableSupportingCall = enginegraphfrag.GraphFragmentReachableSupportingCall
	// FindingsEnvelope is the findings.json envelope reconstructed from a
	// dependency closure of graph fragments. It is the asset-metadata companion to
	// ToCallgraphExport: consumers join assets (here) to call chains (callgraph
	// export) by finding_id, so the two MUST agree on finding_id — which they do by
	// construction, since both derive it from the same CryptoOperation fields via
	// computeFindingID/depPrefixedPath.
	FindingsEnvelope = enginegraphfrag.FindingsEnvelope
	// FindingFile is one file-level grouping in the envelope, mirroring a
	// findings.json `findings[]` entry.
	FindingFile = enginegraphfrag.FindingFile
	// FindingAsset is one cryptographic asset, mirroring a findings.json
	// `cryptographic_assets[]` entry. Metadata is the verbatim camelCase block.
	FindingAsset = enginegraphfrag.FindingAsset
	// ExportInternedFunction is one identity record in the functions[] catalog.
	// Schema 6.15+ keeps this as the join surface for call-chain frames; hop-specific
	// fields (entry_call, crypto_call, entry_resolution) stay on the frames.
	ExportInternedFunction = enginegraphfrag.ExportInternedFunction
	// FrameIdentity is the intern key and catalog payload for one call-chain frame.
	FrameIdentity = enginegraphfrag.FrameIdentity
	// FunctionInterner assigns stable 0-based indexes to frame identities in first-
	// seen order. Live export and stitch share this so the same N-sample of routes
	// intern the same way.
	FunctionInterner = enginegraphfrag.FunctionInterner
	// ComponentKey identifies one mined component version.
	ComponentKey = enginegraphfrag.ComponentKey
	// DependencyGraph is the authoritative component-version graph resolved from
	// build metadata. Stitching only crosses into components reachable through this
	// graph, even if extra fragments are available in storage.
	DependencyGraph = enginegraphfrag.DependencyGraph
	// Fragment is one reusable structural graph fragment plus rules-versioned
	// crypto annotations for a single component version. The production storage
	// layer may split this into structural graph blobs and separate crypto
	// annotation blobs, but the stitcher consumes the combined view.
	Fragment = enginegraphfrag.Fragment
	// Function identifies one callable node inside a component graph.
	//
	// The Signature field (the fragment's function key, e.g. "org.bridge.(Bridge).bridge#0")
	// is the join key for edge resolution. The richer identity fields below are
	// populated from graph-fragment-1.2+ exports so the stitcher can emit them
	// verbatim in the schema-6.0 output (callgraph_export.go). They are zero-value
	// on legacy 1.0/1.1 fragments — graceful degradation.
	Function = enginegraphfrag.Function
	// CallSite carries the per-edge call-site invocation detail: the line number and
	// the resolved argument data-flow for each positional argument passed by the
	// caller at this edge. Mirrors the schema-6.0 entry_call shape.
	CallSite = enginegraphfrag.CallSite
	// Parameter is one positional argument at a call site, including any resolved
	// data-flow provenance. Mirrors the schema-6.0 callGraphParameter shape.
	Parameter = enginegraphfrag.Parameter
	// SourceNode is one node in the data-flow provenance graph. The SourceNodes
	// field makes this type recursive so PARAMETER→CALL_RESULT chains are fully
	// preserved. Mirrors the schema-6.0 exportSourceNode shape.
	SourceNode = enginegraphfrag.SourceNode
	// SourceLocation identifies a position in source code.
	SourceLocation = enginegraphfrag.SourceLocation
	// CryptoCall carries the identity and call-site argument data-flow of a matched
	// invocation. It is stored on CryptoOperation (1.2+) and mirrors the schema-6.0
	// callGraphCalledFunction shape. ResolvedKeyLength is populated only when this
	// shared shape is nested under a structurally derived supporting call.
	CryptoCall = enginegraphfrag.CryptoCall
	// SourceCallRef identifies the call-site argument that produced derived
	// callgraph evidence. ParameterIndex is zero-based.
	SourceCallRef = enginegraphfrag.SourceCallRef
	// ResolvedKeyLength is raw key-size evidence derived from a contract-marked
	// integer parameter. Bits is absent when the value is unresolved.
	ResolvedKeyLength = enginegraphfrag.ResolvedKeyLength
	// RoleProvenance explains where a method_role came from: a direct contract
	// match, or inherited from same-class sibling assets (issue-103 WU2).
	RoleProvenance = enginegraphfrag.RoleProvenance
	// InheritedRole carries the algorithm_family/primitive a synthesized
	// operation entry point inherited from a same-class sibling asset.
	InheritedRole = enginegraphfrag.InheritedRole
	// ParameterRole is one index-aligned parameter role/contribution entry
	// (issue-103 WU3).
	ParameterRole = enginegraphfrag.ParameterRole
	// Contribution names the property a parameter contributes to and the
	// derivation strategy a downstream consumer applies.
	Contribution = enginegraphfrag.Contribution
	// MatchedOp records the matched operation kind, symbol, and expression for a
	// crypto finding — the same fields carried by the schema-6.0 matched_operation.
	MatchedOp = enginegraphfrag.MatchedOp
	// InternalEdge connects two functions inside the same component fragment.
	//
	// Internal edges carry the same resolution metadata as ExternalCall: an
	// interface or fluent call resolved by name+arity can land on a co-located
	// implementation just as easily as a cross-component one, so it must be gated
	// by the same policy. The dispatch-group identity (Caller + CallSite +
	// MethodName + Arity) is shared with ExternalCall so that siblings of one call
	// site that span the component boundary are judged together.
	InternalEdge = enginegraphfrag.InternalEdge
	// ResolutionKind classifies how confidently the producer resolved a call to its
	// target. The stitcher uses this to decide whether an edge is allowed to extend
	// a reachability chain. The zero value is ResolutionUnknown, which is treated as
	// untrusted: the stitcher fails closed rather than guessing.
	//
	// This is the central guard against over-broad dispatch false positives. An
	// interface or fluent call resolved purely by method name + arity (no receiver
	// type anchor) must never be presented as typed reachability proof.
	ResolutionKind = enginegraphfrag.ResolutionKind
	// ExternalCall is a call from this component to a function whose implementation
	// may live in another component from the dependency graph.
	ExternalCall = enginegraphfrag.ExternalCall
	// CryptoOperation is a crypto finding attached to a function.
	//
	// The rich fields (CryptoCall, OID, Metadata, Source, MatchedOperation) are
	// populated from graph-fragment-1.2+ exports. They are zero/nil on legacy
	// fragments — the stitcher still emits structural chains, just without
	// data-flow / asset metadata (safe degradation).
	CryptoOperation = enginegraphfrag.CryptoOperation
	// SupportingCall is a non-finding crypto-adjacent call carried as context for
	// reachability. It is intentionally separate from CryptoOperation so config and
	// lifecycle calls do not inflate finding counts.
	SupportingCall = enginegraphfrag.SupportingCall
	// CryptoEntryPoint is the decoded entrypoint/stitch projection from
	// graph-fragment-1.3.
	CryptoEntryPoint = enginegraphfrag.CryptoEntryPoint
	// ReachableFinding links an entrypoint to a reachable terminal finding.
	ReachableFinding = enginegraphfrag.ReachableFinding
	// ReachableSupportingCall links an entrypoint to a reachable supporting call.
	ReachableSupportingCall = enginegraphfrag.ReachableSupportingCall
	// Result is the stitched reachability output in its minimal semantic form.
	// Rendering into crypto-finder's customer-facing callgraph schema is a later
	// adapter concern.
	Result = enginegraphfrag.Result
	// FindingChain is one root-to-crypto path.
	FindingChain = enginegraphfrag.FindingChain
	// SuppressedEdge is one call edge (or grouped call site) the stitcher declined
	// to traverse, with the reason and the candidate targets it would have reached.
	SuppressedEdge = enginegraphfrag.SuppressedEdge
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
	CallFrame = enginegraphfrag.CallFrame
	// ErrMissingFragment means the dependency closure references components whose
	// graph fragments are absent. The stitcher fails closed instead of returning a
	// partial graph.
	ErrMissingFragment = enginegraphfrag.ErrMissingFragment
	// StitchOptions tunes which root-fragment functions a stitch traces from. The
	// zero value reproduces the historical Stitch behavior (trace from every
	// root-fragment function), so adding fields here never changes existing callers.
	StitchOptions = enginegraphfrag.StitchOptions
)

const (
	// CallgraphSchemaVersion is the inlined callgraph contract and the zero-value
	// SDK/stitch default. Local CLI exports default to the interned 6.18 contract;
	// --export-callgraph-interned-frames=false selects this compatibility render.
	// Both paths use CallgraphExportSchemaVersion to stamp the selected render.
	CallgraphSchemaVersion = enginegraphfrag.CallgraphSchemaVersion
)

const (
	// CallgraphInternedSchemaVersion is the interned contract: call_chains frames
	// omit catalog identity and join through functions[] plus call_chain_indexes.
	// 6.16 adds the optional scan_metadata.ecosystems list. 6.17 adds the
	// optional finding_graphs[].dependency block, analysis.paths_total,
	// paths_kept, route_evidence and no_callers_only, root_kind on a chain's first
	// frame, the stitched unresolved_reason, and the unresolved_reason values
	// traversal_truncated, unresolved_dispatch and dependency_without_source.
	// 6.18 adds a chain frame's excerpt, excerpt_unavailable, entry_rule and
	// entry_call.call_site_column.
	// 6.15 to 6.17 artifacts remain valid against their own published schemas.
	CallgraphInternedSchemaVersion = enginegraphfrag.CallgraphInternedSchemaVersion
)

// Reachability states stamped on finding_graphs[].reachability (6.8+, issue
// #242). The legacy `reachable *bool` keeps its semantics through 6.x;
// consumers should prefer this field.
const (
	// ReachabilityReachable — at least one genuinely traced call chain from
	// user code reaches the finding. The one-node self-chain fallback does
	// NOT count.
	ReachabilityReachable = enginegraphfrag.ReachabilityReachable
	// ReachabilityUnreachable — the containing function resolved and the
	// user-package universe is known, but no chain was traced and no known
	// limitation (suppression, truncation) applies.
	ReachabilityUnreachable = enginegraphfrag.ReachabilityUnreachable
	// ReachabilityUnknown — analysis could not decide: resolution was
	// suppressed or the chain search hit a cap.
	ReachabilityUnknown = enginegraphfrag.ReachabilityUnknown
	// ReachabilityNotApplicable — the question does not apply: no containing
	// function, or no user-package universe (mine/fragment-only path).
	ReachabilityNotApplicable = enginegraphfrag.ReachabilityNotApplicable
)

// Completeness states used by ExportFindingAnalysis (6.8+), reusing the
// existing complete/partial vocabulary from the ambiguity taxonomy plus
// unavailable for absent analysis.
const (
	AnalysisComplete    = enginegraphfrag.AnalysisComplete
	AnalysisPartial     = enginegraphfrag.AnalysisPartial
	AnalysisUnavailable = enginegraphfrag.AnalysisUnavailable
)

// Route evidence values of ExportFindingAnalysis.RouteEvidence.
const (
	// RouteEvidenceDirect: every call of the route resolved statically.
	RouteEvidenceDirect = enginegraphfrag.RouteEvidenceDirect
	// RouteEvidenceDispatch: the route needs at least one call linked to an
	// implementation of the receiver's declared type, and no name_only call.
	RouteEvidenceDispatch = enginegraphfrag.RouteEvidenceDispatch
	// RouteEvidenceNameOnly: every route needs a call linked only by name.
	RouteEvidenceNameOnly = enginegraphfrag.RouteEvidenceNameOnly
)

const (
	// AmbiguityComplete marks ambiguity evidence with complete call-site and candidate identities.
	AmbiguityComplete = enginegraphfrag.AmbiguityComplete
	// AmbiguityPartial marks ambiguity evidence that degraded because identity data was unavailable.
	AmbiguityPartial = enginegraphfrag.AmbiguityPartial
)

// Relationships on finding_graphs[].dependency.relationship.
const (
	// DependencyDirect is a dependency the application declares itself.
	DependencyDirect = enginegraphfrag.DependencyDirect
	// DependencyTransitive is a dependency the application reaches only
	// through another dependency.
	DependencyTransitive = enginegraphfrag.DependencyTransitive
)

const (
	// UnresolvedReasonDependencyWithoutSource says why a dependency finding is
	// unknown rather than unreachable: no call chain reaches it, and every route
	// from the application to its dependency in the dependency graph crosses a
	// dependency that joined the call graph without source code, whose calls are
	// not in the graph. Live export only: a stitch with a fragment missing fails.
	UnresolvedReasonDependencyWithoutSource = enginegraphfrag.UnresolvedReasonDependencyWithoutSource
)

// Excerpt bounds: the lines kept on each side of the focus line, and the runes
// kept of one line.
const (
	ExcerptContextLines = enginegraphfrag.ExcerptContextLines
	ExcerptLineMaxRunes = enginegraphfrag.ExcerptLineMaxRunes
)

// Reasons a chain frame carries no excerpt (ExportChainNode.ExcerptUnavailable).
const (
	// ExcerptNoSource: the frame's file is not in the scanned tree or in a
	// dependency source directory the scan resolved, such as a dependency
	// joined for its types only, or the export has no source (stitched).
	ExcerptNoSource = enginegraphfrag.ExcerptNoSource
	// ExcerptUnreadable: reading the file failed.
	ExcerptUnreadable = enginegraphfrag.ExcerptUnreadable
	// ExcerptOutOfRange: the focus line is not a line of the file.
	ExcerptOutOfRange = enginegraphfrag.ExcerptOutOfRange
)

const (
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
	//
	// 1.9 adds generic-erased function join signatures for Java source-type
	// hierarchy stitching. 1.10 adds optional occurrence_key propagation for
	// canonical crypto annotations. 1.11 adds resolved key-length call evidence.
	// 1.12 adds the rule-vs-callgraph key-length conflict marker on that evidence.
	//
	// 1.14 adds entry_kind on a function the producing scan recognized as an entry
	// point (main or framework_entry) and scan_metadata.entry_kinds, which says the
	// producer recorded entry kinds at all. The stitched export reads them to give
	// a chain root its root_kind and a finding its no_callers_only. A fragment
	// without scan_metadata.entry_kinds (1.13 and older) decodes with no entry
	// kinds and the stitcher claims neither for its functions.
	//
	// 1.15 adds returns_calls on a function: the callees of the calls whose result
	// it returns. Annotate reads it to follow a crypto object a helper returns into
	// the callers that configure it, as a scan does. A fragment without it (1.14
	// and older) decodes with no returned calls, and annotate follows none.
	SchemaVersion = enginegraphfrag.SchemaVersion
)

const (
	// GraphAlgoVersion identifies the callgraph-CONSTRUCTION algorithm version. It
	// is independent of the binary version (cf_version) and the wire schema
	// (SchemaVersion): it bumps ONLY when callgraph/inference construction changes
	// in a way that alters the structural graph. Consumers key their cached
	// structural graphs on this so a routine binary release does not invalidate the
	// cache — only a graph-affecting change does. Stamped into scan_metadata.
	// TestGraphAlgoVersionGuard fails when the structural graph changes without a
	// bump (see docs/ARCHITECTURE.md, Schema Versioning).
	//
	// graph-algo-6: Go dependencies contribute only their imported packages, on
	// top of the Go, Node and Python call resolution and Go interface dispatch
	// changes merged since graph-algo-5.
	//
	// graph-algo-7: functions carry the entry kind the scan recognized (main or
	// framework_entry), so a stitched export can give a chain root its root_kind.
	// A structural graph cached under graph-algo-6 has none.
	//
	// graph-algo-8: Python symbols are no longer prefixed with the pyproject name.
	//
	// graph-algo-9: Python standard-library contracts type the objects hashlib,
	// hmac, ssl and random.SystemRandom return, so a method chained on such a call
	// (hashlib.sha256(d).hexdigest()) resolves to its stdlib class instead of a
	// local name.
	//
	// graph-algo-10: a Node call on the WebCrypto API resolves to its WebIDL
	// interface (SubtleCrypto.encrypt, Crypto.getRandomValues) under every
	// spelling: the global crypto object, Node's crypto.webcrypto, and a subtle
	// object held in a variable. It was an unbound member named after the calling
	// module.
	//
	// graph-algo-11: a class assigned to Node exports (`module.exports = class Key
	// {..}`, `exports.Key = class {..}`) declares its methods, which were missing.
	//
	// graph-algo-12: C++ calls on an `auto` variable take the type the producing
	// call's contract returns, a direct initializer (`T v(f())`, `auto v{f()}`)
	// binds its variable, and a templated callee is recorded without its template
	// arguments (`std::make_unique<T>()` calls std::make_unique).
	//
	// graph-algo-13: a Rust call written inside a macro's parenthesized or
	// bracketed expression arguments (`println!("{:?}", f(x))`) is an edge from
	// the enclosing function.
	//
	// graph-algo-14: the default exclusions (node_modules, venv, build, ...) match
	// only directories inside the project or dependency being graphed, so npm
	// packages, packages in a virtualenv named venv and checkouts under such a
	// directory enter the graph; and a Node call made through a package name
	// (`require('pkg').fn()`, `import { fn } from 'pkg'`) is an edge to the
	// function the package's entry module exports.
	//
	// graph-algo-15: functions carry returns_calls, the calls whose result they
	// return, so annotate can follow a returned crypto object into its callers. A
	// structural graph cached under graph-algo-14 has none.
	GraphAlgoVersion = enginegraphfrag.GraphAlgoVersion
)

const (
	// FindingsSchemaVersion is the findings.json envelope version emitted by
	// ToFindingsEnvelope. It is the schema crypto-finder's scanner writes, so
	// downstream consumers see a uniform `version` regardless of whether the
	// findings came from a live scan or were reconstructed from graph fragments,
	// and can validate a scan's findings.json against it.
	FindingsSchemaVersion = enginegraphfrag.FindingsSchemaVersion
)

const (
	// ResolutionUnknown is the zero value: the producer did not classify the
	// edge. Treated as untrusted and never traversed. Its presence usually means
	// a producer bug (an edge exported without a resolution kind).
	ResolutionUnknown = enginegraphfrag.ResolutionUnknown
	// ResolutionExact means the receiver's static type was known and the method
	// resolved to a unique declared target on that type (or an overload set on
	// that exact type). Always traversed.
	ResolutionExact = enginegraphfrag.ResolutionExact
	// ResolutionInterfaceDispatch means the target was found by expanding an
	// interface/abstract method to concrete implementations matching name+arity
	// within a namespace root. Trusted ONLY when exactly one implementation is
	// present in the current component's direct dependencies; ambiguous (>1)
	// call sites fail closed.
	ResolutionInterfaceDispatch = enginegraphfrag.ResolutionInterfaceDispatch
	// ResolutionNameOnly means the target was guessed by method name + arity
	// (plus namespace heuristics) with no receiver type anchor — e.g. fluent
	// fallback. Never traversed.
	ResolutionNameOnly = enginegraphfrag.ResolutionNameOnly
)

const (
	// ConfidenceHigh is the confidence of every chain emitted under the default
	// fail-closed policy (only exact and unique-implementation interface edges are
	// traversed). The constant exists so a future opt-in mode can surface
	// lower-confidence chains explicitly.
	ConfidenceHigh = enginegraphfrag.ConfidenceHigh
)

// Suppression reasons recorded on a SuppressedEdge.
const (
	// SuppressReasonUnknown: an edge had no resolution kind (producer bug or an
	// intentionally untrusted edge).
	SuppressReasonUnknown = enginegraphfrag.SuppressReasonUnknown
	// SuppressReasonNameOnly: a name+arity guess with no receiver type anchor.
	SuppressReasonNameOnly = enginegraphfrag.SuppressReasonNameOnly
	// SuppressReasonAmbiguousDispatch: an interface call site with more than one
	// concrete implementation present in the current component's direct dependencies.
	SuppressReasonAmbiguousDispatch = enginegraphfrag.SuppressReasonAmbiguousDispatch
)

// Stitch preserves the SDK depth and sample defaults. Local CLI shares the
// depth cap but selects its own smaller export profile; callers can align
// MaxChains explicitly when comparing sampled routes across both surfaces.
const (
	DefaultMaxChainsPerOp = enginegraphfrag.DefaultMaxChainsPerOp
)

// Root kinds a stitched chain's first frame can carry (ExportChainNode.RootKind).
// They mirror the live callgraph export. The stitched export never says
// depth_limit: its walk has no depth limit.
const (
	// RootKindMain is a program entry point.
	RootKindMain = enginegraphfrag.RootKindMain
	// RootKindFrameworkEntry is a function a framework or the runtime calls.
	RootKindFrameworkEntry = enginegraphfrag.RootKindFrameworkEntry
	// RootKindNoCallers is a root-component function nothing in the stitched
	// graph calls and the producer did not recognize as an entry point.
	RootKindNoCallers = enginegraphfrag.RootKindNoCallers
)

const (
	// UnresolvedReasonDispatch is the unresolved_reason of a finding whose every
	// route crosses a name_only edge, the value the live export uses.
	UnresolvedReasonDispatch = enginegraphfrag.UnresolvedReasonDispatch
)

// CallgraphExportSchemaVersion returns the stamped schema_version for a render.
func CallgraphExportSchemaVersion(internedFrames bool) string {
	return enginegraphfrag.CallgraphExportSchemaVersion(internedFrames)
}

// ParameterCompleteness maps a resolved/total parameter count onto the 6.8
// analysis vocabulary: unavailable when nothing resolved, complete when
// everything did, partial in between. Shared by the live and stitched exports.
func ParameterCompleteness(resolved, total int) string {
	return enginegraphfrag.ParameterCompleteness(resolved, total)
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
	return enginegraphfrag.ConstructorDisplayFromSymbol(symbol)
}

// EncodeFragment renders a Fragment back to current graph-fragment wire JSON — the
// inverse of DecodeFragment for the STRUCTURAL payload (scan_metadata, functions,
// internal_edges, external_calls, including each edge's call-site object identity
// receiver_var/assigned_var/chain_id and entry_call args).
//
// It exists for consumers that cached only the rules-independent structural graph
// (e.g. the mining service's component_code_graphs) and need to materialize it as
// a graph-fragment file to feed `crypto-finder annotate --import-fragment`. The
// crypto sections (crypto_annotations, supporting_calls, crypto_entry_points) are
// intentionally NOT re-encoded: they are rules-versioned and the annotate path
// re-derives them from the structural edges, so a structural-only fragment is
// exactly what the import needs.
func EncodeFragment(frag Fragment) ([]byte, error) {
	return enginegraphfrag.EncodeFragment(frag)
}

// ToFindingsEnvelope reconstructs the findings.json envelope for the root
// component and its transitive dependency closure, from the stored crypto
// annotations in each fragment. Unlike ToCallgraphExport (which emits only
// reachable findings), this emits EVERY crypto operation in the closure —
// reachability decoration happens in the callgraph export.
//
// finding_id, file_path, and source are computed to match a live
// `--scan-dependencies` run:
//   - root-component ops: unprefixed file_path, source="direct".
//   - dependency ops: file_path prefixed with "module@version/", source="indirect".
//
// finding_id is computed with the SAME inputs as ToCallgraphExport
// (computeFindingID over the resolved path + start_line + rule_id), so the
// asset->call_chains join by finding_id holds.
func ToFindingsEnvelope(root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment, meta ScanMeta) FindingsEnvelope {
	return enginegraphfrag.ToFindingsEnvelope(root, deps, fragments, meta)
}

// DecodeFragment parses one graph-fragment export (JSON) into a Fragment for the
// given component. Legacy fragments exported before the resolution fields
// existed decode to ResolutionUnknown, which the stitcher fails closed on —
// safe under-reporting, never a false positive.
func DecodeFragment(component ComponentKey, data []byte) (Fragment, error) {
	return enginegraphfrag.DecodeFragment(component, data)
}

// IdentityFromChainNode copies interned identity fields from an inlined frame.
func IdentityFromChainNode(n ExportChainNode) FrameIdentity { //nolint:gocritic // Public SDK signature; a pointer would break callers.
	return enginegraphfrag.IdentityFromChainNode(n)
}

// ContractChainIdentities clears interned identity fields from frames so the
// catalog plus call_chain_indexes are the only copy of function identity.
func ContractChainIdentities(chains [][]ExportChainNode) {
	enginegraphfrag.ContractChainIdentities(chains)
}

// HydrateChainIdentities copies catalog identity onto frames whose function_name
// and canonical_signature are empty. Inlined 6.14 frames are left unchanged.
// An empty index list is treated as inlined (no-op, true). Returns false when
// indexes exist but do not reconstruct the same routes.
func HydrateChainIdentities(catalog []ExportInternedFunction, chains [][]ExportChainNode, indexes [][]int) bool {
	return enginegraphfrag.HydrateChainIdentities(catalog, chains, indexes)
}

// ReconstructChainIdentities rebuilds each route from catalog indexes.
func ReconstructChainIdentities(catalog []ExportInternedFunction, indexes [][]int) ([][]ExportInternedFunction, bool) {
	return enginegraphfrag.ReconstructChainIdentities(catalog, indexes)
}

// Stitch composes reusable component graph fragments into root-to-crypto
// reachability chains for root.
//
// This is the pure graph algorithm. It deliberately does not know about
// storage, compression, or HTTP response DTOs. It traces from every
// root-fragment function; for entry-point-only rooting use StitchWithOptions.
func Stitch(root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment) (*Result, error) {
	return enginegraphfrag.Stitch(root, deps, fragments)
}

// StitchWithOptions is Stitch with an explicit rooting policy. See StitchOptions.
func StitchWithOptions(root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment, opts StitchOptions) (*Result, error) {
	return enginegraphfrag.StitchWithOptions(root, deps, fragments, opts)
}

// ResolveMaxChains maps a caller-supplied emit budget onto DefaultMaxChainsPerOp
// when the value is omitted (zero) or invalid (negative).
func ResolveMaxChains(n int) int {
	return enginegraphfrag.ResolveMaxChains(n)
}
