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

	"github.com/scanoss/crypto-finder/pkg/purl"
)

// CallgraphSchemaVersion is the canonical schema_version of the callgraph
// export envelope (the `--export-callgraph` / stitch reachability format). It is
// the single source of truth for both the live CLI export (internal/scan) and
// the graph-fragment stitch path (ToCallgraphExport), so the two can never drift
// — a consumer that serves stitched output stamps the SAME version a live
// `--scan-dependencies --export-callgraph` run produces.
const CallgraphSchemaVersion = "6.11"

// Reachability states stamped on finding_graphs[].reachability (6.8+, issue
// #242). The legacy `reachable *bool` keeps its semantics through 6.x;
// consumers should prefer this field.
const (
	// ReachabilityReachable — at least one genuinely traced call chain from
	// user code reaches the finding. The one-node self-chain fallback does
	// NOT count.
	ReachabilityReachable = "reachable"
	// ReachabilityUnreachable — the containing function resolved and the
	// user-package universe is known, but no chain was traced and no known
	// limitation (suppression, truncation) applies.
	ReachabilityUnreachable = "unreachable"
	// ReachabilityUnknown — analysis could not decide: resolution was
	// suppressed or the chain search hit a cap.
	ReachabilityUnknown = "unknown"
	// ReachabilityNotApplicable — the question does not apply: no containing
	// function, or no user-package universe (mine/fragment-only path).
	ReachabilityNotApplicable = "not_applicable"
)

// Completeness states used by ExportFindingAnalysis (6.8+), reusing the
// existing complete/partial vocabulary from the ambiguity taxonomy plus
// unavailable for absent analysis.
const (
	AnalysisComplete    = "complete"
	AnalysisPartial     = "partial"
	AnalysisUnavailable = "unavailable"
)

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

// ExportFindingGraph groups all surviving chains for one crypto finding occurrence.
type ExportFindingGraph struct {
	// FindingID is the crypto finding identifier.
	FindingID string `json:"finding_id"`
	// PURL is the optional package URL promoted from a direct rule finding.
	PURL string `json:"purl,omitempty"`
	// OccurrenceKey is the optional AST-anchored structural finding identity.
	OccurrenceKey string `json:"occurrence_key,omitempty"`
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
	// ForwardCalls is the finding anchor's forward call closure (6.3+): what the
	// matched method transitively calls, with per-call-site argument data-flow.
	// Present only when the stitch ran with StitchOptions.ForwardClosure; findings
	// sharing an anchor inline the same projected content (per-anchor memo).
	ForwardCalls *ExportForwardClosure `json:"forward_calls,omitempty"`
	// Reachability is the explicit reachability state (6.8+): one of the
	// Reachability* constants. Supersedes the implicit chain-presence signal.
	Reachability string `json:"reachability,omitempty"`
	// Analysis reports call-chain and parameter completeness (6.8+).
	Analysis *ExportFindingAnalysis `json:"analysis,omitempty"`
}

// ExportFindingAnalysis reports how complete the analysis behind one finding
// graph is (6.8+). CallChains is partial when any search cap was hit or when
// ambiguous forward calls with partial completeness exist. Parameters is
// complete when every exported parameter resolves, partial when only some do,
// unavailable when none do.
type ExportFindingAnalysis struct {
	CallChains string `json:"call_chains,omitempty"`
	Parameters string `json:"parameters,omitempty"`
}

// ExportForwardClosure is the projected forward call graph from one finding
// anchor (6.3+). Nodes are deduped forward-reachable functions (depth >= 1);
// edges are the traversed call sites (endpoints in {anchor} ∪ nodes). MaxDepth
// echoes the depth CAP applied (the budget), not the deepest node reached;
// Truncated is true whenever any cap (depth/node/edge) cut the walk short.
type ExportForwardClosure struct {
	Anchor         ExportForwardAnchor          `json:"anchor"`
	MaxDepth       int                          `json:"max_depth"`
	Truncated      bool                         `json:"truncated"`
	Nodes          []ExportForwardNode          `json:"nodes,omitempty"`
	Edges          []ExportForwardEdge          `json:"edges,omitempty"`
	AmbiguousCalls []ExportAmbiguousForwardCall `json:"ambiguous_calls,omitempty"`
}

const (
	// AmbiguityComplete marks ambiguity evidence with complete call-site and candidate identities.
	AmbiguityComplete = "complete"
	// AmbiguityPartial marks ambiguity evidence that degraded because identity data was unavailable.
	AmbiguityPartial = "partial"
)

// ExportAmbiguousForwardCall is one fail-closed interface-dispatch call site.
// Its candidates are evidence, never traversed forward edges.
type ExportAmbiguousForwardCall struct {
	GroupID      string                            `json:"group_id"`
	Reason       string                            `json:"reason"`
	Completeness string                            `json:"completeness"`
	CallSite     ExportAmbiguousCallSite           `json:"call_site"`
	Candidates   []ExportAmbiguousForwardCandidate `json:"candidates"`
}

// ExportAmbiguousCallSite identifies the source invocation shared by every
// candidate in an ambiguous dispatch group.
type ExportAmbiguousCallSite struct {
	CallerFunctionKey        string `json:"caller_function_key"`
	CallerFunctionName       string `json:"caller_function_name,omitempty"`
	CallerCanonicalSignature string `json:"caller_canonical_signature,omitempty"`
	Line                     int    `json:"line,omitempty"`
	StartCol                 int    `json:"start_col,omitempty"`
	EndCol                   int    `json:"end_col,omitempty"`
	MethodName               string `json:"method_name"`
	Arity                    int    `json:"arity"`
}

// ExportAmbiguousForwardCandidate is one possible target for an ambiguous
// dispatch. EntryCall carries the candidate-aligned argument/provenance data.
type ExportAmbiguousForwardCandidate struct {
	CandidateID        string                `json:"candidate_id"`
	FunctionKey        string                `json:"function_key"`
	FunctionName       string                `json:"function_name,omitempty"`
	CanonicalSignature string                `json:"canonical_signature,omitempty"`
	DeclaringType      string                `json:"declaring_type,omitempty"`
	ReturnType         string                `json:"return_type,omitempty"`
	ParameterTypes     []string              `json:"parameter_types"`
	DependencyInfo     *ExportDependencyInfo `json:"dependency_info,omitempty"`
	EntryCall          *ExportEntryCall      `json:"entry_call,omitempty"`
}

// ExportForwardAnchor is the lean identity of the forward closure's root: the
// finding's own function. File path and dependency identity already live on
// the finding itself and are not repeated here.
type ExportForwardAnchor struct {
	FunctionKey   string `json:"function_key"`
	FunctionName  string `json:"function_name,omitempty"`
	DisplaySymbol string `json:"display_symbol,omitempty"`
}

// ExportForwardNode is one forward-reachable function in the closure.
type ExportForwardNode struct {
	FunctionKey        string                `json:"function_key"`
	FunctionName       string                `json:"function_name,omitempty"`
	DisplaySymbol      string                `json:"display_symbol,omitempty"`
	FilePath           string                `json:"file_path,omitempty"`
	DependencyInfo     *ExportDependencyInfo `json:"dependency_info,omitempty"`
	Depth              int                   `json:"depth"`
	CryptoRelevant     bool                  `json:"crypto_relevant,omitempty"`
	SupportingCategory string                `json:"supporting_category,omitempty"`
}

// ExportForwardEdge is one traversed caller→callee call site. EntryCall
// carries the call-site argument data-flow (resolved values, source nodes)
// in the same shape as chain-node entry_call.
type ExportForwardEdge struct {
	From      string           `json:"from"`
	To        string           `json:"to"`
	EntryCall *ExportEntryCall `json:"entry_call,omitempty"`
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
	PURL    string `json:"purl,omitempty"`
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
	// ParameterRoles is the issue-103 (WU3) contracts-KB-derived per-parameter
	// role/contribution list, index-aligned with ParameterTypes. Carried
	// through from the supporting-call declaration on the fragment side (WU1
	// path populates it natively); never present on call-site ExportParameter.
	ParameterRoles []ExportParameterRole `json:"parameter_roles,omitempty"`
	// ResolvedKeyLength is contract-scoped raw key-length evidence. Bits is
	// omitted when analysis could not resolve the source argument.
	ResolvedKeyLength *ResolvedKeyLength `json:"resolved_key_length,omitempty"`
}

// ExportRoleProvenance explains where a method_role came from: a direct
// contract match, or inherited from same-class sibling assets (issue-103 WU2).
type ExportRoleProvenance struct {
	Kind               string               `json:"kind,omitempty"`
	ContractMethod     string               `json:"contract_method,omitempty"`
	InheritedFrom      string               `json:"inherited_from,omitempty"`
	Inherited          *ExportInheritedRole `json:"inherited,omitempty"`
	InheritedAmbiguous bool                 `json:"inherited_ambiguous,omitempty"`
}

// ExportInheritedRole carries the algorithm_family/primitive a synthesized
// operation entry point inherited from a same-class sibling asset.
type ExportInheritedRole struct {
	AlgorithmFamily string `json:"algorithm_family,omitempty"`
	Primitive       string `json:"primitive,omitempty"`
}

// ExportParameterRole is one index-aligned parameter role/contribution entry
// (issue-103 WU3).
type ExportParameterRole struct {
	Index       int                 `json:"index"`
	Name        string              `json:"name,omitempty"`
	Role        string              `json:"role"`
	Contributes *ExportContribution `json:"contributes,omitempty"`
}

// ExportContribution names the property a parameter contributes to and the
// derivation strategy a downstream consumer applies.
type ExportContribution struct {
	Property   string `json:"property,omitempty"`
	Derivation string `json:"derivation,omitempty"`
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
	// ErasedSignature is the generics-erased join form (6.8+): generic
	// arguments stripped, type variables replaced by their erased bounds.
	ErasedSignature string `json:"erased_signature,omitempty"`
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
	// MethodRole, RoleProvenance, ParameterRoles are issue-103 (WU2/WU3)
	// additions. On the served path they are populated either natively (the
	// entry point already existed via the reachability projection) or by the
	// stitch-time by-function_key merge that enriches it from the fragment's
	// carried-through operation-entry data (see stitch.go).
	MethodRole     string                `json:"method_role,omitempty"`
	RoleProvenance *ExportRoleProvenance `json:"role_provenance,omitempty"`
	ParameterRoles []ExportParameterRole `json:"parameter_roles,omitempty"`
	// Root marks a chain root (6.8+): the first root-module caller in
	// dependency mode or an in-degree-zero graph root in standalone mode. The
	// entry-point index is deliberately broader (every function on any chain);
	// this flag is the explicit root classification.
	Root bool `json:"root,omitempty"`
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
	ErasedSignature    string                  `json:"erased_signature,omitempty"`
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

	// Group chains by finding ID and optional occurrence key.
	type findingKey struct {
		findingID     string
		occurrenceKey string
	}
	type chainGroup struct {
		findingID         string
		occurrenceKey     string
		purl              string
		purlConflict      bool
		matchedOp         *ExportMatchedOperation
		supportingCallIDs []string
		callChains        [][]ExportChainNode
		// anchorNode is the finding's terminal (crypto op) node — the key into
		// Result.forwardClosures. Captured from the first chain's terminal frame;
		// all chains of one finding share the same terminal op node.
		anchorNode graphNode
	}
	groupMap := make(map[findingKey]*chainGroup)
	var groupOrder []findingKey

	for i := range r.Chains {
		fc := &r.Chains[i]
		nodes, resolvedFindingID := buildExportChain(fc, root, meta.Ecosystem)
		// Use the resolved (potentially dep-prefixed) finding_id as the group key.
		// For root-component ops the resolved ID equals the original; for dep ops it
		// is recomputed with the "module@version/" prefix to match live --scan-dependencies.
		// When computeFindingID returned "" (legacy fragments with no FilePath/StartLine),
		// fall back to the original FindingChain.FindingID so the chain is still emitted.
		if resolvedFindingID == "" {
			resolvedFindingID = fc.FindingID
		}
		key := findingKey{findingID: resolvedFindingID, occurrenceKey: chainOccurrenceKey(fc)}
		grp, exists := groupMap[key]
		if !exists {
			grp = &chainGroup{
				findingID:         resolvedFindingID,
				occurrenceKey:     key.occurrenceKey,
				matchedOp:         chainMatchedOp(fc),
				supportingCallIDs: chainSupportingCallIDs(fc),
				purl:              directFindingPURL(fc, root),
			}
			if last := len(fc.Frames) - 1; last >= 0 {
				grp.anchorNode = graphNode{
					Component: fc.Frames[last].Component,
					Function:  fc.Frames[last].Signature,
				}
			}
			groupMap[key] = grp
			groupOrder = append(groupOrder, key)
		}
		// All chains for one finding share the same terminal crypto op; fill the
		// FK from the first chain that carries it (legacy/empty fragments → nil).
		if len(grp.supportingCallIDs) == 0 {
			grp.supportingCallIDs = chainSupportingCallIDs(fc)
		}
		mergeDirectFindingPURL(&grp.purl, &grp.purlConflict, directFindingPURL(fc, root))
		if len(nodes) > 0 {
			grp.callChains = append(grp.callChains, nodes)
		}
	}

	sort.Slice(groupOrder, func(i, j int) bool {
		if groupOrder[i].findingID != groupOrder[j].findingID {
			return groupOrder[i].findingID < groupOrder[j].findingID
		}
		return groupOrder[i].occurrenceKey < groupOrder[j].occurrenceKey
	})

	// anchorByFinding maps each emitted finding to its crypto-op node. The
	// reachability sets are keyed by that node, not by finding_id, because
	// dependency finding_ids are recomputed with a module prefix here.
	anchorByFinding := make(map[string]graphNode, len(groupOrder))

	for _, key := range groupOrder {
		grp := groupMap[key]
		fg := ExportFindingGraph{
			FindingID:         grp.findingID,
			PURL:              grp.purl,
			OccurrenceKey:     grp.occurrenceKey,
			MatchedOperation:  grp.matchedOp,
			SupportingCallIDs: grp.supportingCallIDs,
			CallChains:        grp.callChains,
		}
		anchorByFinding[grp.findingID] = grp.anchorNode
		if r.forwardClosures != nil {
			fg.ForwardCalls = projectForwardClosure(r.forwardClosures[grp.anchorNode], root, meta.Ecosystem)
		}
		fg.Reachability = stitchedReachability(fg.CallChains, len(r.Suppressed) > 0)
		fg.Analysis = stitchedFindingAnalysis(&fg)
		r.upgradeComposedReachability(&fg)
		out.FindingGraphs = append(out.FindingGraphs, fg)
	}

	out.SupportingCalls = exportSupportingCalls(r.SupportingCalls)
	// The reachability-derived index already knows every reaching function and
	// which of them are roots, so it needs neither a chain fold nor a chain-head
	// root scan (issue #249).
	out.CryptoEntryPoints = buildEntryPointsFromReach(
		r.reachByAnchor, anchorByFinding, root, meta.Ecosystem,
		out.FindingGraphs, out.SupportingCalls)
	out.CryptoEntryPoints = mergeOperationEntryPoints(out.CryptoEntryPoints, r.operationEntryPoints)
	out.CryptoEntryPoints = appendComposedEntryPoints(out.CryptoEntryPoints, r.composedEntryPoints, r.composedRoots)
	for i := range out.CryptoEntryPoints {
		out.CryptoEntryPoints[i].ErasedSignature = r.erasedByFunctionKey[out.CryptoEntryPoints[i].FunctionKey]
	}
	for i := range out.SupportingCalls {
		out.SupportingCalls[i].ErasedSignature = r.erasedByFunctionKey[out.SupportingCalls[i].FunctionKey]
	}
	return out
}

// directFindingPURL keeps package URLs out of dependency-origin projections.
// A fragment may be mined standalone and later stitched as a dependency; only
// the root component's direct findings may expose the top-level field.
func directFindingPURL(fc *FindingChain, root ComponentKey) string {
	if fc == nil || fc.CryptoOp == nil || len(fc.Frames) == 0 {
		return ""
	}
	last := fc.Frames[len(fc.Frames)-1]
	if last.Component != root {
		return ""
	}
	return fc.CryptoOp.PURL
}

func mergeDirectFindingPURL(current *string, conflict *bool, purlValue string) {
	if purlValue == "" {
		return
	}
	if *current == "" {
		if !*conflict {
			*current = purlValue
		}
		return
	}
	if *current != purlValue {
		*current = ""
		*conflict = true
	}
}

// upgradeComposedReachability marks a finding proven through a composed
// dependency entry point as reachable. The chain itself is summarized (depth
// only), not materialized frame by frame, so call-chain analysis is partial.
func (r *Result) upgradeComposedReachability(fg *ExportFindingGraph) {
	if fg.Reachability == ReachabilityReachable {
		return
	}
	if _, ok := r.composedFindingDepths[composedFindingKey(fg.FindingID)]; !ok {
		return
	}
	fg.Reachability = ReachabilityReachable
	if fg.Analysis != nil {
		fg.Analysis.CallChains = AnalysisPartial
	}
}

// composedFindingKey strips a "module@version/" dependency prefix so composed
// depth lookups match the dependency-local finding IDs carried by fragment
// entry points.
func composedFindingKey(findingID string) string {
	if slash := strings.LastIndex(findingID, "/"); slash >= 0 {
		return findingID[slash+1:]
	}
	return findingID
}

// appendComposedEntryPoints folds the composed root-component entry points into
// the served index. An already-present function_key keeps its traced entry (the
// stitched trace is more precise); new keys are appended and the index is
// re-sorted for deterministic output.
func appendComposedEntryPoints(built []ExportCryptoEntryPoint, composed []CryptoEntryPoint, roots map[string]bool) []ExportCryptoEntryPoint {
	if len(composed) == 0 {
		return built
	}
	present := make(map[string]bool, len(built))
	for i := range built {
		present[built[i].FunctionKey] = true
	}
	for i := range composed {
		ep := &composed[i]
		if present[ep.FunctionKey] {
			continue
		}
		exported := ExportCryptoEntryPoint{
			FunctionKey:        ep.FunctionKey,
			FunctionName:       ep.FunctionName,
			CanonicalSignature: ep.CanonicalSignature,
			Class:              ownerFromFunctionName(ep.FunctionName),
			Method:             simpleMethodName(ep.FunctionName),
			ReturnType:         ep.ReturnType,
			ParameterTypes:     append([]string(nil), ep.ParameterTypes...),
			Visibility:         ep.Visibility,
			OwnerVisibility:    ep.OwnerVisibility,
			DisplaySymbol:      ep.DisplaySymbol,
			Aliases:            append([]string(nil), ep.Aliases...),
			Root:               roots[ep.FunctionKey],
		}
		for _, rf := range ep.ReachableFindings {
			exported.ReachableFindings = append(exported.ReachableFindings, ExportReachableFinding{
				FindingID:       rf.FindingID,
				ChainDepth:      rf.ChainDepth,
				FindingGraphRef: rf.FindingGraphRef,
			})
		}
		for _, sc := range ep.ReachableSupportingCalls {
			exported.ReachableSupportingCalls = append(exported.ReachableSupportingCalls, ExportReachableSupportingCall(sc))
		}
		built = append(built, exported)
	}
	sort.Slice(built, func(i, j int) bool { return built[i].FunctionKey < built[j].FunctionKey })
	return built
}

// ownerFromFunctionName returns everything before the final ".segment" of a
// fully qualified function name, mirroring the class field of traced entries.
func ownerFromFunctionName(functionName string) string {
	if dot := strings.LastIndex(functionName, "."); dot > 0 {
		return functionName[:dot]
	}
	return ""
}

func simpleMethodName(functionName string) string {
	if dot := strings.LastIndex(functionName, "."); dot >= 0 {
		return functionName[dot+1:]
	}
	return functionName
}

// stitchedReachability classifies one finding graph's reachability state.
// A genuinely traced chain has at least two frames; the one-node self-chain
// fallback does not count. When nothing genuine was traced, any fail-closed
// suppression in the stitch means the negative cannot be proven — unknown —
// while a suppression-free stitch proves unreachable.
func stitchedReachability(chains [][]ExportChainNode, anySuppressed bool) string {
	for _, chain := range chains {
		if len(chain) >= 2 {
			return ReachabilityReachable
		}
	}
	if anySuppressed {
		return ReachabilityUnknown
	}
	return ReachabilityUnreachable
}

// stitchedFindingAnalysis reports completeness for one finding graph.
func stitchedFindingAnalysis(fg *ExportFindingGraph) *ExportFindingAnalysis {
	resolved, total := countStitchedParameters(fg.CallChains)
	return &ExportFindingAnalysis{
		CallChains: forwardClosureCompleteness(fg.ForwardCalls),
		Parameters: ParameterCompleteness(resolved, total),
	}
}

// forwardClosureCompleteness is partial when the forward walk hit a cap or any
// ambiguous dispatch group carries partial evidence; complete otherwise.
func forwardClosureCompleteness(fc *ExportForwardClosure) string {
	if fc == nil {
		return AnalysisComplete
	}
	if fc.Truncated {
		return AnalysisPartial
	}
	for i := range fc.AmbiguousCalls {
		if fc.AmbiguousCalls[i].Completeness == AmbiguityPartial {
			return AnalysisPartial
		}
	}
	return AnalysisComplete
}

func countStitchedParameters(chains [][]ExportChainNode) (resolved, total int) {
	for _, chain := range chains {
		for i := range chain {
			if chain[i].EntryCall == nil {
				continue
			}
			for j := range chain[i].EntryCall.Parameters {
				p := &chain[i].EntryCall.Parameters[j]
				total++
				if p.ResolvedValue != "" || len(p.SourceNodes) > 0 {
					resolved++
				}
			}
		}
	}
	return resolved, total
}

// ParameterCompleteness maps a resolved/total parameter count onto the 6.8
// analysis vocabulary: unavailable when nothing resolved, complete when
// everything did, partial in between. Shared by the live and stitched exports.
func ParameterCompleteness(resolved, total int) string {
	switch {
	case total == 0 || resolved == 0:
		return AnalysisUnavailable
	case resolved == total:
		return AnalysisComplete
	default:
		return AnalysisPartial
	}
}

// mergeOperationEntryPoints folds role-bearing fragment crypto_entry_points into
// reachability-projected entry points by function_key. Only entries already
// present are enriched; operation-only catalog entries with no reachable finding
// are ignored. The result is re-sorted by function_key to preserve deterministic
// ordering. Returns the input unchanged when no fragment carried role data.
func mergeOperationEntryPoints(built []ExportCryptoEntryPoint, carried map[string][]CryptoEntryPoint) []ExportCryptoEntryPoint {
	if len(carried) == 0 {
		return built
	}

	present := make(map[string]int, len(built))
	for i := range built {
		present[built[i].FunctionKey] = i
	}

	for key, eps := range carried {
		idx, ok := present[key]
		if !ok {
			continue
		}
		for i := range eps {
			enrichEntryPointRoles(&built[idx], &eps[i])
		}
	}

	sort.Slice(built, func(i, j int) bool {
		return built[i].FunctionKey < built[j].FunctionKey
	})
	return built
}

// enrichEntryPointRoles copies role data onto an existing export entry without
// clobbering fields the reachability projection already set.
func enrichEntryPointRoles(dst *ExportCryptoEntryPoint, src *CryptoEntryPoint) {
	if dst.MethodRole == "" {
		dst.MethodRole = src.MethodRole
	}
	if dst.RoleProvenance == nil {
		dst.RoleProvenance = exportRoleProvenance(src.RoleProvenance)
	}
	if len(dst.ParameterRoles) == 0 {
		dst.ParameterRoles = exportParameterRoles(src.ParameterRoles)
	}
}

func exportRoleProvenance(src *RoleProvenance) *ExportRoleProvenance {
	if src == nil {
		return nil
	}
	rp := &ExportRoleProvenance{
		Kind:               src.Kind,
		ContractMethod:     src.ContractMethod,
		InheritedFrom:      src.InheritedFrom,
		InheritedAmbiguous: src.InheritedAmbiguous,
	}
	if src.Inherited != nil {
		rp.Inherited = &ExportInheritedRole{
			AlgorithmFamily: src.Inherited.AlgorithmFamily,
			Primitive:       src.Inherited.Primitive,
		}
	}
	return rp
}

func exportParameterRoles(src []ParameterRole) []ExportParameterRole {
	if len(src) == 0 {
		return nil
	}
	out := make([]ExportParameterRole, len(src))
	for i := range src {
		out[i] = ExportParameterRole{
			Index: src[i].Index,
			Name:  src[i].Name,
			Role:  src[i].Role,
		}
		if src[i].Contributes != nil {
			out[i].Contributes = &ExportContribution{
				Property:   src[i].Contributes.Property,
				Derivation: src[i].Contributes.Derivation,
			}
		}
	}
	return out
}

// projectForwardClosure converts one internal forwardClosure into its export
// shape. Nodes are sorted by (function_key, component purl) and edges by
// (from, to, line) — a projection-time ordering deliberately decoupled from
// BFS traversal order so golden output stays stable across refactors.
// Returns nil for a nil closure (finding whose anchor has no computed closure).
func projectForwardClosure(fc *forwardClosure, root ComponentKey, ecosystem string) *ExportForwardClosure {
	if fc == nil {
		return nil
	}
	out := &ExportForwardClosure{
		Anchor: ExportForwardAnchor{
			FunctionKey:   fc.anchor.Function.Signature,
			FunctionName:  fc.anchor.Function.FunctionName,
			DisplaySymbol: fc.anchor.Function.DisplaySymbol,
		},
		MaxDepth:  fc.maxDepth,
		Truncated: fc.truncated,
	}

	// calleeFns resolves an edge's `to` endpoint to its rich Function identity
	// for entry_call projection (mirrors how backward frames stamp the callee).
	calleeFns := map[graphNode]Function{
		{Component: fc.anchor.Component, Function: fc.anchor.Signature}: fc.anchor.Function,
	}

	nodes := make([]ExportForwardNode, 0, len(fc.nodes))
	for i := range fc.nodes {
		n := &fc.nodes[i]
		calleeFns[n.node] = n.frame.Function
		en := ExportForwardNode{
			FunctionKey:        n.frame.Function.Signature,
			FunctionName:       n.frame.Function.FunctionName,
			DisplaySymbol:      n.frame.Function.DisplaySymbol,
			FilePath:           n.frame.Function.FilePath,
			Depth:              n.depth,
			CryptoRelevant:     n.cryptoRelevant,
			SupportingCategory: n.supportingCategory,
		}
		if n.frame.Component != root {
			en.DependencyInfo = exportDependencyInfo(&n.frame, ecosystem)
		}
		nodes = append(nodes, en)
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].FunctionKey != nodes[j].FunctionKey {
			return nodes[i].FunctionKey < nodes[j].FunctionKey
		}
		return nodes[i].FilePath < nodes[j].FilePath
	})
	out.Nodes = nodes

	edges := make([]ExportForwardEdge, 0, len(fc.edges))
	for i := range fc.edges {
		e := &fc.edges[i]
		edges = append(edges, ExportForwardEdge{
			From:      e.from.Function,
			To:        e.to.Function,
			EntryCall: exportEntryCall(e.entryCall, calleeFns[e.to]),
		})
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].To != edges[j].To {
			return edges[i].To < edges[j].To
		}
		li, lj := 0, 0
		if edges[i].EntryCall != nil {
			li = edges[i].EntryCall.Line
		}
		if edges[j].EntryCall != nil {
			lj = edges[j].EntryCall.Line
		}
		return li < lj
	})
	out.Edges = edges
	out.AmbiguousCalls = projectAmbiguousCalls(fc.ambiguous, root, ecosystem)

	return out
}

func projectAmbiguousCalls(groups []SuppressedEdge, root ComponentKey, ecosystem string) []ExportAmbiguousForwardCall {
	out := make([]ExportAmbiguousForwardCall, 0, len(groups))
	for i := range groups {
		group := &groups[i]
		groupID := ambiguityID("group", group.Caller.Component.String(), group.Caller.Signature,
			strconv.Itoa(group.CallSite), strconv.Itoa(group.StartCol), strconv.Itoa(group.EndCol), group.MethodName, strconv.Itoa(group.Arity))
		exported := ExportAmbiguousForwardCall{
			GroupID: groupID,
			Reason:  group.Reason,
			CallSite: ExportAmbiguousCallSite{
				CallerFunctionKey:        group.Caller.Signature,
				CallerFunctionName:       group.Caller.Function.FunctionName,
				CallerCanonicalSignature: group.Caller.Function.CanonicalSignature,
				Line:                     group.CallSite,
				StartCol:                 group.StartCol,
				EndCol:                   group.EndCol,
				MethodName:               group.MethodName,
				Arity:                    group.Arity,
			},
		}
		frames := append([]CallFrame(nil), group.CandidateFrames...)
		sort.Slice(frames, func(i, j int) bool {
			a, b := frames[i], frames[j]
			if a.Function.CanonicalSignature != b.Function.CanonicalSignature {
				return a.Function.CanonicalSignature < b.Function.CanonicalSignature
			}
			if a.Signature != b.Signature {
				return a.Signature < b.Signature
			}
			return a.Component.String() < b.Component.String()
		})
		for j := range frames {
			frame := &frames[j]
			parameterTypes := append([]string(nil), frame.Function.ParameterTypes...)
			if parameterTypes == nil {
				parameterTypes = []string{}
			}
			candidate := ExportAmbiguousForwardCandidate{
				CandidateID:        ambiguityID("candidate", groupID, frame.Component.String(), frame.Signature, frame.Function.CanonicalSignature),
				FunctionKey:        frame.Signature,
				FunctionName:       frame.Function.FunctionName,
				CanonicalSignature: frame.Function.CanonicalSignature,
				DeclaringType:      frame.Function.DeclaringType,
				ReturnType:         frame.Function.ReturnType,
				ParameterTypes:     parameterTypes,
				EntryCall:          exportEntryCall(frame.EntryCall, frame.Function),
			}
			if frame.Component != root {
				candidate.DependencyInfo = exportDependencyInfo(frame, ecosystem)
			}
			exported.Candidates = append(exported.Candidates, candidate)
		}
		exported.Completeness = ambiguityCompleteness(exported)
		out = append(out, exported)
	}
	return out
}

func ambiguityCompleteness(group ExportAmbiguousForwardCall) string {
	if !completeAmbiguousCallSite(group.CallSite) || len(group.Candidates) < 2 {
		return AmbiguityPartial
	}
	for i := range group.Candidates {
		if !completeAmbiguousCandidate(&group.Candidates[i], group.CallSite.Arity) {
			return AmbiguityPartial
		}
	}
	return AmbiguityComplete
}

func completeAmbiguousCallSite(callSite ExportAmbiguousCallSite) bool {
	return callSite.CallerFunctionKey != "" && callSite.CallerCanonicalSignature != "" &&
		callSite.Line > 0 && callSite.StartCol > 0 && callSite.EndCol > callSite.StartCol &&
		callSite.MethodName != ""
}

func completeAmbiguousCandidate(candidate *ExportAmbiguousForwardCandidate, arity int) bool {
	if candidate.FunctionKey == "" || candidate.CanonicalSignature == "" || candidate.DeclaringType == "" ||
		candidate.ReturnType == "" || candidate.EntryCall == nil || len(candidate.EntryCall.Parameters) != arity {
		return false
	}
	return len(candidate.ParameterTypes) == arity
}

func ambiguityID(kind string, parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return kind + "-" + hex.EncodeToString(h[:8])
}

// chainOccurrenceKey returns the terminal crypto operation's optional structural identity.
func chainOccurrenceKey(fc *FindingChain) string {
	if fc == nil || fc.CryptoOp == nil {
		return ""
	}
	return fc.CryptoOp.OccurrenceKey
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
func buildExportChain(fc *FindingChain, root ComponentKey, ecosystem string) ([]ExportChainNode, string) {
	nodes := make([]ExportChainNode, 0, len(fc.Frames))
	resolvedFindingID := fc.FindingID // default: use the stored (isolated-scan) ID

	for i := range fc.Frames {
		frame := &fc.Frames[i]
		node := buildExportNode(frame, root, ecosystem)
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
func buildExportNode(frame *CallFrame, root ComponentKey, ecosystem string) ExportChainNode {
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
		node.DependencyInfo = exportDependencyInfo(frame, ecosystem)
	}
	return node
}

func exportDependencyInfo(frame *CallFrame, ecosystem string) *ExportDependencyInfo {
	module := moduleFromFrame(frame)
	packageURL := purl.Dependency(ecosystem, frame.Module, frame.Component.Version)
	if frame.Module == "" && strings.HasPrefix(frame.Component.Purl, "pkg:") {
		packageURL = frame.Component.Purl
	}
	return &ExportDependencyInfo{
		Module:  module,
		Version: frame.Component.Version,
		PURL:    packageURL,
	}
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
		ParameterRoles:     exportParameterRoles(cc.ParameterRoles),
		ResolvedKeyLength:  cloneResolvedKeyLength(cc.ResolvedKeyLength),
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

func recordEPSupporting(ep *epData, support ExportSupportingCall, depth int) {
	if ep == nil || support.SupportingID == "" {
		return
	}
	existing, exists := ep.supporting[support.SupportingID]
	if exists && depth >= existing.ChainDepth {
		return
	}
	ep.supporting[support.SupportingID] = ExportReachableSupportingCall{
		SupportingID:      support.SupportingID,
		ChainDepth:        depth,
		SupportingCallRef: support.SupportingID,
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
	recordEPSupporting(ep, support, 1)
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
