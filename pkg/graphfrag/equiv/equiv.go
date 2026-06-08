// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package equiv provides a semantic equivalence diff tool for schema-6.0
// callgraph exports produced by crypto-finder.
//
// Compare takes two decoded schema-6.0 callgraph exports — A (live
// `scan --scan-dependencies --export-callgraph`) and B (graphfrag.Stitch ->
// ToCallgraphExport) — plus the suppressed edges from the same stitch run, and
// returns a DiffReport describing any differences.
//
// The comparison is SEMANTIC, not byte-equal:
//
//   - Each call_chain is canonicalized to a ChainKey (ordered slice of node
//     identities keyed by canonical_signature or function_name).
//   - EXPECTED(B) = chains(A) MINUS chains that traverse a suppressed edge.
//   - Chains in EXPECTED(B) but missing from B → MissingInB (real regressions).
//   - Chains in B not in A → ExtraInB (false synthesis).
//   - For chains present in both A and B, node fields are compared. Differences
//     in ignored fields go to KnownDivergences; others to NodeFieldMismatches.
//   - B's crypto_entry_points are validated against B's surviving chain set
//     and top-level supporting_calls.
//
// Suppression oracle (heuristic):
//
// A chain in A is considered "suppressed" (expected to be absent from B) when
// ANY adjacent caller→callee pair in the chain matches a SuppressedEdge by:
//
//	callerIdentity (canonical_signature or function_name) matches the
//	   SuppressedEdge.Caller.Signature, AND
//	the method name (derived from the callee node's function_name suffix) matches
//	   SuppressedEdge.MethodName, AND
//	SuppressedEdge.Arity == 0 OR the arity matches the callee's parameter count
//	   (when ParameterTypes is available on the callee node, else arity is not checked).
//
// The heuristic is intentionally broad on arity (0 matches any) because the
// JSON export does not always carry arity separately from the function signature.
// A future refinement can tighten this by storing suppressed edge arity on the
// chain node.
//
// Known v1 divergences (default IgnoreFields):
//
//   - "file_path": entry_call.file_path is not populated by callgraph_export.go.
//   - "inferred_return": not stored in graph-fragment-1.2, absent on all nodes.
//   - "confidence": schema-6.0 has no confidence field (internal only).
//
// These go to KnownDivergences, not NodeFieldMismatches.
package equiv

import (
	"fmt"
	"strings"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// ---------------------------------------------------------------------------
// JSON mirror types (schema-6.0 decoded form)
// ---------------------------------------------------------------------------

// CallgraphExportJSON is the decoded form of a schema-6.0 callgraph export.
// Both A (live scan) and B (stitched) are decoded into this type before
// comparison so the diff operates on a common representation.
type CallgraphExportJSON struct {
	SchemaVersion     string                       `json:"schema_version"`
	FindingGraphs     []ExportFindingGraphJSON     `json:"finding_graphs"`
	CryptoEntryPoints []ExportCryptoEntryPointJSON `json:"crypto_entry_points,omitempty"`
	SupportingCalls   []ExportSupportingCallJSON   `json:"supporting_calls,omitempty"`
}

// ExportFindingGraphJSON is one finding_graph entry in a CallgraphExportJSON.
type ExportFindingGraphJSON struct {
	FindingID         string                  `json:"finding_id"`
	SupportingCallIDs []string                `json:"supporting_call_ids,omitempty"`
	CallChains        [][]ExportChainNodeJSON `json:"call_chains,omitempty"`
}

// ExportChainNodeJSON is one node in a schema-6.0 call chain.
type ExportChainNodeJSON struct {
	FunctionKey        string   `json:"function_key,omitempty"`
	FunctionName       string   `json:"function_name"`
	CanonicalSignature string   `json:"canonical_signature,omitempty"`
	ReturnType         string   `json:"return_type,omitempty"`
	ParameterTypes     []string `json:"parameter_types,omitempty"`
	Visibility         string   `json:"visibility,omitempty"`
	OwnerVisibility    string   `json:"owner_visibility,omitempty"`
	FilePath           string   `json:"file_path,omitempty"`
}

// ExportCryptoEntryPointJSON is one crypto_entry_points entry.
type ExportCryptoEntryPointJSON struct {
	FunctionKey         string                              `json:"function_key"`
	FunctionName        string                              `json:"function_name,omitempty"`
	CanonicalSignature  string                              `json:"canonical_signature,omitempty"`
	ReachableFindings   []ExportReachableFindingJSON        `json:"reachable_findings,omitempty"`
	ReachableSupporting []ExportReachableSupportingCallJSON `json:"reachable_supporting_calls,omitempty"`
}

// ExportReachableFindingJSON is one reachable finding inside an entry point.
type ExportReachableFindingJSON struct {
	FindingID  string `json:"finding_id"`
	ChainDepth int    `json:"chain_depth"`
}

// ExportReachableSupportingCallJSON is one supporting-call reference inside a
// crypto entry point.
type ExportReachableSupportingCallJSON struct {
	SupportingID string `json:"supporting_id"`
	ChainDepth   int    `json:"chain_depth"`
}

// ExportSupportingCallJSON is one top-level supporting call.
type ExportSupportingCallJSON struct {
	SupportingID string `json:"supporting_id"`
	FunctionKey  string `json:"function_key,omitempty"`
}

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

// ChainKey is the canonical identity of one call chain. It is the ordered
// sequence of node identity strings (canonical_signature when available,
// otherwise function_name), joined by " -> ".
type ChainKey string

// FieldMismatch records a per-node field difference between A and B for the
// same chain.
type FieldMismatch struct {
	// FindingID is the finding this mismatch belongs to.
	FindingID string
	// ChainKey is the canonical chain identity.
	ChainKey ChainKey
	// NodeIdentity is the canonical identity of the mismatched node.
	NodeIdentity string
	// Field is the JSON field name that differs.
	Field string
	// AValue is the value in A.
	AValue string
	// BValue is the value in B.
	BValue string
}

// DiffReport is the result of a Compare call. A clean comparison (B fully
// reproduces A minus suppressed chains) has all slices nil or empty.
type DiffReport struct {
	// MissingInB holds chains that were expected in B (present in A and not
	// suppressed) but are absent from B. These are real regressions.
	MissingInB []ChainKey
	// ExtraInB holds chains that appear in B but are not present in A. These
	// represent false synthesis (chains the stitcher emitted that the live scan
	// did not produce).
	ExtraInB []ChainKey
	// NodeFieldMismatches records per-node field differences for chains present
	// in both A and B, for fields that are NOT in the IgnoreFields list.
	NodeFieldMismatches []FieldMismatch
	// EntryPointDivergences records crypto_entry_points entries in B that do not
	// correspond to a surviving B chain/supporting call.
	EntryPointDivergences []string
	// SupportingCallIDDivergences records finding_graph.supporting_call_ids in B
	// (the per-finding foreign key, 6.1+) that do not resolve to a top-level
	// supporting_calls entry — a dangling reference the served API would expose.
	SupportingCallIDDivergences []string
	// KnownDivergences records differences in fields that are in the IgnoreFields
	// list (default: file_path, inferred_return, confidence). These are documented
	// v1 limitations, not hard failures.
	KnownDivergences []string
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

// defaultIgnoreFields is the set of fields ignored by default in v1 because
// they are documented divergences between live and stitched exports.
var defaultIgnoreFields = []string{
	"file_path",       // entry_call.file_path not populated in callgraph_export.go
	"inferred_return", // not stored in graph-fragment-1.2
	"confidence",      // internal only, not present in schema-6.0 output
}

// Options controls the behavior of Compare.
type Options struct {
	// IgnoreFields is the set of JSON field names to treat as known divergences
	// rather than hard failures when they differ between A and B nodes.
	// When nil, defaultIgnoreFields is used. Pass an explicit empty slice to
	// disable all ignores.
	IgnoreFields []string

	// SuppressedChainKey is an optional predicate that overrides the built-in
	// suppression oracle. When non-nil it is called for each chain in A and
	// should return true if the chain should be excluded from EXPECTED(B).
	// When nil, the built-in heuristic (caller/method/arity matching against
	// suppressed SuppressedEdges) is used.
	SuppressedChainKey func(chainKey ChainKey, chain []ExportChainNodeJSON) bool
}

// ignoreSet returns the effective set of ignored fields (map for O(1) lookup).
func (o Options) ignoreSet() map[string]bool {
	src := o.IgnoreFields
	if src == nil {
		src = defaultIgnoreFields
	}
	m := make(map[string]bool, len(src))
	for _, f := range src {
		m[f] = true
	}
	return m
}

// ---------------------------------------------------------------------------
// Core API
// ---------------------------------------------------------------------------

// Compare performs a semantic diff of A and B.
//
// suppressed is the SuppressedEdge list from graphfrag.Stitch for the same
// closure — the suppression oracle uses it to determine which A chains are
// expected to be absent from B.
//
// opts controls field ignores and lets the caller override the suppression
// oracle predicate.
func Compare(a, b CallgraphExportJSON, suppressed []graphfrag.SuppressedEdge, opts Options) *DiffReport {
	report := &DiffReport{}
	ignore := opts.ignoreSet()

	// Index B chains per finding.
	bChainsByFinding := indexChainsByFinding(b.FindingGraphs)
	// Index A chains per finding.
	aChainsByFinding := indexChainsByFinding(a.FindingGraphs)

	// Build the full set of finding IDs across A and B.
	allFindings := unionFindingIDs(a.FindingGraphs, b.FindingGraphs)

	// Per-finding comparison.
	for _, fid := range allFindings {
		compareFindingForID(
			fid,
			aChainsByFinding[fid],
			bChainsByFinding[fid],
			suppressed,
			opts.SuppressedChainKey,
			ignore,
			report,
		)
	}

	// Crypto entry point consistency: validate B's index against B's chains and
	// supporting calls.
	if len(b.CryptoEntryPoints) > 0 {
		validateCryptoEntryPoints(b, bChainsByFinding, report)
	}

	// Foreign-key consistency: every per-finding supporting_call_id (6.1+) must
	// resolve to a top-level supporting_calls entry.
	validateSupportingCallIDs(b, report)

	return report
}

// validateSupportingCallIDs checks that every finding_graph.supporting_call_ids
// reference in B resolves to a top-level supporting_calls entry. A dangling id is
// a broken foreign key the served API would surface as a per-asset breadcrumb
// pointing at nothing.
func validateSupportingCallIDs(b CallgraphExportJSON, report *DiffReport) {
	supportingIDs := collectSupportingIDs(b.SupportingCalls)
	for _, fg := range b.FindingGraphs {
		for _, id := range fg.SupportingCallIDs {
			if !supportingIDs[id] {
				report.SupportingCallIDDivergences = append(report.SupportingCallIDDivergences,
					fmt.Sprintf("finding_graph %q references supporting_call_id %q not present in supporting_calls",
						fg.FindingID, id))
			}
		}
	}
}

func compareFindingForID(
	fid string,
	aChains map[ChainKey][]ExportChainNodeJSON,
	bChains map[ChainKey][]ExportChainNodeJSON,
	suppressed []graphfrag.SuppressedEdge,
	suppressedChainKey func(ChainKey, []ExportChainNodeJSON) bool,
	ignore map[string]bool,
	report *DiffReport,
) {
	if aChains == nil {
		aChains = map[ChainKey][]ExportChainNodeJSON{}
	}
	if bChains == nil {
		bChains = map[ChainKey][]ExportChainNodeJSON{}
	}

	// Build EXPECTED(B) = aChains MINUS suppressed chains.
	expectedB := make(map[ChainKey][]ExportChainNodeJSON)
	for key, ch := range aChains {
		if !isChainSuppressed(key, ch, suppressed, suppressedChainKey) {
			expectedB[key] = ch
		}
	}

	// MissingInB: in EXPECTED(B) but not in bChains.
	for key := range expectedB {
		if _, ok := bChains[key]; !ok {
			report.MissingInB = append(report.MissingInB, key)
		}
	}

	// ExtraInB: in bChains but not in EXPECTED(B), after suppression.
	for key := range bChains {
		if _, ok := expectedB[key]; !ok {
			report.ExtraInB = append(report.ExtraInB, key)
		}
	}

	// Node field comparison: only chains expected to survive and present in B.
	for key, aChain := range expectedB {
		bChain, ok := bChains[key]
		if !ok {
			continue // already reported above
		}
		compareChainNodes(fid, key, aChain, bChain, ignore, report)
	}
}

// ---------------------------------------------------------------------------
// Chain indexing and canonicalization
// ---------------------------------------------------------------------------

// indexChainsByFinding builds a map: findingID → map[ChainKey][]ExportChainNodeJSON.
func indexChainsByFinding(graphs []ExportFindingGraphJSON) map[string]map[ChainKey][]ExportChainNodeJSON {
	out := make(map[string]map[ChainKey][]ExportChainNodeJSON, len(graphs))
	for i := range graphs {
		fg := &graphs[i]
		if out[fg.FindingID] == nil {
			out[fg.FindingID] = make(map[ChainKey][]ExportChainNodeJSON)
		}
		for _, ch := range fg.CallChains {
			key := canonicalChainKey(ch)
			out[fg.FindingID][key] = ch
		}
	}
	return out
}

// canonicalChainKey produces a stable string key for one call chain by joining
// the canonical identity of each node with " -> ". The node identity is
// canonical_signature when non-empty, otherwise function_name.
func canonicalChainKey(chain []ExportChainNodeJSON) ChainKey {
	parts := make([]string, len(chain))
	for i := range chain {
		parts[i] = nodeIdentity(chain[i])
	}
	return ChainKey(strings.Join(parts, " -> "))
}

// nodeIdentity returns the canonical identifier for a node: its
// canonical_signature when non-empty, otherwise its function_name.
func nodeIdentity(n ExportChainNodeJSON) string {
	if n.CanonicalSignature != "" {
		return n.CanonicalSignature
	}
	return n.FunctionName
}

// unionFindingIDs returns the sorted union of finding IDs across two graph slices.
func unionFindingIDs(a, b []ExportFindingGraphJSON) []string {
	seen := make(map[string]bool)
	var out []string
	for _, fg := range a {
		if !seen[fg.FindingID] {
			seen[fg.FindingID] = true
			out = append(out, fg.FindingID)
		}
	}
	for _, fg := range b {
		if !seen[fg.FindingID] {
			seen[fg.FindingID] = true
			out = append(out, fg.FindingID)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Suppression oracle
// ---------------------------------------------------------------------------

// isChainSuppressed returns true when the given chain should be excluded from
// EXPECTED(B) because it traverses a suppressed edge.
//
// When opts.SuppressedChainKey is non-nil, it is called; otherwise the built-in
// heuristic runs: the chain is suppressed if any adjacent (caller, callee) pair
// matches a SuppressedEdge by caller identity + method name (+ arity when > 0).
func isChainSuppressed(
	key ChainKey,
	chain []ExportChainNodeJSON,
	suppressed []graphfrag.SuppressedEdge,
	override func(ChainKey, []ExportChainNodeJSON) bool,
) bool {
	if override != nil {
		return override(key, chain)
	}
	if len(suppressed) == 0 {
		return false
	}
	// Check every adjacent pair in the chain.
	for i := 0; i+1 < len(chain); i++ {
		caller := chain[i]
		callee := chain[i+1]
		if adjacentPairSuppressed(caller, callee, suppressed) {
			return true
		}
	}
	return false
}

// adjacentPairSuppressed returns true when the caller→callee pair matches any
// SuppressedEdge.
//
// Matching rules:
//   - callerIdentity must equal SuppressedEdge.Caller.Signature (exact string
//     match; the Signature field holds the fragment key used in suppression).
//   - The method name (last dot-separated segment of callee's function_name)
//     must equal SuppressedEdge.MethodName.
//   - If SuppressedEdge.Arity == 0, arity is not checked (matches any callee).
//     Otherwise, the callee's ParameterTypes count must equal SuppressedEdge.Arity.
func adjacentPairSuppressed(caller, callee ExportChainNodeJSON, suppressed []graphfrag.SuppressedEdge) bool {
	callerID := nodeIdentity(caller)
	calleeMethod := lastSegment(callee.FunctionName)
	calleeArity := len(callee.ParameterTypes)

	for i := range suppressed {
		se := &suppressed[i]
		if se.Caller.Signature != callerID && se.Caller.Signature != caller.FunctionName {
			continue
		}
		if se.MethodName != "" && se.MethodName != calleeMethod {
			continue
		}
		if se.Arity > 0 && len(callee.ParameterTypes) > 0 && se.Arity != calleeArity {
			continue
		}
		return true
	}
	return false
}

// lastSegment returns the last dot-separated segment of a fully qualified name,
// which is the simple method name. Returns the full string if there is no dot.
func lastSegment(fqn string) string {
	idx := strings.LastIndex(fqn, ".")
	if idx < 0 {
		return fqn
	}
	return fqn[idx+1:]
}

// ---------------------------------------------------------------------------
// Node field comparison
// ---------------------------------------------------------------------------

// compareChainNodes compares corresponding nodes in A and B for the same chain.
// When node counts differ, comparison stops at the shorter chain (structural
// mismatch is already captured by the chain-key logic above).
func compareChainNodes(
	findingID string,
	key ChainKey,
	aChain, bChain []ExportChainNodeJSON,
	ignore map[string]bool,
	report *DiffReport,
) {
	limit := len(aChain)
	if len(bChain) < limit {
		limit = len(bChain)
	}
	for i := 0; i < limit; i++ {
		compareNodes(findingID, key, aChain[i], bChain[i], ignore, report)
	}
}

// compareNodes compares two nodes field-by-field. Differences in ignored fields
// go to KnownDivergences; others to NodeFieldMismatches.
func compareNodes(
	findingID string,
	key ChainKey,
	a, b ExportChainNodeJSON,
	ignore map[string]bool,
	report *DiffReport,
) {
	nodeID := nodeIdentity(a)
	recordField := func(field, aVal, bVal string) {
		if aVal == bVal {
			return
		}
		if ignore[field] {
			report.KnownDivergences = append(report.KnownDivergences,
				fmt.Sprintf("finding=%s chain=%q node=%q field=%s: A=%q B=%q (ignored)",
					findingID, key, nodeID, field, aVal, bVal))
		} else {
			report.NodeFieldMismatches = append(report.NodeFieldMismatches, FieldMismatch{
				FindingID:    findingID,
				ChainKey:     key,
				NodeIdentity: nodeID,
				Field:        field,
				AValue:       aVal,
				BValue:       bVal,
			})
		}
	}

	recordField("return_type", a.ReturnType, b.ReturnType)
	recordField("visibility", a.Visibility, b.Visibility)
	recordField("owner_visibility", a.OwnerVisibility, b.OwnerVisibility)
	recordField("file_path", a.FilePath, b.FilePath)
	recordField("parameter_types", joinStrings(a.ParameterTypes), joinStrings(b.ParameterTypes))
}

// joinStrings joins a slice with commas for scalar comparison.
func joinStrings(ss []string) string {
	return strings.Join(ss, ",")
}

// ---------------------------------------------------------------------------
// Entry point index consistency
// ---------------------------------------------------------------------------

// validateCryptoEntryPoints checks that every entry in B's crypto_entry_points has
// at least one corresponding chain in B's finding graphs. Entry points that
// reference findings not present in any B chain are flagged as divergences.
func validateCryptoEntryPoints(
	b CallgraphExportJSON,
	bChainsByFinding map[string]map[ChainKey][]ExportChainNodeJSON,
	report *DiffReport,
) {
	// Build the set of entry function identities from B's chains.
	bEntryFunctions := collectEntryFunctions(bChainsByFinding)
	supportingIDs := collectSupportingIDs(b.SupportingCalls)

	for _, ep := range b.CryptoEntryPoints {
		epID := ep.CanonicalSignature
		if epID == "" {
			epID = ep.FunctionKey
		}
		if epID == "" {
			epID = ep.FunctionName
		}
		for _, rf := range ep.ReachableFindings {
			// Check: the finding must appear in B's chains.
			if _, ok := bChainsByFinding[rf.FindingID]; !ok {
				report.EntryPointDivergences = append(report.EntryPointDivergences,
					fmt.Sprintf("crypto_entry_points entry %q references finding %q not present in any B chain",
						epID, rf.FindingID))
				continue
			}
			// Check: the entry function must appear as a reachable node in at
			// least one chain for this finding.
			if !entryFunctionMatches(bEntryFunctions[rf.FindingID], ep) {
				report.EntryPointDivergences = append(report.EntryPointDivergences,
					fmt.Sprintf("crypto_entry_points entry %q for finding %q: function not found as entry in any B chain",
						epID, rf.FindingID))
			}
		}
		for _, rs := range ep.ReachableSupporting {
			if !supportingIDs[rs.SupportingID] {
				report.EntryPointDivergences = append(report.EntryPointDivergences,
					fmt.Sprintf("crypto_entry_points entry %q references supporting call %q not present in supporting_calls",
						epID, rs.SupportingID))
			}
		}
	}
}

func collectSupportingIDs(calls []ExportSupportingCallJSON) map[string]bool {
	out := make(map[string]bool, len(calls))
	for _, call := range calls {
		if call.SupportingID != "" {
			out[call.SupportingID] = true
		}
	}
	return out
}

func entryFunctionMatches(entries map[string]bool, ep ExportCryptoEntryPointJSON) bool {
	if entries == nil {
		return false
	}
	candidates := []string{ep.FunctionKey, ep.CanonicalSignature, ep.FunctionName}
	for _, candidate := range candidates {
		if candidate != "" && entries[candidate] {
			return true
		}
	}
	return false
}

// collectEntryFunctions builds a map: findingID → set of entry function identities.
//
// crypto_entry_points indexes EVERY node on a surviving chain, not just the head:
// an entry point is "any function from which the finding is reachable", so an
// intermediate node (e.g. a shared ancestor on a collapsed diamond) is a valid
// entry point even though it is never chain[0]. The consistency check must
// therefore accept any chain node, otherwise it spuriously flags every non-head
// entry point — which both the live and stitched exporters legitimately emit (see
// addEntryPointChain / addChainToEPI: both iterate the full chain).
func collectEntryFunctions(bChainsByFinding map[string]map[ChainKey][]ExportChainNodeJSON) map[string]map[string]bool {
	out := make(map[string]map[string]bool)
	for fid, chains := range bChainsByFinding {
		if out[fid] == nil {
			out[fid] = make(map[string]bool)
		}
		for _, ch := range chains {
			for i := range ch {
				for _, key := range nodeIdentityCandidates(ch[i]) {
					out[fid][key] = true
				}
			}
		}
	}
	return out
}

func nodeIdentityCandidates(node ExportChainNodeJSON) []string {
	candidates := []string{
		nodeIdentity(node),
		node.FunctionKey,
		node.CanonicalSignature,
		node.FunctionName,
	}
	out := make([]string, 0, len(candidates))
	seen := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		out = append(out, candidate)
	}
	return out
}
