// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package equiv provides a semantic equivalence diff tool for schema-5.x
// callgraph exports produced by crypto-finder.
//
// Compare takes two decoded schema-5.x callgraph exports — A (live
// `scan --scan-dependencies --export-callgraph`) and B (emulated mining:
// graphfrag.Stitch -> ToCallgraphExport) — plus the suppressed edges from the
// same stitch run, and returns a DiffReport describing any differences.
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
//   - B's entry_point_index is validated against B's surviving chain set.
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
//   - "confidence": schema-5.x has no confidence field (internal only).
//
// These go to KnownDivergences, not NodeFieldMismatches.
package equiv

import (
	"fmt"
	"strings"

	"github.com/scanoss/crypto-finder/pkg/graphfrag"
)

// ---------------------------------------------------------------------------
// JSON mirror types (schema-5.x decoded form)
// ---------------------------------------------------------------------------

// CallgraphExportJSON is the decoded form of a schema-5.x callgraph export.
// Both A (live scan) and B (stitched) are decoded into this type before
// comparison so the diff operates on a common representation.
type CallgraphExportJSON struct {
	SchemaVersion   string                   `json:"schema_version"`
	FindingGraphs   []ExportFindingGraphJSON `json:"finding_graphs"`
	EntryPointIndex []ExportEntryPointJSON   `json:"entry_point_index,omitempty"`
}

// ExportFindingGraphJSON is one finding_graph entry in a CallgraphExportJSON.
type ExportFindingGraphJSON struct {
	FindingID  string                  `json:"finding_id"`
	CallChains [][]ExportChainNodeJSON `json:"call_chains,omitempty"`
}

// ExportChainNodeJSON is one node in a schema-5.x call chain.
type ExportChainNodeJSON struct {
	FunctionName       string   `json:"function_name"`
	CanonicalSignature string   `json:"canonical_signature,omitempty"`
	ReturnType         string   `json:"return_type,omitempty"`
	ParameterTypes     []string `json:"parameter_types,omitempty"`
	Visibility         string   `json:"visibility,omitempty"`
	OwnerVisibility    string   `json:"owner_visibility,omitempty"`
	FilePath           string   `json:"file_path,omitempty"`
}

// ExportEntryPointJSON is one entry_point_index entry.
type ExportEntryPointJSON struct {
	Function           string                       `json:"function"`
	CanonicalSignature string                       `json:"canonical_signature,omitempty"`
	ReachableFindings  []ExportReachableFindingJSON `json:"reachable_findings,omitempty"`
}

// ExportReachableFindingJSON is one reachable finding inside an entry point.
type ExportReachableFindingJSON struct {
	FindingID  string `json:"finding_id"`
	ChainDepth int    `json:"chain_depth"`
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
	// EntryPointDivergences records entry_point_index entries in B that do not
	// correspond to a surviving B chain's entry function and finding.
	EntryPointDivergences []string
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
	"confidence",      // internal only, not present in schema-5.x output
}

// Options controls the behaviour of Compare.
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
		aChains := aChainsByFinding[fid] // map[ChainKey][]ExportChainNodeJSON
		bChains := bChainsByFinding[fid] // map[ChainKey][]ExportChainNodeJSON
		if aChains == nil {
			aChains = map[ChainKey][]ExportChainNodeJSON{}
		}
		if bChains == nil {
			bChains = map[ChainKey][]ExportChainNodeJSON{}
		}

		// Build EXPECTED(B) = aChains MINUS suppressed chains.
		expectedB := make(map[ChainKey][]ExportChainNodeJSON)
		for key, ch := range aChains {
			if !isChainSuppressed(key, ch, suppressed, opts.SuppressedChainKey) {
				expectedB[key] = ch
			}
		}

		// MissingInB: in EXPECTED(B) but not in bChains.
		for key := range expectedB {
			if _, ok := bChains[key]; !ok {
				report.MissingInB = append(report.MissingInB, key)
			}
		}

		// ExtraInB: in bChains but not in aChains (raw A, not just expected).
		for key := range bChains {
			if _, ok := aChains[key]; !ok {
				report.ExtraInB = append(report.ExtraInB, key)
			}
		}

		// Node field comparison: for chains present in both A and B.
		for key, aChain := range aChains {
			bChain, ok := bChains[key]
			if !ok {
				continue // already reported above
			}
			compareChainNodes(fid, key, aChain, bChain, ignore, report)
		}
	}

	// Entry point index consistency: validate B's index against B's chains.
	if len(b.EntryPointIndex) > 0 {
		validateEntryPointIndex(b, bChainsByFinding, report)
	}

	return report
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
	for i, n := range chain {
		parts[i] = nodeIdentity(n)
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

	for _, se := range suppressed {
		if se.Caller.Signature != callerID && se.Caller.Signature != caller.FunctionName {
			continue
		}
		if se.MethodName != "" && se.MethodName != calleeMethod {
			continue
		}
		if se.Arity > 0 && se.Arity != calleeArity {
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

// validateEntryPointIndex checks that every entry in B's entry_point_index has
// at least one corresponding chain in B's finding graphs. Entry points that
// reference findings not present in any B chain are flagged as divergences.
func validateEntryPointIndex(
	b CallgraphExportJSON,
	bChainsByFinding map[string]map[ChainKey][]ExportChainNodeJSON,
	report *DiffReport,
) {
	// Build the set of entry function identities from B's chains.
	bEntryFunctions := collectEntryFunctions(bChainsByFinding)

	for _, ep := range b.EntryPointIndex {
		epID := ep.CanonicalSignature
		if epID == "" {
			epID = ep.Function
		}
		for _, rf := range ep.ReachableFindings {
			// Check: the finding must appear in B's chains.
			if _, ok := bChainsByFinding[rf.FindingID]; !ok {
				report.EntryPointDivergences = append(report.EntryPointDivergences,
					fmt.Sprintf("entry_point_index entry %q references finding %q not present in any B chain",
						epID, rf.FindingID))
				continue
			}
			// Check: the entry function must appear as the first node in at least one chain for this finding.
			if !bEntryFunctions[rf.FindingID][epID] {
				report.EntryPointDivergences = append(report.EntryPointDivergences,
					fmt.Sprintf("entry_point_index entry %q for finding %q: function not found as entry in any B chain",
						epID, rf.FindingID))
			}
		}
	}
}

// collectEntryFunctions builds a map: findingID → set of entry function identities
// (first node of each chain for that finding).
func collectEntryFunctions(bChainsByFinding map[string]map[ChainKey][]ExportChainNodeJSON) map[string]map[string]bool {
	out := make(map[string]map[string]bool)
	for fid, chains := range bChainsByFinding {
		if out[fid] == nil {
			out[fid] = make(map[string]bool)
		}
		for _, ch := range chains {
			if len(ch) > 0 {
				out[fid][nodeIdentity(ch[0])] = true
			}
		}
	}
	return out
}
