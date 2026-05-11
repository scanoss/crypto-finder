// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package stitch produces the merged findings + callgraph that
// `crypto-finder scan --scan-dependencies --export-callgraph` would emit,
// from inputs that have already been computed per-component.
//
// The intended caller is a service that has previously scanned each
// component independently (no --scan-dependencies) and stored the
// resulting findings.json + callgraph.json. When asked "what crypto is
// reachable from artifact X?", the caller fetches X's outputs and X's
// transitive deps' outputs from its storage, hands them to Merge, and
// receives bytes byte-equivalent to what crypto-finder would have
// produced in one --scan-dependencies run.
//
// Why this lives in crypto-finder (not the calling service):
//
//   - The InterimReport / call-graph-export schemas are crypto-finder's
//     public contract. Operations on that contract — finding_id hashing,
//     dependency_info stamping, schema-5.x's "self-contained chains"
//     concat rule — belong with the contract owner. A reimplementation in
//     a downstream service would drift the moment the schema bumps.
//
//   - The pure stitch is reusable: catalog services, CI plugins, IDE
//     extensions can all import this package to assemble cross-component
//     reachability without re-running crypto-finder.
//
// What this package does NOT do:
//
//   - It does not read from any storage. Inputs are []byte; the caller is
//     responsible for fetching them (e.g., from a DB).
//   - It does not run any scanner, resolver, or callgraph builder. The
//     dependency tree must be resolved by the caller before invocation.
//   - It does not gzip. Inputs and outputs are plain JSON; storage
//     compression is a caller concern.
//
// Correctness properties Merge depends on (validated empirically against
// `crypto-finder scan --scan-dependencies` output on real Maven
// artifacts):
//
//   1. Schema 5.x callgraph exports contain no top-level functions[] /
//      edges[]. The graph is materialized as finding_graphs (one per
//      cryptographic asset) with self-contained call_chains. Zero chains
//      span multiple components — every chain lives entirely in one
//      module, tagged by dependency_info on every frame.
//
//   2. findings.json is a flat union: target findings (source=direct)
//      interleaved with dep findings (source=dependency + dependency_info).
//      finding_id is sha256(path:start_line:first_rule_id)[:8], with path
//      prefixed by "module@version/" when the asset belongs to a dep.
//
// Both properties make Merge a structural concat + decorate pass — no
// type resolution, no edge synthesis, no scanner invocation.
package stitch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Policy controls how Merge prunes the merged callgraph. The zero value
// is "passthrough" — every chain from every fragment is copied verbatim,
// matching what a naive concat would produce.
//
// Direction-B callers should set PruneToRootModule=true so the merged
// callgraph mirrors what `crypto-finder scan --scan-dependencies` would
// emit, where the internal Tracer is constrained by
// userPackages={root_module} and walks back only until it reaches the
// component's package boundary. Without that prune, L1's standalone
// fragments (built with userPackages=nil, walking to graph roots) carry
// chains many times longer and more numerous than L2 keeps.
type Policy struct {
	// PruneToRootModule truncates every chain at the first frame whose
	// function name is in the source fragment's root module. The fragment
	// supplies its root via scan_metadata.root_module; fragments that
	// omit it are passed through unchanged. After truncation, chains that
	// are now byte-equal to a sibling are deduplicated.
	PruneToRootModule bool

	// MaxChainsPerFinding caps the number of chains kept for any one
	// finding_graph. 0 disables the cap. crypto-finder's exporter uses
	// 128; mirror that for output-shape parity.
	MaxChainsPerFinding int

	// RebuildEntryPointIndex regenerates entry_point_index from the
	// pruned + deduped chains, replacing whatever the source fragments
	// supplied. This is required to match crypto-finder's L2 baseline
	// shape, where entry_point_index is always a derivative of the
	// final finding_graphs and never carries entries for frames that
	// were pruned away.
	RebuildEntryPointIndex bool
}

// Dep is one transitive dependency's contribution to the merge.
//
// Module is the crypto-finder-internal module identifier — for Maven this
// is "<group>:<artifact>" (e.g. "commons-codec:commons-codec"); for other
// ecosystems whatever crypto-finder's dependency scanner would have
// emitted. The exact string is propagated into every
// CryptographicAsset.DependencyInfo.Module and every chain frame's
// dependency_info.module in the merged output, so the caller controls
// what downstream consumers see.
//
// Findings is the raw findings.json bytes (uncompressed) produced by
// running `crypto-finder scan` against this dep's source, without
// --scan-dependencies. Required.
//
// Callgraph is the raw callgraph.json bytes produced by running
// `crypto-finder scan --export-callgraph` against this dep's source.
// Optional: a nil/empty Callgraph means the dep contributes findings only
// and its frames are absent from the merged finding_graphs. Callers that
// require complete reachability should refuse to call Merge when any dep
// is missing a callgraph rather than silently producing a thin graph.
type Dep struct {
	Module    string
	Version   string
	Findings  []byte
	Callgraph []byte
}

// Result is what Merge returns.
//
// Findings and Callgraph are raw JSON bytes ready to write to disk, gzip,
// or push to an HTTP response. The callgraph carries the same
// schema_version as the highest-version input fragment; Merge does not
// transcode between schema versions, so all inputs must share a schema.
type Result struct {
	Findings  []byte
	Callgraph []byte
	Summary   Summary
}

// Summary holds the few counts a typical caller wants to denormalize next
// to the stored callgraph for fast listings (matching the columns
// crypto-mining-service writes to reachability_paths today).
type Summary struct {
	SchemaVersion         string
	FindingCount          int
	EntryPointCount       int
	ReachableFindingCount int
}

// Merge produces the cross-component findings + callgraph from one target
// and zero or more dep contributions, applying the default policy
// (passthrough — no pruning). Use MergeWithPolicy to control pruning.
func Merge(targetFindings, targetCallgraph []byte, deps []Dep) (*Result, error) {
	return MergeWithPolicy(targetFindings, targetCallgraph, deps, Policy{})
}

// MergeWithPolicy is the policy-aware form of Merge. See Policy for the
// supported knobs.
//
// targetFindings is required; the merge fails if it's nil or empty.
// targetCallgraph is optional — Merge still produces a Callgraph result
// when only deps contributed graphs, but the typical caller will
// invariant-check that the target has its own graph before invoking.
//
// Ordering: deps are processed in slice order. The merged finding_graphs
// and entry_point_index preserve that order with the target's
// contribution first, then each dep's contribution in the order received.
// Callers wanting byte-stable output should sort deps before calling.
func MergeWithPolicy(targetFindings, targetCallgraph []byte, deps []Dep, policy Policy) (*Result, error) {
	if len(targetFindings) == 0 {
		return nil, fmt.Errorf("stitch: target findings are required")
	}

	mergedFindings, err := mergeFindings(targetFindings, deps)
	if err != nil {
		return nil, fmt.Errorf("stitch: merge findings: %w", err)
	}

	mergedCG, summary, err := mergeCallgraph(targetCallgraph, deps, policy)
	if err != nil {
		return nil, fmt.Errorf("stitch: merge callgraph: %w", err)
	}

	return &Result{
		Findings:  mergedFindings,
		Callgraph: mergedCG,
		Summary:   summary,
	}, nil
}

// ---- findings merge ----

// findingsEnvelope is the minimal projection of crypto-finder's
// InterimReport that mergeFindings needs to read. Tool/Rules/Version are
// preserved verbatim from the target so the output is indistinguishable
// from a live --scan-dependencies run.
type findingsEnvelope struct {
	Tool     json.RawMessage `json:"tool,omitempty"`
	Rules    json.RawMessage `json:"rules,omitempty"`
	Version  json.RawMessage `json:"version,omitempty"`
	Findings []findingEntry  `json:"findings"`
}

// findingEntry / assetEntry / ruleRef are intentionally lighter than
// internal/entities.Finding etc. We only need to read FilePath / StartLine
// / Rules[0].ID for finding_id, and to stamp Source / DependencyInfo /
// FindingID on the way out. Everything else (Match, OID, Metadata, …)
// passes through unchanged as RawMessage to keep us forward-compatible
// with schema additions.
type findingEntry struct {
	FilePath            string          `json:"file_path"`
	Language            string          `json:"language,omitempty"`
	CryptographicAssets []assetEntry    `json:"cryptographic_assets"`
}

type assetEntry struct {
	StartLine      int             `json:"start_line"`
	EndLine        int             `json:"end_line,omitempty"`
	Match          json.RawMessage `json:"match,omitempty"`
	OID            json.RawMessage `json:"oid,omitempty"`
	Rules          []ruleRef       `json:"rules"`
	Status         json.RawMessage `json:"status,omitempty"`
	Metadata       json.RawMessage `json:"metadata,omitempty"`
	FindingID      string          `json:"finding_id,omitempty"`
	Source         string          `json:"source,omitempty"`
	DependencyInfo *depInfo        `json:"dependency_info,omitempty"`
}

type ruleRef struct {
	ID       string          `json:"id"`
	Message  json.RawMessage `json:"message,omitempty"`
	Severity json.RawMessage `json:"severity,omitempty"`
	Version  json.RawMessage `json:"version,omitempty"`
}

type depInfo struct {
	Module  string `json:"module"`
	Version string `json:"version"`
}

func mergeFindings(targetRaw []byte, deps []Dep) ([]byte, error) {
	var target findingsEnvelope
	if err := json.Unmarshal(targetRaw, &target); err != nil {
		return nil, fmt.Errorf("unmarshal target: %w", err)
	}

	out := findingsEnvelope{
		Tool:    target.Tool,
		Rules:   target.Rules,
		Version: target.Version,
	}
	stampAssets(target.Findings, "", "")
	out.Findings = append(out.Findings, target.Findings...)

	for _, dep := range deps {
		if len(dep.Findings) == 0 {
			continue
		}
		var depEnv findingsEnvelope
		if err := json.Unmarshal(dep.Findings, &depEnv); err != nil {
			return nil, fmt.Errorf("unmarshal dep %s@%s findings: %w", dep.Module, dep.Version, err)
		}
		stampAssets(depEnv.Findings, dep.Module, dep.Version)
		out.Findings = append(out.Findings, depEnv.Findings...)
	}

	return json.Marshal(out)
}

// stampAssets rewrites Source / DependencyInfo / FindingID on every asset
// in `findings`. When module == "" the assets are treated as the target's
// own (source=direct, no dependency_info); otherwise as a dep
// contribution (source=dependency, dependency_info populated, finding_id
// computed with the dep prefix).
//
// Mirrors crypto-finder/internal/engine/dependency_scanner.go's
// AssignFindingIDs (logic) + findingIDPath (path construction) +
// generateFindingID (hash). If those evolve, this must follow.
func stampAssets(findings []findingEntry, module, version string) {
	for i := range findings {
		f := &findings[i]
		for j := range f.CryptographicAssets {
			a := &f.CryptographicAssets[j]
			if module != "" {
				a.Source = "dependency"
				a.DependencyInfo = &depInfo{Module: module, Version: version}
			} else {
				a.Source = "direct"
				a.DependencyInfo = nil
			}
			a.FindingID = generateFindingID(f.FilePath, a.StartLine, a.Rules, module, version)
		}
	}
}

// generateFindingID computes the 8-hex-char stable identifier crypto-finder
// uses to cross-reference findings to call-graph entries. Mirrors
// crypto-finder/internal/engine/dependency_scanner.go:generateFindingID
// and :findingIDPath. Kept here (not imported) so Merge has no dependency
// on the internal package, but the implementations must stay byte-equal
// — TestGenerateFindingID pins this against fixture cases captured from
// the live scanner.
func generateFindingID(filePath string, startLine int, rules []ruleRef, depModule, depVersion string) string {
	path := filePath
	if depModule != "" && depVersion != "" {
		path = depModule + "@" + depVersion + "/" + filePath
	}
	ruleID := ""
	if len(rules) > 0 {
		ruleID = rules[0].ID
	}
	h := sha256.Sum256([]byte(path + ":" + strconv.Itoa(startLine) + ":" + ruleID))
	return hex.EncodeToString(h[:])[:8]
}

// ---- callgraph merge ----

// mergeCallgraph stitches the target's callgraph fragment with each dep's
// fragment, applying the supplied Policy. Returns nil bytes when neither
// the target nor any dep has a callgraph.
//
// Schema 5.x callgraphs are envelope { schema_version, scan_metadata,
// finding_graphs, entry_point_index }. Without pruning (zero policy) we
// preserve scan_metadata from the target and concatenate finding_graphs
// + entry_point_index, stamping dependency_info on every dep frame.
//
// With PruneToRootModule, each fragment's chains are first truncated at
// the fragment's own root-module boundary (read from scan_metadata.
// root_module), then deduped and capped. With RebuildEntryPointIndex,
// entry_point_index is regenerated from the resulting chains so the
// index never carries entries for frames that were pruned away.
func mergeCallgraph(targetRaw []byte, deps []Dep, policy Policy) ([]byte, Summary, error) {
	var summary Summary

	// Detect "no callgraphs anywhere" early so we return nil bytes (caller
	// can store SQL NULL) rather than an empty envelope.
	hasAnyCG := len(targetRaw) > 0
	if !hasAnyCG {
		for _, d := range deps {
			if len(d.Callgraph) > 0 {
				hasAnyCG = true
				break
			}
		}
	}
	if !hasAnyCG {
		return nil, summary, nil
	}

	type cgEnvelope struct {
		SchemaVersion   string            `json:"schema_version"`
		ScanMetadata    json.RawMessage   `json:"scan_metadata,omitempty"`
		FindingGraphs   []json.RawMessage `json:"finding_graphs"`
		EntryPointIndex []json.RawMessage `json:"entry_point_index"`
	}

	out := cgEnvelope{
		FindingGraphs:   []json.RawMessage{},
		EntryPointIndex: []json.RawMessage{},
	}

	if len(targetRaw) > 0 {
		stamped, err := processFragment(targetRaw, "", "", policy)
		if err != nil {
			return nil, summary, fmt.Errorf("unmarshal target callgraph: %w", err)
		}
		out.SchemaVersion = stamped.schemaVersion
		out.ScanMetadata = stamped.scanMetadata
		out.FindingGraphs = append(out.FindingGraphs, stamped.findingGraphs...)
		out.EntryPointIndex = append(out.EntryPointIndex, stamped.entryPointIndex...)
	}

	for _, dep := range deps {
		if len(dep.Callgraph) == 0 {
			continue
		}
		stamped, err := processFragment(dep.Callgraph, dep.Module, dep.Version, policy)
		if err != nil {
			return nil, summary, fmt.Errorf("stamp dep %s@%s callgraph: %w", dep.Module, dep.Version, err)
		}
		if out.SchemaVersion == "" {
			out.SchemaVersion = stamped.schemaVersion
		}
		out.FindingGraphs = append(out.FindingGraphs, stamped.findingGraphs...)
		out.EntryPointIndex = append(out.EntryPointIndex, stamped.entryPointIndex...)
	}

	// Optional: rebuild entry_point_index from the (post-prune)
	// finding_graphs so it reflects only the frames that survived
	// pruning. crypto-finder's exporter does this unconditionally — we
	// gate it behind a policy flag for backward compatibility with
	// callers that just want the raw union.
	if policy.RebuildEntryPointIndex {
		rebuilt, err := rebuildEntryPointIndex(out.FindingGraphs)
		if err != nil {
			return nil, summary, fmt.Errorf("rebuild entry_point_index: %w", err)
		}
		out.EntryPointIndex = rebuilt
	}

	summary.SchemaVersion = out.SchemaVersion
	summary.FindingCount = len(out.FindingGraphs)
	summary.EntryPointCount = len(out.EntryPointIndex)
	summary.ReachableFindingCount = countReachableFindings(out.EntryPointIndex)

	raw, err := json.Marshal(out)
	if err != nil {
		return nil, summary, err
	}
	return raw, summary, nil
}

// stampedFragment is mergeCallgraph's intermediate output for one
// fragment (target or dep): scan_metadata + finding_graphs +
// entry_point_index, post-stamping and post-pruning.
type stampedFragment struct {
	schemaVersion   string
	scanMetadata    json.RawMessage
	findingGraphs   []json.RawMessage
	entryPointIndex []json.RawMessage
}

// processFragment is the per-fragment pipeline: unmarshal → optionally
// stamp dependency_info → optionally prune chains to the fragment's
// root_module → optionally dedup + cap chains → optionally stamp entry
// points → re-marshal.
//
// module == "" identifies the target fragment (no dependency_info
// stamping). Both target and dep fragments are otherwise processed
// uniformly so policy applies symmetrically. The target's chains need
// the same prune treatment as a dep's, because L1 standalone always
// runs with userPackages=nil regardless of whether it's a future
// "target" or "dep" in the eventual stitch.
//
// We unmarshal each finding_graph as a generic map[string]any rather
// than a fully-typed schema-5 struct because:
//
//   - Schema 5.x's finding_graph nesting is deep and irregular (chains,
//     entry_call, crypto_call, parameters[], source_nodes[], …).
//   - We only WRITE one field on each frame (dependency_info); the rest
//     is passthrough. A generic map is byte-stable on round-trip for the
//     fields we don't touch, and resilient to schema additions.
//   - Pruning operates on frames in array positions only — no field
//     introspection needed beyond function_name for the module check.
//
// Cost is one extra marshal pass per fragment, which is negligible next
// to the wall-time of a stitch (postgres fetches dominate).
func processFragment(raw []byte, module, version string, policy Policy) (stampedFragment, error) {
	var in struct {
		SchemaVersion   string            `json:"schema_version"`
		ScanMetadata    json.RawMessage   `json:"scan_metadata,omitempty"`
		FindingGraphs   []json.RawMessage `json:"finding_graphs"`
		EntryPointIndex []json.RawMessage `json:"entry_point_index"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return stampedFragment{}, err
	}

	rootPkg := extractRootModule(in.ScanMetadata)

	var depTag map[string]string
	if module != "" {
		depTag = map[string]string{"module": module, "version": version}
	}

	outFG := make([]json.RawMessage, 0, len(in.FindingGraphs))
	for _, fgRaw := range in.FindingGraphs {
		var fg map[string]any
		if err := json.Unmarshal(fgRaw, &fg); err != nil {
			return stampedFragment{}, err
		}

		if chainsAny, ok := fg["call_chains"].([]any); ok {
			processed := processCallChains(chainsAny, depTag, rootPkg, policy)
			fg["call_chains"] = processed
		}

		buf, err := json.Marshal(fg)
		if err != nil {
			return stampedFragment{}, err
		}
		outFG = append(outFG, buf)
	}

	outEP := make([]json.RawMessage, 0, len(in.EntryPointIndex))
	for _, epRaw := range in.EntryPointIndex {
		var ep map[string]any
		if err := json.Unmarshal(epRaw, &ep); err != nil {
			return stampedFragment{}, err
		}
		if depTag != nil {
			ep["dependency_info"] = depTag
		}
		buf, err := json.Marshal(ep)
		if err != nil {
			return stampedFragment{}, err
		}
		outEP = append(outEP, buf)
	}

	return stampedFragment{
		schemaVersion:   in.SchemaVersion,
		scanMetadata:    in.ScanMetadata,
		findingGraphs:   outFG,
		entryPointIndex: outEP,
	}, nil
}

// processCallChains is the heart of phase-B pruning. Each chain is
// (1) optionally truncated to start at the first frame inside rootPkg,
// (2) decorated with dependency_info, (3) deduped against earlier chains
// that produced the same byte-shape, and (4) capped at
// policy.MaxChainsPerFinding.
//
// The order matters: prune before dedup, because pruning is what causes
// previously-distinct chains to become equal. Stamping happens last so
// the dep_info tag doesn't perturb the dedup key.
func processCallChains(chains []any, depTag map[string]string, rootPkg string, policy Policy) []any {
	prune := policy.PruneToRootModule && rootPkg != ""
	cap := policy.MaxChainsPerFinding

	seen := make(map[string]bool, len(chains))
	out := make([]any, 0, len(chains))
	for _, chRaw := range chains {
		chain, ok := chRaw.([]any)
		if !ok {
			continue
		}

		if prune {
			chain = truncateChainAtModule(chain, rootPkg)
			if len(chain) == 0 {
				continue
			}
		}

		// Dedup key is computed BEFORE dep_info stamping so two chains
		// from the same dep collapse correctly. dep_info is constant
		// per fragment so adding it pre-key would be redundant; adding
		// it post-key keeps the key minimal.
		key := chainDedupKey(chain)
		if seen[key] {
			continue
		}
		seen[key] = true

		if depTag != nil {
			stampChainFrames(chain, depTag)
		}

		out = append(out, chain)
		if cap > 0 && len(out) >= cap {
			break
		}
	}
	return out
}

// truncateChainAtModule mirrors crypto-finder's Tracer behavior when
// userPackages is set: it walks backward from the target (rightmost
// frame) and stops as soon as a frame in rootPkg appears at the chain
// head. The resulting chain starts at the first user-pkg frame walking
// back from the target.
//
// Chain layout in the export is [entryPoint, ..., immediateCaller,
// target]. The L1-standalone tracer (userPackages=nil) walks all the
// way to graph roots, producing long chains. L2's tracer with
// userPackages={rootPkg} stops at the first frame in rootPkg
// encountered walking back — which yields chains of length 2 in the
// common case (immediateCaller is in rootPkg) and longer chains only
// when intermediate frames are external (JDK, runtime).
//
// To replicate that here, scan rightward-to-leftward across the L1
// chain (skipping the target itself at index N-1) and return the
// suffix beginning at the first frame in rootPkg. A chain whose
// non-target frames are all external is dropped — same outcome as
// crypto-finder's chainReachesUserCode check.
//
// Match rule: function_name == rootPkg OR function_name starts with
// rootPkg + ".". The trailing dot guards against false positives like
// "org.apache.poison" matching "org.apache.poi".
func truncateChainAtModule(chain []any, rootPkg string) []any {
	if len(chain) <= 1 {
		return chain
	}
	prefix := rootPkg + "."
	// Walk callers (positions N-2 down to 0). The first frame at or
	// before index N-2 that's in rootPkg is where L2's tracer would
	// have stopped — truncate everything before it.
	for i := len(chain) - 2; i >= 0; i-- {
		frame, ok := chain[i].(map[string]any)
		if !ok {
			continue
		}
		fn, _ := frame["function_name"].(string)
		if fn == rootPkg || strings.HasPrefix(fn, prefix) {
			return chain[i:]
		}
	}
	return nil
}

// chainDedupKey produces a stable identity for a chain so we can dedup
// chains that became byte-equal after pruning. We hash the canonical
// signature of each frame (falling back to function_name); the chain
// shape (frame count + frame identities) is what determines uniqueness,
// not the pre-prune prefix.
func chainDedupKey(chain []any) string {
	var b strings.Builder
	for _, frameRaw := range chain {
		frame, ok := frameRaw.(map[string]any)
		if !ok {
			b.WriteString("|?")
			continue
		}
		if sig, ok := frame["canonical_signature"].(string); ok && sig != "" {
			b.WriteString("|s:")
			b.WriteString(sig)
		} else if fn, ok := frame["function_name"].(string); ok {
			b.WriteString("|f:")
			b.WriteString(fn)
		}
	}
	return b.String()
}

// stampChainFrames adds dependency_info to every frame in chain (and the
// nested entry_call / crypto_call sub-objects when present), in-place.
// Caller has already decided depTag is non-nil.
func stampChainFrames(chain []any, depTag map[string]string) {
	for _, frameRaw := range chain {
		frame, ok := frameRaw.(map[string]any)
		if !ok {
			continue
		}
		frame["dependency_info"] = depTag
		if ec, ok := frame["entry_call"].(map[string]any); ok {
			ec["dependency_info"] = depTag
		}
		if cc, ok := frame["crypto_call"].(map[string]any); ok {
			cc["dependency_info"] = depTag
		}
	}
}

// extractRootModule pulls scan_metadata.root_module without unmarshalling
// the whole envelope. Returns "" if scan_metadata is missing or the
// field is absent — caller treats that as "pruning disabled for this
// fragment" (passthrough).
func extractRootModule(scanMetadata json.RawMessage) string {
	if len(scanMetadata) == 0 {
		return ""
	}
	var sm struct {
		RootModule string `json:"root_module"`
	}
	if err := json.Unmarshal(scanMetadata, &sm); err != nil {
		return ""
	}
	return sm.RootModule
}

// rebuildEntryPointIndex regenerates entry_point_index from the final
// finding_graphs, mirroring crypto-finder/internal/scan/export.go's
// buildEntryPointIndex. Every function appearing in any chain frame is
// an entry-point candidate (external code might call any of them); each
// entry point records which finding_ids it reaches.
//
// We use canonical_signature as the dedup key when present, falling
// back to function_name — same precedence crypto-finder uses
// (ensureEntryPointData).
func rebuildEntryPointIndex(findingGraphs []json.RawMessage) ([]json.RawMessage, error) {
	type epEntry struct {
		function           string
		canonicalSignature string
		dependencyInfo     map[string]string
		// findings keyed by finding_id, value=shallowest depth seen
		findings map[string]int
	}
	index := make(map[string]*epEntry)
	order := make([]string, 0)

	for _, fgRaw := range findingGraphs {
		var fg struct {
			FindingID        string          `json:"finding_id"`
			MatchedOperation json.RawMessage `json:"matched_operation"`
			CallChains       [][]map[string]any `json:"call_chains"`
		}
		if err := json.Unmarshal(fgRaw, &fg); err != nil {
			return nil, err
		}
		for _, chain := range fg.CallChains {
			for pos, frame := range chain {
				fn, _ := frame["function_name"].(string)
				if fn == "" {
					continue
				}
				canonical, _ := frame["canonical_signature"].(string)
				key := canonical
				if key == "" {
					key = fn
				}
				ep, exists := index[key]
				if !exists {
					ep = &epEntry{
						function:           fn,
						canonicalSignature: canonical,
						findings:           make(map[string]int),
					}
					if di, ok := frame["dependency_info"].(map[string]any); ok {
						ep.dependencyInfo = mapToStringStrings(di)
					}
					index[key] = ep
					order = append(order, key)
				}
				depth := len(chain) - pos
				if cur, ok := ep.findings[fg.FindingID]; !ok || depth < cur {
					ep.findings[fg.FindingID] = depth
				}
			}
		}
	}

	out := make([]json.RawMessage, 0, len(order))
	for _, key := range order {
		ep := index[key]
		class, method := splitFunctionName(ep.function)
		entry := map[string]any{
			"function": ep.function,
			"class":    class,
			"method":   method,
		}
		if ep.canonicalSignature != "" {
			entry["canonical_signature"] = ep.canonicalSignature
		}
		if ep.dependencyInfo != nil {
			entry["dependency_info"] = ep.dependencyInfo
		}
		// reachable_findings: sorted by finding_id for stable output.
		refs := make([]map[string]any, 0, len(ep.findings))
		ids := make([]string, 0, len(ep.findings))
		for id := range ep.findings {
			ids = append(ids, id)
		}
		sortStrings(ids)
		for _, id := range ids {
			refs = append(refs, map[string]any{
				"finding_id":        id,
				"chain_depth":       ep.findings[id],
				"finding_graph_ref": id,
			})
		}
		entry["reachable_findings"] = refs

		buf, err := json.Marshal(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, buf)
	}
	return out, nil
}

// splitFunctionName mirrors crypto-finder/internal/scan/export.go's
// splitFunctionName: everything up to the last '.' is the class,
// everything after is the method. Match the package separator for Java;
// add cases here if the stitcher starts handling other ecosystems.
func splitFunctionName(fn string) (class, method string) {
	idx := strings.LastIndex(fn, ".")
	if idx < 0 {
		return "", fn
	}
	return fn[:idx], fn[idx+1:]
}

// mapToStringStrings converts a JSON-unmarshalled map[string]any whose
// values are strings into a typed map[string]string. Used for
// dependency_info round-trip; non-string values are dropped (shouldn't
// happen for our usage but defensive).
func mapToStringStrings(in map[string]any) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// sortStrings is sort.Strings inlined to keep the import surface small —
// pkg/stitch otherwise has zero sort dependency, and the slice is small
// (reachable_findings per entry point is typically <20).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// countReachableFindings sums reachable_findings[] length across every
// entry-point row. Tolerant: missing or unexpected shapes contribute zero.
func countReachableFindings(entryPoints []json.RawMessage) int {
	total := 0
	for _, raw := range entryPoints {
		var shape struct {
			ReachableFindings []json.RawMessage `json:"reachable_findings"`
		}
		if err := json.Unmarshal(raw, &shape); err == nil {
			total += len(shape.ReachableFindings)
		}
	}
	return total
}
