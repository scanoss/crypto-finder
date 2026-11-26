// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

// render projects crypto-finder's findings (v1.4) + callgraph (6.x) envelopes
// into the per-component response block. metadata and call_chains are
// PASS-THROUGH json.RawMessage — no re-curation or field-casing translation;
// the layer only groups findings, JOINs reachability by finding_id, applies the
// entry_point_signatures / max_chains_per_asset filters, and accounts the
// post-prune count. Ported verbatim from the mining service's
// render package (pure: no I/O, no global state).

import (
	"encoding/json"
	"fmt"

	"github.com/scanoss/crypto-finder/pkg/pqc"
)

// hardCapMaxChainsPerAsset is the upper bound on per-asset call_chains
// regardless of the request value.
const hardCapMaxChainsPerAsset = 128

type rawFindingsEnvelope struct {
	Version  string           `json:"version"`
	Findings []rawFindingFile `json:"findings"`
}

type rawFindingFile struct {
	Language            string           `json:"language"`
	FilePath            string           `json:"file_path"`
	CryptographicAssets []rawCryptoAsset `json:"cryptographic_assets"`
}

type rawCryptoAsset struct {
	FindingID           string             `json:"finding_id"`
	OID                 string             `json:"oid,omitempty"`
	Match               string             `json:"match"`
	Source              string             `json:"source"`
	PURL                string             `json:"purl,omitempty"`
	DependencyInfo      *rawDependencyInfo `json:"dependency_info,omitempty"`
	StartLine           int                `json:"start_line"`
	EndLine             int                `json:"end_line"`
	Metadata            json.RawMessage    `json:"metadata"`
	ParameterConditions json.RawMessage    `json:"parameter_conditions,omitempty"`
	Rules               []CryptoRuleDTO    `json:"rules,omitempty"`
}

// rawDependencyInfo mirrors crypto-finder's findings.json (v1.6)
// dependency_info object for an indirect finding.
type rawDependencyInfo struct {
	Module  string `json:"module"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

// CallgraphEnvelope is a crypto-finder callgraph export with its entries kept
// raw.
type CallgraphEnvelope struct {
	SchemaVersion     string                   `json:"schema_version"`
	Functions         []ExportInternedFunction `json:"functions"`
	FindingGraphs     []json.RawMessage        `json:"finding_graphs"`
	CryptoEntryPoints []json.RawMessage        `json:"crypto_entry_points"`
	SupportingCalls   []json.RawMessage        `json:"supporting_calls"`
}

// RawFindingGraph is one finding_graphs entry as the renderer reads it.
type RawFindingGraph struct {
	FindingID         string            `json:"finding_id"`
	SupportingCallIDs []string          `json:"supporting_call_ids,omitempty"`
	CallChains        []json.RawMessage `json:"call_chains"`
	ForwardCalls      json.RawMessage   `json:"forward_calls,omitempty"`
	Reachability      string            `json:"reachability,omitempty"`
	Analysis          json.RawMessage   `json:"analysis,omitempty"`
}

type rawCallNode struct {
	CanonicalSignature string `json:"canonical_signature"`
}

// ComponentBlock projects one ComponentInput into one ComponentDataDTO block.
// Empty/nil Findings → block with Findings=[] and FindingCount=0; malformed
// JSON → error. See ComponentInput for the per-flag behavior.
func ComponentBlock(in ComponentInput) (*ComponentDataDTO, *BlockReport, error) { //nolint:funlen,gocognit,gocyclo // ComponentBlock renders one served block in a single pass over the stitched assets; the pass shares its filters
	maxChains := resolveMaxChains(in.MaxChainsPerAsset)

	var env rawFindingsEnvelope
	if len(in.Findings) > 0 {
		if err := json.Unmarshal(in.Findings, &env); err != nil {
			return nil, nil, fmt.Errorf("render: unmarshal findings: %w", err)
		}
		if err := ValidateSchemaVersion("findings", env.Version, FindingsSchemaVersion); err != nil {
			return nil, nil, err
		}
	}

	var cg CallgraphEnvelope
	if len(in.Callgraph) > 0 {
		if err := json.Unmarshal(in.Callgraph, &cg); err != nil {
			return nil, nil, fmt.Errorf("render: unmarshal callgraph: %w", err)
		}
		if err := ValidateSchemaVersion("callgraph", cg.SchemaVersion, CallgraphInternedSchemaVersion); err != nil {
			return nil, nil, err
		}
	}

	chainsByID := make(map[string][]json.RawMessage, len(cg.FindingGraphs))
	reachabilityByID := make(map[string]string, len(cg.FindingGraphs))
	analysisByID := make(map[string]json.RawMessage, len(cg.FindingGraphs))
	forwardCallsByID := make(map[string]json.RawMessage, len(cg.FindingGraphs))
	supportingIDsByID := make(map[string][]string, len(cg.FindingGraphs))
	var droppedCallChains []string
	for _, fgRaw := range cg.FindingGraphs {
		var fg RawFindingGraph
		if err := json.Unmarshal(fgRaw, &fg); err != nil {
			return nil, nil, fmt.Errorf("render: unmarshal finding_graph: %w", err)
		}
		chainsByID[fg.FindingID] = fg.CallChains
		hadIndexes := true
		if chainFramesNeedHydrate(fg.CallChains) {
			hydrated, gotIndexes, err := hydrateFindingGraphChains(cg.Functions, fgRaw)
			if err != nil {
				return nil, nil, err
			}
			chainsByID[fg.FindingID] = hydrated
			hadIndexes = gotIndexes
		}
		if hadIndexes {
			// Either never needed hydration, or hydration ran against real
			// call_chain_indexes. A frame still missing identity here means the
			// index resolved to a catalog entry that was itself blank — seen on a
			// self-contained crypto call whose anchor has no matching structural
			// function (a field or static initializer, say), which crypto-finder's
			// own stitch still reports as a real one-frame chain, by design. Drop
			// only that chain body; the finding, its reachability and analysis
			// stay. One such frame isn't evidence the rest of the component is
			// untrustworthy.
			kept, anyDropped := dropChainsMissingIdentity(chainsByID[fg.FindingID])
			chainsByID[fg.FindingID] = kept
			if anyDropped {
				droppedCallChains = append(droppedCallChains, fg.FindingID)
			}
		} else {
			// Needed hydration but call_chain_indexes was missing/empty, so
			// HydrateChainIdentities no-opped: the frames never had a chance to
			// resolve. That's the index itself being missing or invalid — genuine
			// corruption, not something a partial response should paper over.
			if err := requireHydratedChainIdentities(chainsByID[fg.FindingID]); err != nil {
				return nil, nil, err
			}
		}
		if fg.Reachability != "" {
			reachabilityByID[fg.FindingID] = fg.Reachability
		}
		if len(fg.Analysis) > 0 {
			analysisByID[fg.FindingID] = fg.Analysis
		}
		if len(fg.ForwardCalls) > 0 {
			forwardCallsByID[fg.FindingID] = fg.ForwardCalls
		}
		if len(fg.SupportingCallIDs) > 0 {
			supportingIDsByID[fg.FindingID] = fg.SupportingCallIDs
		}
	}

	sigFilter := buildSigFilter(in.EntryPointSignatures)
	matchedSigs := make(map[string]bool, len(in.EntryPointSignatures))

	var reachableSet map[string]bool
	if sigFilter != nil {
		reachableSet = make(map[string]bool, len(chainsByID))
		markEntryPointMatches(cg.CryptoEntryPoints, sigFilter, reachableSet, matchedSigs)
		markChainHeadMatches(chainsByID, sigFilter, reachableSet)
	}

	findings := make([]*FindingDTO, 0, len(env.Findings))
	totalAssets := 0
	survivingIDs := make(map[string]bool)
	referencedSupporting := make(map[string]bool)

	for _, file := range env.Findings {
		assets := make([]*CryptographicAssetDTO, 0, len(file.CryptographicAssets))
		var fileDependencyInfo *DependencyInfoDTO
		for _, raw := range file.CryptographicAssets {
			if sigFilter != nil && !reachableSet[raw.FindingID] {
				continue
			}

			if fileDependencyInfo == nil {
				fileDependencyInfo = toDependencyInfoDTO(raw.DependencyInfo)
			}

			asset := &CryptographicAssetDTO{
				FindingID:           raw.FindingID,
				OID:                 raw.OID,
				Match:               raw.Match,
				Source:              raw.Source,
				PURL:                raw.PURL,
				StartLine:           raw.StartLine,
				EndLine:             raw.EndLine,
				Metadata:            raw.Metadata,
				ParameterConditions: raw.ParameterConditions,
				Rules:               raw.Rules,
				PQC:                 pqc.Current(nil, raw.Metadata),
			}

			rawChains := chainsByID[raw.FindingID]

			if in.IncludeCallChains {
				filtered := filterChains(rawChains, sigFilter, matchedSigs)
				if maxChains < len(filtered) {
					filtered = filtered[:maxChains]
				}
				out, err := marshalRawArray(filtered)
				if err != nil {
					return nil, nil, fmt.Errorf("render: marshal call_chains: %w", err)
				}
				asset.CallChains = out
				asset.Reachability = reachabilityByID[raw.FindingID]
				asset.Analysis = analysisByID[raw.FindingID]
			} else if sigFilter != nil {
				for _, chain := range rawChains {
					if sigFilter[chainEntryPointSignature(chain)] {
						matchedSigs[chainEntryPointSignature(chain)] = true
					}
				}
			}

			if in.IncludeSupportingCalls {
				if ids := supportingIDsByID[raw.FindingID]; len(ids) > 0 {
					asset.SupportingCallIDs = ids
					for _, id := range ids {
						referencedSupporting[id] = true
					}
				}
			}
			if in.IncludeForwardCalls {
				asset.ForwardCalls = forwardCallsByID[raw.FindingID]
			}

			assets = append(assets, asset)
			survivingIDs[raw.FindingID] = true
		}
		if len(assets) == 0 {
			continue
		}
		findings = append(findings, &FindingDTO{
			FilePath:            file.FilePath,
			Language:            file.Language,
			DependencyInfo:      fileDependencyInfo,
			CryptographicAssets: assets,
		})
		totalAssets += len(assets)
	}

	var cryptoEntryPoints json.RawMessage
	if in.IncludeCryptoEntryPoints && len(cg.CryptoEntryPoints) > 0 {
		filtered := filterCryptoEntryPoints(cg.CryptoEntryPoints, survivingIDs, referencedSupporting)
		if len(filtered) > 0 {
			b, err := marshalRawArray(filtered)
			if err != nil {
				return nil, nil, fmt.Errorf("render: marshal crypto_entry_points: %w", err)
			}
			cryptoEntryPoints = b
		}
	}

	var supportingCalls json.RawMessage
	if in.IncludeSupportingCalls && len(cg.SupportingCalls) > 0 && len(referencedSupporting) > 0 {
		filtered := filterSupportingCalls(cg.SupportingCalls, referencedSupporting)
		if len(filtered) > 0 {
			b, err := marshalRawArray(filtered)
			if err != nil {
				return nil, nil, fmt.Errorf("render: marshal supporting_calls: %w", err)
			}
			supportingCalls = b
		}
	}

	var schemas *SchemasDTO
	if env.Version != "" || cg.SchemaVersion != "" {
		schemas = &SchemasDTO{
			Findings:  env.Version,
			Callgraph: cg.SchemaVersion,
		}
	}

	report := &BlockReport{
		UnmatchedSignatures: buildUnmatched(in.EntryPointSignatures, matchedSigs),
		DroppedCallChains:   droppedCallChains,
	}

	dto := &ComponentDataDTO{
		Purl:              in.Purl,
		Version:           in.Version,
		Requirement:       in.Requirement,
		Findings:          findings,
		FindingCount:      totalAssets,
		Schemas:           schemas,
		CryptoEntryPoints: cryptoEntryPoints,
		SupportingCalls:   supportingCalls,
	}
	return dto, report, nil
}

func toDependencyInfoDTO(raw *rawDependencyInfo) *DependencyInfoDTO {
	if raw == nil {
		return nil
	}
	return &DependencyInfoDTO{
		Module:  raw.Module,
		Version: raw.Version,
		PURL:    raw.PURL,
	}
}

func resolveMaxChains(requested int) int {
	if requested <= 0 {
		return int(^uint(0) >> 1) // math.MaxInt — "unlimited"
	}
	if requested > hardCapMaxChainsPerAsset {
		return hardCapMaxChainsPerAsset
	}
	return requested
}

func buildSigFilter(sigs []string) map[string]bool {
	if len(sigs) == 0 {
		return nil
	}
	m := make(map[string]bool, len(sigs))
	for _, s := range sigs {
		m[s] = true
	}
	return m
}

// markEntryPointMatches resolves the filter against `crypto_entry_points` — the
// index of every function a finding is reachable from — recording which findings
// survive and which supplied signatures were recognized.
//
// The index is the authority on "does this entry point reach this finding".
// Deriving the answer from chain heads instead can only see the entries some
// emitted chain happens to START at, and chains are capped per finding
// (hardCapMaxChainsPerAsset here, 128 per crypto op upstream), so the bulk of a
// dense library's index would filter to nothing while looking like a typo in
// `unmatched_signatures`. See #116.
func markEntryPointMatches(entries []json.RawMessage, sigFilter, reachable, matched map[string]bool) {
	for _, raw := range entries {
		var entry struct {
			CanonicalSignature string `json:"canonical_signature"`
			ErasedSignature    string `json:"erased_signature"`
			ReachableFindings  []struct {
				FindingID string `json:"finding_id"`
			} `json:"reachable_findings"`
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			continue
		}
		// Both published spellings are accepted. A generic API declares type
		// variables no call site can reproduce (`send(String, K, V)`), so a
		// consumer joining from erased bytecode can only supply the erased form.
		// `matched` records the spelling the CALLER supplied, or a signature that
		// did match would be reported back in unmatched_signatures.
		var hit bool
		for _, sig := range [2]string{entry.CanonicalSignature, entry.ErasedSignature} {
			if sig != "" && sigFilter[sig] {
				matched[sig] = true
				hit = true
			}
		}
		if !hit {
			continue
		}
		for _, finding := range entry.ReachableFindings {
			if finding.FindingID != "" {
				reachable[finding.FindingID] = true
			}
		}
	}
}

// markChainHeadMatches preserves the pre-#116 selection: a signature naming the
// first frame of an emitted chain also keeps that chain's finding. For a
// well-formed callgraph every chain head is in the index too, so this is
// redundant — it stays so that a caller already filtering on a chain head cannot
// be made worse off by the index becoming the primary source.
func markChainHeadMatches(chainsByID map[string][]json.RawMessage, sigFilter, reachable map[string]bool) {
	for findingID, chains := range chainsByID {
		for _, chain := range chains {
			if sigFilter[chainEntryPointSignature(chain)] {
				reachable[findingID] = true
				break
			}
		}
	}
}

func chainEntryPointSignature(chain json.RawMessage) string {
	var frames []json.RawMessage
	if err := json.Unmarshal(chain, &frames); err != nil || len(frames) == 0 {
		return ""
	}
	var frame rawCallNode
	if err := json.Unmarshal(frames[0], &frame); err != nil {
		return ""
	}
	return frame.CanonicalSignature
}

func chainFramesNeedHydrate(chains []json.RawMessage) bool {
	for _, chain := range chains {
		var frames []json.RawMessage
		if err := json.Unmarshal(chain, &frames); err != nil {
			return true
		}
		for _, frame := range frames {
			if frameMissingIdentity(frame) {
				return true
			}
		}
	}
	return false
}

func requireHydratedChainIdentities(chains []json.RawMessage) error {
	for _, chain := range chains {
		var frames []json.RawMessage
		if err := json.Unmarshal(chain, &frames); err != nil {
			return fmt.Errorf("render: interned callgraph frame missing identity: %w", err)
		}
		for _, frame := range frames {
			if frameMissingIdentity(frame) {
				return fmt.Errorf("render: interned callgraph frame missing identity")
			}
		}
	}
	return nil
}

// dropChainsMissingIdentity filters out any already-inline chain (one that
// never needed interned-catalog hydration) carrying a frame without identity,
// rather than failing the whole component block over it. Reports whether
// anything was dropped so the caller can log the anomaly.
func dropChainsMissingIdentity(chains []json.RawMessage) (kept []json.RawMessage, dropped bool) {
	kept = make([]json.RawMessage, 0, len(chains))
	for _, chain := range chains {
		var frames []json.RawMessage
		if err := json.Unmarshal(chain, &frames); err != nil {
			dropped = true
			continue
		}
		bad := false
		for _, frame := range frames {
			if frameMissingIdentity(frame) {
				bad = true
				break
			}
		}
		if bad {
			dropped = true
			continue
		}
		kept = append(kept, chain)
	}
	return kept, dropped
}

func frameMissingIdentity(frame json.RawMessage) bool {
	var node struct {
		FunctionName       string `json:"function_name"`
		CanonicalSignature string `json:"canonical_signature"`
	}
	if err := json.Unmarshal(frame, &node); err != nil {
		return true
	}
	return node.FunctionName == "" && node.CanonicalSignature == ""
}

// hydrateFindingGraphChains hydrates fgRaw's chains from catalog and reports
// whether call_chain_indexes was actually present. crypto-finder.
// HydrateChainIdentities treats an absent/empty indexes list as "nothing to
// hydrate" and returns success without touching a single frame — hadIndexes
// lets the caller tell that no-op apart from a hydration that genuinely ran
// (valid indexes resolved) but copied an identity that was itself blank.
func hydrateFindingGraphChains(catalog []ExportInternedFunction, fgRaw json.RawMessage) (chains []json.RawMessage, hadIndexes bool, err error) {
	var fg ExportFindingGraph
	if err := json.Unmarshal(fgRaw, &fg); err != nil {
		return nil, false, fmt.Errorf("render: unmarshal finding_graph for hydrate: %w", err)
	}
	if !HydrateChainIdentities(catalog, fg.CallChains, fg.CallChainIndexes) {
		return nil, false, fmt.Errorf("render: interned callgraph chain indexes")
	}
	out := make([]json.RawMessage, len(fg.CallChains))
	for i, chain := range fg.CallChains {
		raw, err := json.Marshal(chain)
		if err != nil {
			return nil, false, fmt.Errorf("render: marshal hydrated chain: %w", err)
		}
		out[i] = raw
	}
	return out, len(fg.CallChainIndexes) > 0, nil
}

func filterChains(chains []json.RawMessage, sigFilter, matchedSigs map[string]bool) []json.RawMessage {
	if sigFilter == nil {
		return chains
	}
	out := make([]json.RawMessage, 0, len(chains))
	for _, chain := range chains {
		sig := chainEntryPointSignature(chain)
		if sigFilter[sig] {
			matchedSigs[sig] = true
			out = append(out, chain)
		}
	}
	return out
}

func marshalRawArray(elems []json.RawMessage) (json.RawMessage, error) {
	if len(elems) == 0 {
		return json.RawMessage("[]"), nil
	}
	return json.Marshal(elems)
}

func filterCryptoEntryPoints(entries []json.RawMessage, surviving, referencedSupporting map[string]bool) []json.RawMessage { //nolint:gocognit // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	if len(entries) == 0 || len(surviving) == 0 {
		return nil
	}
	out := make([]json.RawMessage, 0, len(entries))
	for _, raw := range entries {
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entry); err != nil {
			continue
		}
		var findings []json.RawMessage
		if err := json.Unmarshal(entry["reachable_findings"], &findings); err != nil {
			continue
		}
		findings = filterRawReferences(findings, "finding_id", surviving)
		if len(findings) == 0 {
			continue
		}
		entry["reachable_findings"] = lenient(json.Marshal(findings))

		if rawCalls, ok := entry["reachable_supporting_calls"]; ok {
			var calls []json.RawMessage
			if err := json.Unmarshal(rawCalls, &calls); err != nil {
				continue
			}
			calls = filterRawReferences(calls, "supporting_id", referencedSupporting)
			if len(calls) == 0 {
				delete(entry, "reachable_supporting_calls")
			} else {
				entry["reachable_supporting_calls"] = lenient(json.Marshal(calls))
			}
		}
		filtered, err := json.Marshal(entry)
		if err == nil {
			out = append(out, filtered)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func filterRawReferences(values []json.RawMessage, field string, allowed map[string]bool) []json.RawMessage {
	out := values[:0]
	for _, raw := range values {
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(raw, &probe); err != nil {
			continue
		}
		var id string
		if err := json.Unmarshal(probe[field], &id); err == nil && allowed[id] {
			out = append(out, raw)
		}
	}
	return out
}

func filterSupportingCalls(calls []json.RawMessage, referenced map[string]bool) []json.RawMessage {
	if len(calls) == 0 || len(referenced) == 0 {
		return nil
	}
	out := make([]json.RawMessage, 0, len(referenced))
	for _, raw := range calls {
		var probe struct {
			SupportingID string `json:"supporting_id"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			continue
		}
		if referenced[probe.SupportingID] {
			out = append(out, raw)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func buildUnmatched(requested []string, matched map[string]bool) []string {
	if len(requested) == 0 {
		return nil
	}
	var out []string
	for _, sig := range requested {
		if !matched[sig] {
			out = append(out, sig)
		}
	}
	return out
}
