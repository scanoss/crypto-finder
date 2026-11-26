// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"encoding/json"

	gf "github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/crypto-finder/pkg/conditioned"

	"github.com/scanoss/crypto-finder/pkg/pqc"
)

// A dependency's generic finding on a call whose selector is a parameter of
// its function (bcprov's DefaultJcaJceHelper.createSecretKeyFactory(algorithm)
// -> SecretKeyFactory.getInstance(algorithm)) gets its values from the
// components that call it (bcpkix passes "PBKDF-OpenSSL"). The miner, which
// scans each component alone, cannot specialize it; the project request holds
// the closure, so the stitch traces those calls and the client's conditioned
// rules specialize each anchor with the values found (crypto-finder
// pkg/conditioned, the code the offline mode runs). Each specialized asset is
// served beside its anchor, under the dependency that holds it.

// MaxConditionedRules bounds the conditioned rules one request may carry; a
// ruleset has a few hundred.
const MaxConditionedRules = 10000

// verdictRank orders verdicts by how much they claim.
func verdictRank(v string) int {
	switch v {
	case VerdictReachable:
		return 2
	case VerdictUnknown:
		return 1
	default:
		return 0
	}
}

// conditionedExpansions groups a plan's expansions by the dependency and
// stored finding id of their anchor.
type conditionedExpansions map[ComponentKey]map[string][]conditioned.Expansion

func groupExpansions(expansions []conditioned.Expansion) conditionedExpansions {
	out := make(conditionedExpansions)
	for _, e := range expansions {
		key, id := e.Anchor.Component, e.Anchor.Operation.FindingID
		if id == "" {
			continue
		}
		if out[key] == nil {
			out[key] = make(map[string][]conditioned.Expansion)
		}
		out[key][id] = append(out[key][id], e)
	}
	return out
}

// addConditionedAssets appends to each served file of a dependency the assets
// its anchors yield, after the anchor's own verdict is set. stored holds the
// files as stored, whose paths the ids hash; served is their served copy, in
// the same order. A value whose asset the file already holds (one the miner
// specialized from the component's own values) adds nothing. It returns the
// assets added.
func addConditionedAssets(frag *Fragment, stored, served []*FindingDTO, byAnchor map[string][]conditioned.Expansion) []*CryptographicAssetDTO { //nolint:gocognit // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	if len(byAnchor) == 0 {
		return nil
	}
	var added []*CryptographicAssetDTO
	for i, file := range served {
		existing := make(map[string]bool, len(file.CryptographicAssets))
		for _, asset := range file.CryptographicAssets {
			existing[conditionedAssetKey(asset)] = true
		}
		anchors := file.CryptographicAssets
		for _, anchor := range anchors {
			for _, e := range byAnchor[anchor.FindingID] {
				if e.Truncated {
					anchor.Analysis = withCallChainsPartial(anchor.Analysis)
				}
				for _, spec := range e.Specializations {
					asset := specializedAsset(frag, stored[i].FilePath, anchor, e, spec)
					if key := conditionedAssetKey(asset); !existing[key] {
						existing[key] = true
						file.CryptographicAssets = append(file.CryptographicAssets, asset)
						added = append(added, asset)
					}
				}
			}
		}
	}
	return added
}

// specializedAsset is anchor specialized by spec: anchor's span, match and
// dependency, the rule and metadata of the value, ids derived as the scan
// derives them, and a verdict no stronger than the anchor's (a route to the
// value is a route to the anchor).
func specializedAsset(frag *Fragment, storedPath string, anchor *CryptographicAssetDTO, e conditioned.Expansion, spec conditioned.ClosureSpecialization) *CryptographicAssetDTO {
	asset := *anchor
	rule := spec.Rule
	metadata := lenient(json.Marshal(spec.Metadata))     // a string map always encodes
	conditions := lenient(json.Marshal(spec.Conditions)) // plain values always encode
	asset.FindingID = conditioned.FindingID(storedPath, anchor.StartLine, rule.ID, spec.ConditionedValue)
	asset.OID, asset.PURL = "", rule.PURL
	asset.Metadata, asset.ParameterConditions = metadata, conditions
	asset.Rules = []CryptoRuleDTO{{ID: rule.ID, Message: rule.Message, Severity: rule.Severity}}
	asset.ConditionedValue = spec.ConditionedValue
	asset.TerminalStartCol, asset.TerminalEndCol = conditioned.TerminalColumns(frag, e.Anchor.Operation, anchor.StartCol, anchor.EndCol)
	asset.OccurrenceKey = conditioned.OccurrenceKey(anchor.OccurrenceKey, spec.ConditionedValue)
	asset.PQC, asset.Migration = pqc.Current(nil, metadata), nil
	asset.CallChains, asset.ForwardCalls, asset.SupportingCallIDs = nil, nil, nil
	asset.Reachability, asset.ReachabilityReason = spec.Reachability, spec.UnresolvedReason
	if verdictRank(anchor.Reachability) < verdictRank(spec.Reachability) {
		asset.Reachability, asset.ReachabilityReason = anchor.Reachability, anchor.ReachabilityReason
	}
	chains := gf.AnalysisComplete
	if e.Truncated {
		chains = gf.AnalysisPartial
	}
	asset.Analysis = lenient(json.Marshal(map[string]string{"call_chains": chains, "parameters": gf.AnalysisComplete}))
	return &asset
}

// conditionedAssetKey is the identity of an asset as a scan dedupes the assets
// specialization adds: its first rule, span and metadata.
func conditionedAssetKey(a *CryptographicAssetDTO) string {
	rule := ""
	if len(a.Rules) > 0 {
		rule = a.Rules[0].ID
	}
	var metadata map[string]any
	discard(json.Unmarshal(a.Metadata, &metadata)) // absent or malformed metadata keys as empty
	canonical := lenient(json.Marshal(metadata))   // map keys encode sorted
	span := lenient(json.Marshal([4]int{a.StartLine, a.StartCol, a.EndLine, a.EndCol}))
	return rule + "\x00" + string(span) + "\x00" + string(canonical)
}

// withCallChainsPartial is analysis with call_chains partial: a value of the
// anchor's selector may be missing, and with it an asset.
func withCallChainsPartial(analysis json.RawMessage) json.RawMessage {
	fields := map[string]any{}
	discard(json.Unmarshal(analysis, &fields)) // absent analysis starts empty
	fields["call_chains"] = gf.AnalysisPartial
	out := lenient(json.Marshal(fields))
	return out
}
