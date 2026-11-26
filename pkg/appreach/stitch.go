// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"encoding/json"

	"github.com/Masterminds/semver/v3"
)

// HighestRulesVersion returns the highest rules_version among the contributing
// blocks (semver-aware; semver tags outrank non-semver; lexical fallback).
func HighestRulesVersion(versions []string) string {
	best := ""
	var bestSem *semver.Version
	for _, rv := range versions {
		if rv == "" {
			continue
		}
		if sv, err := semver.NewVersion(rv); err == nil {
			if bestSem == nil || sv.GreaterThan(bestSem) {
				bestSem, best = sv, rv
			}
			continue
		}
		if bestSem == nil && rv > best {
			best = rv
		}
	}
	return best
}

type assetWithRules struct {
	FindingAsset
	Rules []CryptoRuleDTO `json:"rules,omitempty"`
}

type fileWithRules struct {
	Language            string           `json:"language"`
	FilePath            string           `json:"file_path"`
	CryptographicAssets []assetWithRules `json:"cryptographic_assets"`
}

type envelopeWithRules struct {
	Version  string          `json:"version"`
	Findings []fileWithRules `json:"findings"`
}

// MarshalFindingsJSON projects RuleID onto ToFindingsEnvelope. Callers that
// marshal the envelope themselves must use this or rules stay empty.
func MarshalFindingsJSON(root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment, meta ScanMeta) ([]byte, error) {
	return MarshalFindingsEnvelope(root, ToFindingsEnvelope(root, deps, fragments, meta), fragments)
}

// MarshalFindingsEnvelope marshals env with each asset's rule id: the rule of
// the operation its finding id was computed from.
func MarshalFindingsEnvelope(root ComponentKey, env FindingsEnvelope, fragments map[ComponentKey]Fragment) ([]byte, error) {
	return json.Marshal(projectRuleIDs(root, env, fragments))
}

func projectRuleIDs(root ComponentKey, env FindingsEnvelope, fragments map[ComponentKey]Fragment) envelopeWithRules {
	index := ruleIDByFindingID(root, fragments)
	out := envelopeWithRules{Version: env.Version, Findings: make([]fileWithRules, 0, len(env.Findings))}
	for _, file := range env.Findings {
		assets := make([]assetWithRules, 0, len(file.CryptographicAssets))
		for _, asset := range file.CryptographicAssets {
			wrapped := assetWithRules{FindingAsset: asset}
			if id := index[asset.FindingID]; id != "" {
				wrapped.Rules = []CryptoRuleDTO{{ID: id}}
			}
			assets = append(assets, wrapped)
		}
		out.Findings = append(out.Findings, fileWithRules{
			Language:            file.Language,
			FilePath:            file.FilePath,
			CryptographicAssets: assets,
		})
	}
	return out
}

func ruleIDByFindingID(root ComponentKey, fragments map[ComponentKey]Fragment) map[string]string {
	index := make(map[string]string)
	for key, frag := range fragments {
		for i := range frag.CryptoOperations {
			op := &frag.CryptoOperations[i]
			if op.RuleID == "" {
				continue
			}
			path := op.FilePath
			if key != root {
				path = DepPrefixedPath(op.FilePath, frag.Module, key.Version)
			}
			index[ComputeFindingID(path, op.StartLine, op.RuleID)] = op.RuleID
		}
	}
	return index
}
