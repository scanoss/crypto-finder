// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	gf "github.com/scanoss/reach/graphfrag"
	pkgpurl "github.com/scanoss/reach/purl"
)

// StitchWithContext runs gf.StitchWithOptions on its own goroutine so ctx's
// deadline can abort a pathologically large graph walk: StitchWithOptions
// itself takes no context and never checks cancellation, so without this a
// caller's timeout budget is unenforceable once the graphs are loaded.
func StitchWithContext(ctx context.Context, root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment, opts StitchOptions) (*Result, error) {
	type outcome struct {
		res *Result
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		res, err := gf.StitchWithOptions(root, deps, fragments, opts)
		ch <- outcome{res, err}
	}()
	select {
	case o := <-ch:
		return o.res, o.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

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

// DepPrefixedPath is a dependency file's path as the stitch names it:
// module@version/path.
func DepPrefixedPath(filePath, module, version string) string {
	if filePath == "" || module == "" || version == "" {
		return filePath
	}
	return module + "@" + version + "/" + filePath
}

// ComputeFindingID is the finding id the stitch gives a crypto operation
// (graphfrag's own, which is unexported).
func ComputeFindingID(path string, startLine int, ruleID string) string {
	if path == "" && startLine == 0 && ruleID == "" {
		return ""
	}
	h := sha256.Sum256([]byte(path + ":" + strconv.Itoa(startLine) + ":" + ruleID))
	return hex.EncodeToString(h[:])[:8]
}

// PurlToModule converts a purl to crypto-finder's module id: "<group>:<artifact>"
// for Maven, the PEP 503 normalised distribution name for PyPI (what the
// Python dependency resolver names a dependency; not the import name, which
// a distribution may not share and a namespace package shares with others).
// The module path for Go and the package id for NuGet. Other purls pass
// through unchanged.
func PurlToModule(purl string) string {
	if rest, ok := strings.CutPrefix(purl, "pkg:golang/"); ok {
		if i := strings.IndexAny(rest, "@?#"); i >= 0 {
			rest = rest[:i]
		}
		if rest != "" {
			return rest
		}
		return purl
	}
	if rest, ok := strings.CutPrefix(purl, "pkg:pypi/"); ok {
		if i := strings.IndexAny(rest, "@?#"); i >= 0 {
			rest = rest[:i]
		}
		if rest == "" {
			return purl
		}
		return pkgpurl.PyPIName(rest)
	}
	if rest, ok := strings.CutPrefix(purl, "pkg:nuget/"); ok {
		if i := strings.IndexAny(rest, "@?#"); i >= 0 {
			rest = rest[:i]
		}
		if rest != "" {
			return rest
		}
		return purl
	}
	const prefix = "pkg:maven/"
	if !strings.HasPrefix(purl, prefix) {
		return purl
	}
	rest := purl[len(prefix):]
	group, artifact, ok := strings.Cut(rest, "/")
	if !ok {
		return purl
	}
	return group + ":" + artifact
}

// EcosystemForPurl is crypto-finder's ecosystem name for a purl's type.
func EcosystemForPurl(purl string) string {
	return gf.EcosystemForPurl(purl)
}
