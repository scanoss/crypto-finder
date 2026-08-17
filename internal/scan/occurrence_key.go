// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/scanoss/crypto-finder/internal/callgraph"
	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

type occurrenceKeyGroup struct {
	assets   []*entities.CryptographicAsset
	line     int
	col      int
	identity string
}

type occurrenceKeyCandidate struct {
	asset      *entities.CryptographicAsset
	hash       string
	occurrence string
}

// AssignOccurrenceKeys attaches structural occurrence keys to canonical findings,
// using terminal call AST anchors when available and a file/module fallback otherwise.
func AssignOccurrenceKeys(result *engine.DepScanResult) {
	if result == nil || result.Report == nil || result.CallGraph == nil {
		return
	}
	assignOccurrenceKeyGroups(groupOccurrenceKeyCandidates(occurrenceKeyCandidates(result)))
}

func occurrenceKeyCandidates(result *engine.DepScanResult) []occurrenceKeyCandidate {
	ctx := newExportBuildContext(result)
	functions := occurrenceAnchorFunctions(result)
	var candidates []occurrenceKeyCandidate

	for i := range result.Report.Findings {
		finding := &result.Report.Findings[i]
		for j := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[j]
			asset.OccurrenceKey = ""
			containing := findOccurrenceContainingFunction(functions, finding.FilePath, asset.StartLine)
			if containing == nil {
				location := normalizeFindingPath(ctx, finding.FilePath, asset.DependencyInfo)
				hash := occurrenceKeyHash(occurrenceSourceSubject(result, asset), location.FilePath, "", "", "")
				occurrence := strings.Join([]string{location.FilePath, strconv.Itoa(asset.StartLine), strconv.Itoa(asset.StartCol), strconv.Itoa(asset.EndCol)}, "\n")
				candidates = append(candidates, occurrenceKeyCandidate{asset: asset, hash: hash, occurrence: occurrence})
				continue
			}
			terminal := findCryptoCallNode(ctx.graph, containing, *asset, asset.StartLine, asset.EndLine)
			if terminal == nil || terminal.ASTKind == "" || terminal.NamedASTPath == "" {
				continue
			}
			location := normalizeFindingPath(ctx, finding.FilePath, asset.DependencyInfo)
			container := buildExportFunctionMetadata(ctx.graph, containing.ID, containing).CanonicalSignature
			hash := occurrenceKeyHash(occurrenceSourceSubject(result, asset), location.FilePath, container, terminal.ASTKind, terminal.NamedASTPath)
			occurrence := strings.Join([]string{terminal.FilePath, strconv.Itoa(terminal.Line), strconv.Itoa(terminal.StartCol), strconv.Itoa(terminal.EndCol)}, "\n")
			candidates = append(candidates, occurrenceKeyCandidate{asset: asset, hash: hash, occurrence: occurrence})
		}
	}
	return candidates
}

func groupOccurrenceKeyCandidates(candidates []occurrenceKeyCandidate) map[string]map[string]*occurrenceKeyGroup {
	byHash := make(map[string]map[string]*occurrenceKeyGroup, len(candidates))
	for _, candidate := range candidates {
		groups := byHash[candidate.hash]
		if groups == nil {
			groups = make(map[string]*occurrenceKeyGroup)
			byHash[candidate.hash] = groups
		}
		group := groups[candidate.occurrence]
		if group == nil {
			group = &occurrenceKeyGroup{line: candidate.asset.StartLine, col: candidate.asset.StartCol, identity: candidate.occurrence}
			groups[candidate.occurrence] = group
		}
		group.assets = append(group.assets, candidate.asset)
	}
	return byHash
}

func assignOccurrenceKeyGroups(byHash map[string]map[string]*occurrenceKeyGroup) {
	for hash, groups := range byHash {
		ordered := make([]*occurrenceKeyGroup, 0, len(groups))
		for _, group := range groups {
			ordered = append(ordered, group)
		}
		sort.SliceStable(ordered, func(i, j int) bool { return occurrenceKeyGroupLess(ordered[i], ordered[j]) })
		for i, group := range ordered {
			key := "v1:" + hash
			if i > 0 {
				key += "-" + strconv.Itoa(i+1)
			}
			for _, asset := range group.assets {
				asset.OccurrenceKey = key
			}
		}
	}
}

func occurrenceKeyGroupLess(left, right *occurrenceKeyGroup) bool {
	if left.line != right.line {
		return left.line < right.line
	}
	if left.col != right.col {
		return left.col < right.col
	}
	return left.identity < right.identity
}

func occurrenceAnchorFunctions(result *engine.DepScanResult) map[string]*callgraph.FunctionDecl {
	functions := make(map[string]*callgraph.FunctionDecl)
	for key, fn := range result.CallGraph.Functions {
		functions[key] = fn
	}
	for key, fn := range result.OccurrenceAnchors {
		functions[key] = fn
	}
	return functions
}

func findOccurrenceContainingFunction(functions map[string]*callgraph.FunctionDecl, findingPath string, line int) *callgraph.FunctionDecl {
	normalized := filepath.ToSlash(dependencyRelativePath(findingPath))
	if normalized == "" {
		normalized = filepath.ToSlash(findingPath)
	}

	var best *callgraph.FunctionDecl
	for _, fn := range functions {
		if !hasPathSegmentSuffix(fn.FilePath, normalized) || line < fn.StartLine || line > fn.EndLine {
			continue
		}
		if best == nil || tighterSpan(fn, best) {
			best = fn
		}
	}
	return best
}

func hasPathSegmentSuffix(path, suffix string) bool {
	path = strings.Trim(filepath.ToSlash(path), "/")
	suffix = strings.Trim(filepath.ToSlash(suffix), "/")
	return path == suffix || strings.HasSuffix(path, "/"+suffix)
}

func occurrenceSourceSubject(result *engine.DepScanResult, asset *entities.CryptographicAsset) string {
	if asset != nil && asset.DependencyInfo != nil && asset.DependencyInfo.Module != "" && asset.DependencyInfo.Version != "" {
		return asset.DependencyInfo.Module + "@" + asset.DependencyInfo.Version
	}
	if result == nil {
		return ""
	}
	return result.RootModule
}

func occurrenceKeyHash(subject, path, container, nodeKind, namedASTPath string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{subject, path, container, nodeKind, namedASTPath}, "\n")))
	return hex.EncodeToString(sum[:])[:16]
}
