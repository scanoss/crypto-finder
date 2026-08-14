// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/scanoss/crypto-finder/internal/engine"
	"github.com/scanoss/crypto-finder/internal/entities"
)

// AssignOccurrenceKeys attaches structural occurrence keys to canonical findings
// when the callgraph retains the terminal call's AST anchor.
func AssignOccurrenceKeys(result *engine.DepScanResult) {
	if result == nil || result.Report == nil || result.CallGraph == nil {
		return
	}

	ctx := newExportBuildContext(result)
	type candidate struct {
		asset *entities.CryptographicAsset
		hash  string
	}
	var candidates []candidate

	for i := range result.Report.Findings {
		finding := &result.Report.Findings[i]
		for j := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[j]
			asset.OccurrenceKey = ""
			containing := ctx.findContainingFunctionByFinding(finding.FilePath, asset.StartLine)
			if containing == nil {
				continue
			}
			terminal := findCryptoCallNode(ctx.graph, containing, *asset, asset.StartLine, asset.EndLine)
			if terminal == nil || terminal.ASTKind == "" || terminal.NamedASTPath == "" {
				continue
			}
			location := normalizeFindingPath(ctx, finding.FilePath, asset.DependencyInfo)
			container := buildExportFunctionMetadata(ctx.graph, containing.ID, containing).CanonicalSignature
			hash := occurrenceKeyHash(occurrenceSourceSubject(result, asset), location.FilePath, container, terminal.ASTKind, terminal.NamedASTPath)
			candidates = append(candidates, candidate{asset: asset, hash: hash})
		}
	}

	byHash := make(map[string][]candidate, len(candidates))
	for _, candidate := range candidates {
		byHash[candidate.hash] = append(byHash[candidate.hash], candidate)
	}
	for hash, group := range byHash {
		sort.SliceStable(group, func(i, j int) bool {
			if group[i].asset.StartLine != group[j].asset.StartLine {
				return group[i].asset.StartLine < group[j].asset.StartLine
			}
			return group[i].asset.StartCol < group[j].asset.StartCol
		})
		for i := range group {
			key := "v1:" + hash
			if i > 0 {
				key += "-" + strconv.Itoa(i+1)
			}
			group[i].asset.OccurrenceKey = key
		}
	}
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
