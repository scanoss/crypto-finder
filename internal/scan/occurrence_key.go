// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
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
	engine.MarkSyntheticVariants(result.Report)
	assignOccurrenceKeyGroups(groupOccurrenceKeyCandidates(occurrenceKeyCandidates(result)))
}

func occurrenceKeyCandidates(result *engine.DepScanResult) []occurrenceKeyCandidate {
	ctx := newExportPathContext(result)
	functions := newFunctionFileIndex(&ctx.exportArtifacts, occurrenceAnchorFunctions(result))
	var candidates []occurrenceKeyCandidate

	for i := range result.Report.Findings {
		finding := &result.Report.Findings[i]
		for j := range finding.CryptographicAssets {
			asset := &finding.CryptographicAssets[j]
			asset.OccurrenceKey = ""
			var containing *callgraph.FunctionDecl
			if file, ok := ctx.findingFile(finding.FilePath, asset.DependencyInfo); ok {
				containing = functions.containing(file, asset.StartLine, asset.StartCol)
			}
			if containing == nil {
				location := normalizeFindingPath(ctx, finding.FilePath, asset.DependencyInfo)
				hash := occurrenceKeyHash(occurrenceSourceSubject(result, asset), location.FilePath, "", "", "", asset.ConditionedValue)
				occurrence := strings.Join([]string{location.FilePath, strconv.Itoa(asset.StartLine), strconv.Itoa(asset.StartCol), strconv.Itoa(asset.EndCol)}, "\n")
				candidates = append(candidates, occurrenceKeyCandidate{asset: asset, hash: hash, occurrence: occurrence})
				continue
			}
			terminal := findCryptoCallNode(ctx.graph, containing, *asset, asset.StartLine, asset.EndLine)
			location := normalizeFindingPath(ctx, finding.FilePath, asset.DependencyInfo)
			container := buildExportFunctionMetadata(ctx.graph, containing.ID, containing).CanonicalSignature
			if terminal == nil || terminal.ASTKind == "" || terminal.NamedASTPath == "" {
				// No call anchors the match: a library API declaration, or a
				// type usage such as a cast or a declaration. Key it by the
				// function that holds it and its position, so every asset a
				// finding graph is built for can be joined by occurrence key.
				hash := occurrenceKeyHash(occurrenceSourceSubject(result, asset), location.FilePath, container, "", "", asset.ConditionedValue)
				occurrence := strings.Join([]string{location.FilePath, strconv.Itoa(asset.StartLine), strconv.Itoa(asset.StartCol), strconv.Itoa(asset.EndCol)}, "\n")
				candidates = append(candidates, occurrenceKeyCandidate{asset: asset, hash: hash, occurrence: occurrence})
				continue
			}
			hash := occurrenceKeyHash(occurrenceSourceSubject(result, asset), location.FilePath, container, terminal.ASTKind, terminal.NamedASTPath, asset.ConditionedValue)
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
	for _, groups := range byHash {
		splitTwoMatchesOfOneRule(groups)
	}
	return byHash
}

// splitTwoMatchesOfOneRule keeps two matches of one rule apart when both
// anchor to the same call. That happens when the call graph cannot place a
// match: a span that ends on a later line, or a report whose lines do not hold
// the call, falls back to the best call on its lines, so the two calls of
// provider == null ? SSLContext.getInstance(p) : SSLContext.getInstance(p, provider)
// can both land on one. A rule reports a call once, so its two spans are two
// occurrences. The first match in source order stays in the group and keeps its
// key; each later one opens a group of its own, ordered by its position like
// any other collision, so it gets the next -N suffix. An asset of another rule
// joins the call whose span holds it (partHolding), else the first call it does
// not conflict with. A group no rule matched twice is left as it is, so its key
// does not change.
func splitTwoMatchesOfOneRule(groups map[string]*occurrenceKeyGroup) {
	var split []*occurrenceKeyGroup
	for _, group := range groups {
		if len(group.assets) < 2 {
			continue
		}
		assets := append([]*entities.CryptographicAsset(nil), group.assets...)
		sort.SliceStable(assets, func(i, j int) bool { return assetSpanLess(assets[i], assets[j]) })
		var parts [][]*entities.CryptographicAsset
		for _, asset := range assets {
			i := partHolding(parts, asset)
			if i < 0 {
				i = slices.IndexFunc(parts, func(part []*entities.CryptographicAsset) bool {
					return !conflictsWithPart(part, asset)
				})
			}
			if i < 0 {
				parts = append(parts, []*entities.CryptographicAsset{asset})
				continue
			}
			parts[i] = append(parts[i], asset)
		}
		if len(parts) == 1 {
			continue
		}
		// The group takes the position of its first match, so a later match
		// never orders before it and takes its key.
		group.assets = parts[0]
		group.line, group.col = parts[0][0].StartLine, parts[0][0].StartCol
		for n, part := range parts[1:] {
			first := part[0]
			split = append(split, &occurrenceKeyGroup{
				assets:   part,
				line:     first.StartLine,
				col:      first.StartCol,
				identity: group.identity + "\n" + assetSpan(first) + "#" + strconv.Itoa(n+1),
			})
		}
	}
	for _, group := range split {
		groups[group.identity] = group
	}
}

// partHolding is the part whose call span (its first match, which opened it)
// contains asset and which asset does not conflict with, the innermost when
// several do; -1 when none. An asset of another rule belongs to the call it
// sits in: without this, first-fit sent a provider argument of the second
// call of a ternary to the first call, the first part it did not conflict
// with.
func partHolding(parts [][]*entities.CryptographicAsset, asset *entities.CryptographicAsset) int {
	best := -1
	for i, part := range parts {
		if !spanContains(part[0], asset) || conflictsWithPart(part, asset) {
			continue
		}
		if best < 0 || spanContains(parts[best][0], part[0]) {
			best = i
		}
	}
	return best
}

func conflictsWithPart(part []*entities.CryptographicAsset, asset *entities.CryptographicAsset) bool {
	return slices.ContainsFunc(part, func(member *entities.CryptographicAsset) bool { return twoMatchesOfOneRule(member, asset) })
}

// spanContains reports that inner's span lies within outer's.
func spanContains(outer, inner *entities.CryptographicAsset) bool {
	startsAfter := inner.StartLine > outer.StartLine || (inner.StartLine == outer.StartLine && inner.StartCol >= outer.StartCol)
	endsBefore := inner.EndLine < outer.EndLine || (inner.EndLine == outer.EndLine && inner.EndCol <= outer.EndCol)
	return startsAfter && endsBefore
}

// twoMatchesOfOneRule reports that a rule both assets list matched each of
// them at a different span, the deduplicator's test for two calls.
func twoMatchesOfOneRule(a, b *entities.CryptographicAsset) bool {
	if assetSpan(a) == assetSpan(b) {
		return false
	}
	return slices.ContainsFunc(a.Rules, func(rule entities.RuleInfo) bool {
		return slices.ContainsFunc(b.Rules, func(other entities.RuleInfo) bool { return other.ID == rule.ID })
	})
}

func assetSpan(asset *entities.CryptographicAsset) string {
	return strings.Join([]string{strconv.Itoa(asset.StartLine), strconv.Itoa(asset.StartCol), strconv.Itoa(asset.EndLine), strconv.Itoa(asset.EndCol)}, ":")
}

func assetSpanLess(a, b *entities.CryptographicAsset) bool {
	if a.StartLine != b.StartLine {
		return a.StartLine < b.StartLine
	}
	if a.StartCol != b.StartCol {
		return a.StartCol < b.StartCol
	}
	if a.EndLine != b.EndLine {
		return a.EndLine < b.EndLine
	}
	return a.EndCol < b.EndCol
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

func occurrenceSourceSubject(result *engine.DepScanResult, asset *entities.CryptographicAsset) string {
	if asset != nil && asset.DependencyInfo != nil && asset.DependencyInfo.Module != "" && asset.DependencyInfo.Version != "" {
		return asset.DependencyInfo.Module + "@" + asset.DependencyInfo.Version
	}
	if result == nil {
		return ""
	}
	return result.RootModule
}

// occurrenceKeyHash hashes the structural identity of one occurrence. A
// per-value asset adds its resolved condition, so the values of one call get
// distinct keys; every other asset hashes exactly what it always did.
func occurrenceKeyHash(subject, path, container, nodeKind, namedASTPath, conditionedValue string) string {
	parts := []string{subject, path, container, nodeKind, namedASTPath}
	if conditionedValue != "" {
		parts = append(parts, conditionedValue)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])[:16]
}
