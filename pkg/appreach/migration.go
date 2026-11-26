// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"slices"
	"strings"

	"github.com/scanoss/crypto-finder/pkg/pqc"
)

// MigrationSummaryDTO is one component's migration summary: the requested
// component for direct findings, a dependency for indirect ones.
type MigrationSummaryDTO struct {
	Component string         `json:"component"`
	Source    string         `json:"source"`
	Path      string         `json:"path"`
	Counts    map[string]int `json:"counts"`
	Inferred  int            `json:"inferred,omitempty"`
	SizeRisk  []string       `json:"size_risk,omitempty"`
}

// AnnotateMigration sets each vulnerable asset's migration path and the
// block's per-component summary.
func AnnotateMigration(block *ComponentDataDTO) { //nolint:gocognit,gocyclo // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	type group struct {
		summary MigrationSummaryDTO
		paths   []string
	}
	var order []string
	groups := map[string]*group{}
	self := block.Purl
	if block.Version != "" {
		self += "@" + block.Version
	}
	for _, f := range block.Findings {
		if f == nil {
			continue
		}
		for _, a := range f.CryptographicAssets {
			if a == nil {
				continue
			}
			// A stored "dependency" source is indirect even if it reaches here
			// unnormalised; only an indirect finding takes a dependency, and
			// its own coordinate wins over its file's.
			indirect := a.Source == SourceIndirect || a.Source == storedSourceDependency
			source := a.Source
			var dep *pqc.Dependency
			if indirect {
				source = SourceIndirect
				info := a.DependencyInfo
				if info == nil {
					info = f.DependencyInfo
				}
				if info != nil {
					dep = &pqc.Dependency{Module: info.Module, Version: info.Version, Purl: info.PURL}
				}
			}
			a.Migration = pqc.MigrationFor(a.PQC, a.Metadata, source, a.PURL, dep)
			if a.Migration == nil {
				continue
			}
			key := self
			if indirect {
				// An indirect finding with no dependency coordinate belongs to
				// no component: it keeps its path but stays out of the summary.
				if dep == nil || (dep.Purl == "" && dep.Module == "") {
					continue
				}
				key = dep.Purl
				if key == "" {
					key = dep.Module
				}
				key = withVersion(key, dep.Version)
			}
			g := groups[key]
			if g == nil {
				g = &group{summary: MigrationSummaryDTO{Component: key, Source: summarySource(indirect)}}
				groups[key] = g
				order = append(order, key)
			}
			g.paths = append(g.paths, a.Migration.Path)
			if a.Migration.Inferred {
				g.summary.Inferred++
			}
			if r := a.Migration.SizeRisk; r != "" && !slices.Contains(g.summary.SizeRisk, r) {
				g.summary.SizeRisk = append(g.summary.SizeRisk, r)
			}
		}
	}
	block.MigrationSummary = nil
	for _, key := range order {
		g := groups[key]
		g.summary.Path, g.summary.Counts = pqc.SummarizePaths(g.paths)
		block.MigrationSummary = append(block.MigrationSummary, g.summary)
	}
}

// withVersion appends version to a purl that names none, before its qualifiers
// and subpath.
func withVersion(purl, version string) string {
	if version == "" || hasVersion(purl) {
		return purl
	}
	end := strings.IndexAny(purl, "?#")
	if end < 0 {
		end = len(purl)
	}
	return purl[:end] + "@" + version + purl[end:]
}

// hasVersion reports whether a purl names a version: an @ before its
// qualifiers and subpath that does not follow a slash, since the @ of a scoped
// npm name (pkg:npm/@angular/core) does.
func hasVersion(purl string) bool {
	base, _, _ := strings.Cut(purl, "#")
	base, _, _ = strings.Cut(base, "?")
	for i := 1; i < len(base); i++ {
		if base[i] == '@' && base[i-1] != '/' {
			return true
		}
	}
	return false
}

func summarySource(indirect bool) string {
	if indirect {
		return SourceIndirect
	}
	return sourceDirect
}
