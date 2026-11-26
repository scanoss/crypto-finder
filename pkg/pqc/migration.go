// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package pqc

import (
	"encoding/json"
	"strings"

	pqcdataset "github.com/scanoss/crypto-pqc-dataset"
)

// Migration is a vulnerable finding's migration path: upgrade, swap, redesign
// or blocked, with its reason, whether it was inferred and its size risk. It is
// the API's own type, so a dataset release cannot change the response shape.
type Migration struct {
	Path     string `json:"path"`
	Reason   string `json:"reason"`
	Inferred bool   `json:"inferred"`
	SizeRisk string `json:"size_risk,omitempty"`
}

// Dependency is the dependency coordinate an indirect finding sits in.
type Dependency struct {
	Module, Version, Purl string
}

// MigrationFor returns the finding's migration path, or nil when it is not
// quantum-vulnerable.
func MigrationFor(c *Classification, metadata json.RawMessage, source, libraryPurl string, dep *Dependency) *Migration {
	// Only a vulnerable finding has a path; skip decoding the rest's metadata.
	if c == nil || c.Status != string(pqcdataset.Vulnerable) {
		return nil
	}
	var fields map[string]any
	if err := json.Unmarshal(metadata, &fields); err != nil {
		fields = nil // malformed metadata reads as empty
	}
	str := func(k string) string {
		s, ok := fields[k].(string)
		if !ok {
			return ""
		}
		return s
	}
	f := pqcdataset.Finding{
		Status:      pqcdataset.Status(c.Status),
		Family:      c.Family,
		Primitive:   str("algorithmPrimitive"),
		Operation:   str("operation"),
		Source:      source,
		LibraryPurl: libraryPurl,
	}
	if dep != nil {
		f.DependencyModule, f.DependencyPurl, f.DependencyVersion = dep.Module, dep.Purl, dep.Version
		if f.DependencyVersion == "" {
			f.DependencyVersion = purlVersion(dep.Purl)
		}
	}
	m, ok := pqcdataset.MigrationPath(f, pqcdataset.DefaultLibraries())
	if !ok {
		return nil
	}
	return &Migration{Path: string(m.Path), Reason: m.Reason, Inferred: m.Inferred, SizeRisk: m.SizeRisk}
}

// purlVersion is a purl's version: after the first @ before its qualifiers and
// subpath that does not follow a slash (a scoped npm name's @ does).
func purlVersion(purl string) string {
	base, _, _ := strings.Cut(purl, "#")
	base, _, _ = strings.Cut(base, "?")
	for i := 1; i < len(base); i++ {
		if base[i] == '@' && base[i-1] != '/' {
			return base[i+1:]
		}
	}
	return ""
}

// SummarizePaths returns the worst of a component's paths and the count per path.
func SummarizePaths(paths []string) (string, map[string]int) {
	in := make([]pqcdataset.Path, len(paths))
	for i, p := range paths {
		in[i] = pqcdataset.Path(p)
	}
	worst, counts := pqcdataset.ComponentPath(in)
	out := make(map[string]int, len(counts))
	for p, n := range counts {
		out[string(p)] = n
	}
	return string(worst), out
}
