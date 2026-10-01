// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package scan

import (
	"strings"

	"github.com/scanoss/crypto-finder/internal/callgraph"
)

// conditionedKeyMatcher decides whether a conditioned-rule catalog key, the
// API symbol a rule pattern spells, names the callee of a call. A key is
// written the way source code refers to the API, while the callee is the
// resolved FunctionID, so the comparison follows each ecosystem's spelling.
type conditionedKeyMatcher struct {
	ecosystem string
	// goPackageNames maps a Go import path to the package clause names its
	// parsed declarations carry. A package whose source is not in the graph
	// has no entry.
	goPackageNames map[string][]string
}

func newConditionedKeyMatcher(graph *callgraph.CallGraph, ecosystem string) conditionedKeyMatcher {
	m := conditionedKeyMatcher{ecosystem: ecosystem}
	if ecosystem == ecosystemGo && graph != nil {
		m.goPackageNames = goPackageClauseNames(graph)
	}
	return m
}

func (m conditionedKeyMatcher) matches(key string, call *callgraph.FunctionCall) bool {
	callee := strings.TrimSpace(fullFunctionName(call.Callee))
	if callee == "" {
		return false
	}
	switch m.ecosystem {
	case ecosystemRust:
		return rustKeyMatches(key, callee)
	case ecosystemGo:
		return m.goKeyMatches(key, call, callee)
	default:
		return key == callee || strings.HasSuffix(key, "."+callee) || strings.HasSuffix(callee, "."+key)
	}
}

// endsWithSegments reports whether key names path or its trailing
// "."-separated segments.
func endsWithSegments(path, key string) bool {
	return path == key || strings.HasSuffix(path, "."+key)
}

// rustKeyMatches compares a Rust key and callee as paths. A rule spells a path
// with "::" ("openssl::hash::MessageDigest::from_name") and the call graph
// joins a module path to its type and method with "."
// ("openssl::hash.MessageDigest.from_name"), so both are spelled with "."
// between every segment, as rule entry-point synthesis does. A key written
// with fewer leading segments ("MessageDigest::from_name") names a callee that
// ends with them. A callee is never widened into a key: an unresolved "new"
// does not name every "<Type>::new" a catalog holds.
func rustKeyMatches(key, callee string) bool {
	return endsWithSegments(rustSegmentPath(callee), rustSegmentPath(key))
}

func rustSegmentPath(path string) string {
	return strings.ReplaceAll(path, "::", ".")
}

// goKeyMatches compares a Go key such as "jwt.GetSigningMethod" with a callee
// whose Package is the import path ("github.com/golang-jwt/jwt/v5"). The key's
// qualifier is the package as Go code refers to it, its name, so it matches
// when it is the name of the callee's package. A key naming the callee's
// trailing segments ("GetSigningMethod") still matches.
//
// A callee with no package is a selector the parser could not resolve: its
// qualifier is no import binding and no typed local. Its key must be the call
// as written ("jwt.NewWithClaims" for an import whose path does not spell its
// package name), not any key that ends with the bare method name.
func (m conditionedKeyMatcher) goKeyMatches(key string, call *callgraph.FunctionCall, callee string) bool {
	if endsWithSegments(callee, key) {
		return true
	}
	if call.Callee.Package == "" {
		return key == strings.TrimSpace(call.Raw)
	}
	local := strings.TrimPrefix(callee, sanitizeSymbol(call.Callee.Package)+".")
	for _, name := range m.goPackageNamesOf(call.Callee.Package) {
		if key == name+"."+local {
			return true
		}
	}
	return false
}

// goPackageNamesOf returns the names a Go package is referred to by: the
// package clause of its parsed declarations, or, for a package whose source
// is not in the graph, the name an unaliased import of it binds.
func (m conditionedKeyMatcher) goPackageNamesOf(importPath string) []string {
	if names := m.goPackageNames[importPath]; len(names) > 0 {
		return names
	}
	return []string{callgraph.GoImplicitImportName(importPath)}
}

func goPackageClauseNames(graph *callgraph.CallGraph) map[string][]string {
	out := make(map[string][]string)
	for _, fn := range graph.Functions {
		if fn == nil || fn.OwnerType != "package" || fn.OwnerName == "" || fn.ID.Package == "" {
			continue
		}
		names := out[fn.ID.Package]
		known := false
		for _, name := range names {
			known = known || name == fn.OwnerName
		}
		if !known {
			out[fn.ID.Package] = append(names, fn.OwnerName)
		}
	}
	return out
}
