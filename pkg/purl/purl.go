// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package purl builds package URLs for dependency metadata exported by crypto-finder.
package purl

import (
	"fmt"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

// Rule returns a canonical versionless package URL from rule metadata.
// Versioned rule PURLs are rejected because rules identify libraries, while
// resolver output owns the optional version enrichment.
func Rule(raw string) string {
	p, ok := parse(raw)
	if !ok || p.Version != "" {
		return ""
	}
	return p.ToString()
}

// Identity returns the normalized type, namespace, and name of a package URL.
// Those are the identity fields used when matching a rule PURL to a resolved
// dependency; qualifiers, subpaths, and versions do not select a package.
func Identity(raw string) (string, bool) {
	p, ok := parse(raw)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%s\x00%s\x00%s", p.Type, p.Namespace, p.Name), true
}

// WithVersion adds a resolved version to a valid versionless rule PURL.
func WithVersion(raw, version string) string {
	p, ok := parse(raw)
	if !ok || p.Version != "" || strings.TrimSpace(version) == "" {
		return ""
	}
	p.Version = strings.TrimSpace(version)
	if err := p.Normalize(); err != nil {
		return ""
	}
	return p.ToString()
}

func parse(raw string) (packageurl.PackageURL, bool) {
	p, err := packageurl.FromString(strings.TrimSpace(raw))
	if err != nil || p.Type == "" || p.Name == "" {
		return packageurl.PackageURL{}, false
	}
	if p.Type == packageurl.TypePyPi {
		p.Name = normalizePyPIName(p.Name)
	}
	if err := p.Normalize(); err != nil {
		return packageurl.PackageURL{}, false
	}
	return p, true
}

// Dependency returns the canonical package URL for a supported resolver
// ecosystem. It returns an empty string when the ecosystem or module is not
// supported, or when the module cannot identify a package.
func Dependency(ecosystem, module, version string) string {
	var typ, namespace, name string
	switch ecosystem {
	case "java":
		var ok bool
		namespace, name, ok = strings.Cut(module, ":")
		if !ok || namespace == "" || name == "" {
			return ""
		}
		typ = packageurl.TypeMaven
	case "python":
		typ, name = packageurl.TypePyPi, normalizePyPIName(module)
	case "go":
		typ = packageurl.TypeGolang
		namespace, name = splitModule(module)
	case "rust":
		typ, name = packageurl.TypeCargo, module
	default:
		return ""
	}
	if name == "" {
		return ""
	}

	p := packageurl.NewPackageURL(typ, namespace, name, version, nil, "")
	if err := p.Normalize(); err != nil {
		return ""
	}
	return p.ToString()
}

func splitModule(module string) (namespace, name string) {
	if index := strings.LastIndexByte(module, '/'); index >= 0 {
		return module[:index], module[index+1:]
	}
	return "", module
}

func normalizePyPIName(name string) string {
	name = strings.ToLower(name)
	name = strings.NewReplacer(".", "-", "_", "-").Replace(name)
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	return name
}
