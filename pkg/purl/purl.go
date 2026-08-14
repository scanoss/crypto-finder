// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

// Package purl builds package URLs for dependency metadata exported by crypto-finder.
package purl

import (
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

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
