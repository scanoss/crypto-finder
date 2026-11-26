// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package appreach

import (
	"errors"

	packageurl "github.com/package-url/packageurl-go"
)

// ErrInvalidPurl is returned for a purl that does not parse, names no package, or misses a
// namespace its ecosystem requires.
var ErrInvalidPurl = errors.New("invalid purl")

// typesRequiringNamespace lists PURL types whose ecosystems make the namespace
// mandatory for addressability (Maven needs groupId).
var typesRequiringNamespace = map[string]bool{packageurl.TypeMaven: true}

// ParsePurl validates and canonicalizes a PURL. Its String() is the form the
// miners store components under.
func ParsePurl(s string) (packageurl.PackageURL, error) {
	if s == "" {
		return packageurl.PackageURL{}, ErrInvalidPurl
	}
	p, err := packageurl.FromString(s)
	if err != nil {
		return packageurl.PackageURL{}, ErrInvalidPurl
	}
	if p.Name == "" {
		return packageurl.PackageURL{}, ErrInvalidPurl
	}
	if typesRequiringNamespace[p.Type] && p.Namespace == "" {
		return packageurl.PackageURL{}, ErrInvalidPurl
	}
	if p.Type == packageurl.TypePyPi {
		// The miner stores a distribution under its PEP 503 name.
		p.Name = canonicalPyPIName(p.Name)
	}
	return p, nil
}
