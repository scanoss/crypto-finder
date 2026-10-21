// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

package converter

import (
	"sort"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/scanoss/crypto-finder/internal/entities"
)

// dependencyLibraries collects, per dependency package URL, the crypto assets
// found in it. A CBOM links a library to the assets it uses through the
// dependency graph, so each dependency becomes a library component whose
// bom-ref is its package URL and whose dependsOn lists those assets.
type dependencyLibraries map[string]*dependencyLibrary

type dependencyLibrary struct {
	info   entities.DependencyInfo
	assets map[string]bool
}

func (l dependencyLibraries) add(assetRef string, occurrences []AssetOccurrence) {
	for _, occ := range occurrences {
		if occ.Dependency == nil {
			continue
		}
		lib, ok := l[occ.Dependency.PURL]
		if !ok {
			lib = &dependencyLibrary{info: *occ.Dependency, assets: map[string]bool{}}
			l[occ.Dependency.PURL] = lib
		}
		lib.assets[assetRef] = true
	}
}

func (l dependencyLibraries) purls() []string {
	purls := make([]string, 0, len(l))
	for purl := range l {
		purls = append(purls, purl)
	}
	sort.Strings(purls)
	return purls
}

func (l dependencyLibraries) components() []cdx.Component {
	components := make([]cdx.Component, 0, len(l))
	for _, purl := range l.purls() {
		lib := l[purl]
		name := lib.info.Module
		if name == "" {
			name = purl
		}
		components = append(components, cdx.Component{
			Type:       cdx.ComponentTypeLibrary,
			BOMRef:     purl,
			Name:       name,
			Version:    lib.info.Version,
			PackageURL: purl,
		})
	}
	return components
}

func (l dependencyLibraries) dependencies() []cdx.Dependency {
	dependencies := make([]cdx.Dependency, 0, len(l))
	for _, purl := range l.purls() {
		refs := make([]string, 0, len(l[purl].assets))
		for ref := range l[purl].assets {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		dependencies = append(dependencies, cdx.Dependency{Ref: purl, Dependencies: &refs})
	}
	return dependencies
}
