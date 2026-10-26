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

package prefilter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// Index is what a ruleset server publishes about a ruleset: the languages
// its rules name and, per family, every module its rules declare in
// metadata.imports.
type Index struct {
	Languages []string
	Modules   map[Family][]string
}

// Profile is what a unit asks a ruleset server for: the index languages it
// has files of and, per family with files, the index modules its evidence
// satisfies. A family with files and no satisfied module is listed with an
// empty slice, so the server keeps only that family's always-on rules.
type Profile struct {
	Languages []string            `json:"languages"`
	Modules   map[Family][]string `json:"modules"`
}

// BuildProfile matches the index against the unit's evidence. A module
// counts when a rule declaring it alone would be kept for the unit. When
// the index names no languages, the evidence's analyzer ids stand in.
func BuildProfile(ev *Evidence, index *Index) Profile {
	profile := Profile{Languages: []string{}, Modules: make(map[Family][]string)}
	if index == nil {
		return profile
	}
	for _, lang := range index.Languages {
		if ev.HasAnalyzer(analyzerOf(lang)) {
			profile.Languages = append(profile.Languages, lang)
		}
	}
	if len(index.Languages) == 0 {
		profile.Languages = ev.Analyzers()
	}
	for family, modules := range index.Modules {
		if !ev.hasFamily(family) {
			continue
		}
		kept := []string{}
		for _, module := range modules {
			atom := importAtom{family: family, literal: module, declared: true}
			if module != "" && atom.eval(ev) {
				kept = append(kept, module)
			}
		}
		profile.Modules[family] = kept
	}
	profile.sort()
	return profile
}

// IsEmpty reports whether the profile names no language, so no rule could
// be kept for it.
func (p Profile) IsEmpty() bool { return len(p.Languages) == 0 }

// Hash is the sha256 hex of the canonical profile JSON: sorted keys, sorted
// lists, no whitespace. It names the profile's cache entry and is what the
// server echoes back for a filtered ruleset.
func (p Profile) Hash() string {
	p.sort()
	if p.Languages == nil {
		p.Languages = []string{}
	}
	if p.Modules == nil {
		p.Modules = map[Family][]string{}
	}
	data, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ModuleCount is the number of modules over every family.
func (p Profile) ModuleCount() int {
	count := 0
	for _, modules := range p.Modules {
		count += len(modules)
	}
	return count
}

func (p Profile) sort() {
	sort.Strings(p.Languages)
	for _, modules := range p.Modules {
		sort.Strings(modules)
	}
}

// analyzerOf maps a language name as rules spell it to the OpenGrep analyzer
// id the evidence records files under.
func analyzerOf(language string) string {
	name := strings.ToLower(strings.TrimSpace(language))
	switch name {
	case "javascript":
		return analyzerJS
	case "typescript":
		return analyzerTS
	case "py":
		return analyzerPython
	case "golang":
		return analyzerGo
	case "c++":
		return analyzerCpp
	case "c#":
		return analyzerCSharp
	default:
		return name
	}
}
