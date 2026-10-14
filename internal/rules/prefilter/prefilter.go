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

// Rule is one rule as the prefilter sees it.
type Rule struct {
	// Analyzers are the OpenGrep analyzer ids of the rule's languages. A rule
	// with a language the caller could not map lists none and is kept.
	Analyzers []string
	// Requirement is the rule's derived requirement.
	Requirement Expr
}

// Stats counts one decision.
type Stats struct {
	Total int
	Kept  int
	// DroppedLanguage counts rules none of whose languages has a file in the
	// unit; DroppedImports the rest of the dropped rules.
	DroppedLanguage int
	DroppedImports  int
	// Unknown counts kept rules whose requirement the prefilter could not
	// derive, so they are kept whatever the unit imports.
	Unknown int
}

// Decide reports, per rule, whether the unit's evidence may let it match.
func Decide(rules []Rule, ev *Evidence) ([]bool, Stats) {
	keep := make([]bool, len(rules))
	stats := Stats{Total: len(rules)}
	for i := range rules {
		rule := &rules[i]
		if len(rule.Analyzers) > 0 && !anyAnalyzer(rule.Analyzers, ev) {
			stats.DroppedLanguage++
			continue
		}
		if rule.Requirement == nil || !rule.Requirement.known() {
			keep[i] = true
			stats.Kept++
			stats.Unknown++
			continue
		}
		if rule.Requirement.eval(ev) {
			keep[i] = true
			stats.Kept++
			continue
		}
		stats.DroppedImports++
	}
	return keep, stats
}

func anyAnalyzer(analyzers []string, ev *Evidence) bool {
	for _, analyzer := range analyzers {
		if ev.HasAnalyzer(analyzer) {
			return true
		}
	}
	return false
}
