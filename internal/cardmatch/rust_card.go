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

package cardmatch

// Rust hand cards. A card whose kind is `rust:` holds a rule formula the
// Rust compiler reads (pattern, patterns or pattern-either, with the clauses
// compile_rust.go accepts), for a rule the compiler skips or reads wrongly:
// a pattern-regex OpenGrep needs because it cannot parse a metavariable in a
// generic position, say. The rule YAML stays as OpenGrep runs it; the card is
// how the cards engine reads the rule instead.
//
//	cards:
//	- rule: <rule id>
//	  rust:
//	    patterns:
//	    - pattern: acme_mode::Encryptor::<$C>::new(...)
//	    - metavariable-regex: {metavariable: $C, regex: 'Blk(?P<bits>128|256)'}
//
// The card compiles into Rust index entries carrying the rule id and the
// rule's metadata (or the card's own), which replace every compiled entry of
// the rule in the Rust matcher. Only the Rust matcher runs them.
//
// A card's positive may also be a type alias, `type $A = acme_mode::$D<$C>;`,
// which matches the type alias items of a graph-fragment-1.27: $A binds the
// alias name, the aliased type unifies as written (every path segment and
// its generics; a metavariable binds the written type, `acme::Blk128`), and
// the finding spans the `type` keyword to the end of the item, as a
// pattern-regex over the alias reports it. A rule YAML's type item positive
// stays held: OpenGrep 1.33.1 reads it with other semantics
// (rustAliasServable).

import "fmt"

// keyRustCard is the card kind of a Rust hand card.
const keyRustCard = "rust"

// rustCardKeys are the keys a Rust hand card takes: the Java and Python
// card refinements (with, not_in, lossy, ...) do not apply to it.
var rustCardKeys = setOf("rule", keyRustCard, "metadata", "note")

// addRust loads the Rust hand card c for rule, whose formula is f. A card
// the compiler would skip is an error naming the card and the reason: a hand
// card never silently matches nothing.
func (set *CardSet) addRust(c *OMap, f any, path, rule string, info ruleInfo) error {
	if unk := unknownKeys(c, rustCardKeys); len(unk) > 0 {
		return fmt.Errorf("%s: bad rust card %s %v", path, rule, unk)
	}
	if !info.Rust {
		// The card would drop the rule's Java or Python entries and run
		// only in the Rust matcher.
		return fmt.Errorf("%s: rust card %s: %s is not a rust rule", path, rule, rule)
	}
	if info.Taint {
		return fmt.Errorf("%s: rust card %s: a rust card replaces a search rule; %s is a taint rule", path, rule, rule)
	}
	formula, ok := f.(*OMap)
	if !ok || formula.Len() != 1 || !setOf(keyPattern, keyPatterns, keyPatternEither)[asOr[string](formula.Keys[0])] {
		return fmt.Errorf("%s: rust card %s: want one of pattern, patterns, pattern-either", path, rule)
	}
	sinks, err := compileRustRule(formula)
	if err != nil {
		if s, isSkip := asSkip(err); isSkip {
			return fmt.Errorf("%s: rust card %s does not compile: %s", path, rule, s.reason)
		}
		return fmt.Errorf("%s: rust card %s: %w", path, rule, err)
	}
	var meta any = info.Meta
	if md := c.GetOr("metadata"); pyTruthy(md) {
		meta = mustMap(md, path)
	}
	for _, s := range sinks {
		s.Set("rule_id", rule)
		s.Set(strTaint, false)
		s.Set("metadata", meta)
	}
	ix, err := (&compiledRules{Entries: sinks}).index()
	if err != nil {
		return fmt.Errorf("%s: rust card %s: %w", path, rule, err)
	}
	set.Rust = append(set.Rust, ix.Entries...)
	set.RuleIDs[rule] = true
	return nil
}
