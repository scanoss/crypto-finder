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

package cards

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

// ecosystemCPP is the C++ language and reach ecosystem.
const ecosystemCPP = "cpp"

// CEnv names the variable that, set to 1, lets a C or C++ target through the
// scan's language gate for fidelity runs: neither is scanned in production.
const CEnv = "CRYPTO_FINDER_CARDS_C"

// CSharpEnv names the variable that, set to 1, lets a C# target through the
// scan's language gate for fidelity runs: C# is not scanned in production.
const CSharpEnv = "CRYPTO_FINDER_CARDS_CSHARP"

// Language is one language the cards engine knows.
type Language struct {
	// Name is the directory of its rules and cards (semgrep-rules/<Name>,
	// cards/<Name>) and the value of --lang.
	Name string
	// Ecosystem is the reach ecosystem whose fragments its rules match.
	Ecosystem string
	// Aliases are other --lang values that mean this language.
	Aliases []string
	// Spellings are the other names the language goes by outside --lang: the
	// detector's linguist names, file extensions and the short ids rule
	// files write. Canonical reads them; ForName and the ruleset layout do
	// not.
	Spellings []string
	// Scanned is whether the scan gate admits the language: its matcher exists.
	Scanned bool
	// ScannedEnv, when set, names a variable that, set to 1, admits a language
	// that is not Scanned (a fidelity run).
	ScannedEnv string
	// Compiled is whether the rule compiler reads its rules: the cards dev
	// commands (cards-export, cards verify) accept it.
	Compiled bool
	// Shares names the languages whose rules also apply to this one's
	// targets, as OpenGrep runs a rule on every file of a language it
	// names: a C rule (languages [c, cpp]) also matches C++ sources. Their
	// rules keep their own compilation; only the rules that name this
	// language apply.
	Shares []string
}

// IsScanned is whether the scan gate admits the language now: Scanned, or
// its ScannedEnv set to 1.
func (l Language) IsScanned() bool {
	return l.Scanned || l.ScannedEnv != "" && os.Getenv(l.ScannedEnv) == "1"
}

// languages is the only list of the cards engine's languages. The scan gate,
// the --lang validation of the dev commands, the scanner's ruleset layout and
// the annotate path all derive from it.
var languages = []Language{
	{Name: "java", Ecosystem: "java", Scanned: true, Compiled: true},
	{Name: "python", Ecosystem: "python", Spellings: []string{"py"}, Scanned: true, Compiled: true},
	{Name: "go", Ecosystem: "go", Spellings: []string{"golang"}, Scanned: true, Compiled: true},
	{Name: "rust", Ecosystem: "rust", Spellings: []string{"rs"}, Scanned: true, Compiled: true},
	{Name: "javascript", Ecosystem: "node", Aliases: []string{"typescript"}, Spellings: []string{"js", "jsx", "mjs", "cjs", "ts", "tsx"}, Scanned: true, Compiled: true},
	{Name: "c", Ecosystem: "c", Spellings: []string{"h"}, ScannedEnv: CEnv, Compiled: true},
	{Name: ecosystemCPP, Ecosystem: ecosystemCPP, Spellings: []string{"c++", "cxx", "cc", "hpp"}, ScannedEnv: CEnv, Compiled: true, Shares: []string{"c"}},
	{Name: "ruby", Ecosystem: "ruby", Spellings: []string{"rb"}, Scanned: true, Compiled: true},
	{Name: "csharp", Ecosystem: "csharp", Aliases: []string{"c#"}, Spellings: []string{"cs"}, ScannedEnv: CSharpEnv, Compiled: true},
}

// Canonical is the one name of a language every comparison of languages
// uses: the table's name for any of its names, aliases or spellings
// (typescript, tsx and js are javascript), ignoring case and surrounding
// space; any other language lower-cased. The scan's language hints, the rule
// filter (a rule's languages, a card file's directory) and the scanner's rule
// selection compare canonical names, so no spelling drops a language's rules.
func Canonical(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if l, ok := ForName(name); ok {
		return l.Name
	}
	for _, l := range languages {
		if slices.Contains(l.Spellings, name) {
			return l.Name
		}
	}
	return name
}

// ForEcosystem is the cards language of a reach ecosystem. ok is false for an
// ecosystem the cards engine has no language for: callers fail or skip, they
// never fall back to Java.
func ForEcosystem(ecosystem string) (Language, bool) {
	for _, l := range languages {
		if l.Ecosystem == ecosystem {
			return l, true
		}
	}
	return Language{}, false
}

// ForName resolves a --lang value, a name or an alias, ignoring case.
func ForName(name string) (Language, bool) {
	name = strings.ToLower(name)
	for _, l := range languages {
		if l.Name == name {
			return l, true
		}
		for _, alias := range l.Aliases {
			if alias == name {
				return l, true
			}
		}
	}
	return Language{}, false
}

// Languages lists them in declaration order.
func Languages() []Language {
	out := make([]Language, len(languages))
	copy(out, languages)
	return out
}

// directoryNames lists every name a language directory of a ruleset may have:
// each language's name and aliases, and the ruleset languages the engine does
// not know yet.
func directoryNames() []string {
	names := make([]string, 0, 3*len(languages))
	for _, l := range languages {
		names = append(names, l.Name)
		names = append(names, l.Aliases...)
	}
	return names
}

// checkLanguage fails for a language option that is not the name of a language
// of the table: an unset one is not Java.
func checkLanguage(name string) error {
	if l, ok := ForName(name); !ok || l.Name != name {
		return fmt.Errorf("cards: %q is not a cards language", name)
	}
	return nil
}
