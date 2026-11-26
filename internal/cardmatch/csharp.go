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

import (
	"strings"

	"github.com/scanoss/reach/graphfrag"
)

// The C# ecosystem, as the call graph and the ruleset directories name it.
const ecosystemCSharp = "csharp"

// csharpUsingsByFile is the namespaces each file brings into scope, the
// `using N;` directives of the file plus every `global using` of the
// component, which C# applies to all of its files.
func csharpUsingsByFile(imports map[string][]graphfrag.GraphFragmentImport) map[string][]string {
	var global []string
	for _, directives := range imports {
		for _, d := range directives {
			if csharpUsingIsGlobal(d) && !csharpUsingIsAlias(d) {
				global = append(global, d.Module)
			}
		}
	}
	out := make(map[string][]string, len(imports))
	for file, directives := range imports {
		scope := append([]string(nil), global...)
		for _, d := range directives {
			if csharpUsingIsAlias(d) || csharpUsingIsGlobal(d) {
				continue
			}
			scope = append(scope, d.Module)
		}
		out[file] = scope
	}
	return out
}

// The kinds a C# using directive is written as, as the fragment records them:
// a `global using` carries the prefix, so its namespace is in scope in every
// file of the component.
const (
	csharpUsingAlias        = "alias"
	csharpUsingGlobalPrefix = "global-"
)

func csharpUsingIsAlias(d graphfrag.GraphFragmentImport) bool {
	return strings.TrimPrefix(d.Kind, csharpUsingGlobalPrefix) == csharpUsingAlias
}

func csharpUsingIsGlobal(d graphfrag.GraphFragmentImport) bool {
	return strings.HasPrefix(d.Kind, csharpUsingGlobalPrefix)
}

// csharpClassMatch: the entry's type names the site's class. C# has no
// single-type import, so a qualified pattern matches a type written short
// wherever a `using` brings its namespace in -- which is how the reference
// matcher resolves a using. An exact class, and a pattern written short
// against a qualified class, match as they do in Java.
func csharpClassMatch(entryType, cls string, s *Site) bool {
	if cls == "" {
		return false
	}
	if cls == entryType || strings.HasSuffix(cls, "."+entryType) {
		return true
	}
	namespace, name, qualified := csharpCutLast(entryType)
	if !qualified {
		return false
	}
	if _, written, _ := csharpCutLast(cls); written != name {
		return false
	}
	return inList(namespace, s.CSharpUsings)
}

// csharpUsingBrings: a C# argument the rule writes qualified
// (`Org.BouncyCastle.Asn1.GM.GMObjectIdentifiers.sm3`) stands for the short
// name the source writes only where a using brings its namespace in. Any
// other site is left as it was.
func csharpUsingBrings(value, written string, s *Site) bool {
	if !s.CSharp {
		return true
	}
	namespace, ok := strings.CutSuffix(value, "."+written)
	return ok && inList(namespace, s.CSharpUsings)
}

// csharpNameMatch: the card's qualified name and the name the source wrote
// are the same thing. C# has no single-type import, so a key carries the
// namespace of the file that wrote the call wherever no using settles the
// type, and the card's name never ends it. They name the same thing when
// their last segments are the ones the source writes and a using of the file
// brings in the namespace the card writes before them -- which is how the
// reference matcher resolves a using. Without such a using, a lookalike type
// of another namespace is not the card's type, however it is written.
func csharpNameMatch(want, have string, fr *Frag, caller string) bool {
	if fr == nil || !fr.CSharp || want == "" || have == "" {
		return false
	}
	usings := fr.CSharpUsings[fr.CallerFile[caller]]
	if len(usings) == 0 {
		return false
	}
	wantParts, haveParts := strings.Split(want, "."), strings.Split(have, ".")
	shared := 0
	for shared < len(wantParts) && shared < len(haveParts) &&
		wantParts[len(wantParts)-1-shared] == haveParts[len(haveParts)-1-shared] {
		shared++
	}
	if shared == 0 || shared >= len(wantParts) {
		return false
	}
	return inList(strings.Join(wantParts[:len(wantParts)-shared], "."), usings)
}

// csharpCutLast splits a dotted name into everything before its last segment
// and the segment itself.
func csharpCutLast(name string) (prefix, last string, cut bool) {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[:i], name[i+1:], true
	}
	return "", name, false
}
