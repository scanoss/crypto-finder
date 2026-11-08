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

package callgraph

import "strings"

// entry_markers.go tells a decorator, attribute or annotation that may
// register its function with something that calls it from one that cannot.
//
// A marker keeps an uncalled function a root (entry_scope.go) unless it is
// a test marker or a built-in the language defines that only instructs the
// compiler, a linter or a reader: Rust lint, codegen and conditional
// compilation attributes, Python decorators of the standard library that
// wrap or annotate a function in place, and the Java annotations of
// java.lang. A marker this file does not name, a framework's or a procedural
// macro's, still counts: it may register the function.

// inertRustAttributes are the built-in Rust attributes that register
// nothing. #[allow(dead_code)] in particular says nothing calls the
// function. #[no_mangle], #[export_name] and #[used] are not here: they
// export a symbol foreign code can call.
var inertRustAttributes = map[string]bool{
	"allow": true, "warn": true, "deny": true, "forbid": true, "expect": true,
	"inline": true, "cold": true, "track_caller": true, "must_use": true,
	"deprecated": true, "doc": true, "cfg": true, "target_feature": true,
	"rustfmt::skip": true,
}

// inertRustToolPrefixes are tool attribute namespaces that only configure a
// linter or a formatter.
var inertRustToolPrefixes = []string{"clippy::", "rustfmt::"}

// inertAnnotations are the Python standard-library decorators and the
// java.lang annotations that register nothing, by the name the source
// writes.
var inertAnnotations = map[string]bool{
	// Python
	"staticmethod": true, "classmethod": true,
	"functools.wraps": true, "wraps": true,
	"functools.cache": true, "cache": true,
	"functools.lru_cache": true, "lru_cache": true,
	"contextlib.contextmanager": true, "contextmanager": true,
	"contextlib.asynccontextmanager": true, "asynccontextmanager": true,
	"typing.overload": true, "overload": true,
	"typing.override": true, "typing_extensions.override": true, "override": true,
	"typing.final": true, "typing_extensions.final": true, "final": true,
	"typing.no_type_check": true, "no_type_check": true,
	"abc.abstractmethod": true, "abstractmethod": true,
	"warnings.deprecated": true, "typing_extensions.deprecated": true, "deprecated": true,
	// Java
	"Deprecated": true, "java.lang.Deprecated": true,
	"SuppressWarnings": true, "java.lang.SuppressWarnings": true,
	"SafeVarargs": true, "java.lang.SafeVarargs": true,
	"Override": true, "java.lang.Override": true,
}

// registeringLine reports whether a line of markers holds one that may
// register its function: neither a test marker nor an inert built-in.
func registeringLine(text string) bool {
	for _, marker := range lineMarkers(text) {
		if !testMarker(marker) && !inertMarker(marker) {
			return true
		}
	}
	return false
}

// lineMarkers splits the markers a line starts with: "@A @B(x) static void
// f()" holds @A and @B(x), "#[inline] #[get("/")] fn f()" holds #[inline]
// and #[get("/")]. A marker an earlier line opened and this one does not
// close runs to the end of the line.
func lineMarkers(text string) []string {
	var out []string
	for {
		text = strings.TrimSpace(text)
		var end int
		switch {
		case strings.HasPrefix(text, "#["):
			end = closingBracket(text, 1, '[', ']')
		case strings.HasPrefix(text, "@"):
			end = 1
			for end < len(text) && (isIdentByte(text[end]) || text[end] == '.') {
				end++
			}
			if rest := strings.TrimLeft(text[end:], " "); strings.HasPrefix(rest, "(") {
				open := len(text) - len(rest)
				end = closingBracket(text, open, '(', ')')
			}
		default:
			return out
		}
		out = append(out, text[:end])
		text = text[end:]
	}
}

// closingBracket returns the index just past the bracket closing the one at
// open, skipping quoted strings, or len(text) when the line does not close
// it.
func closingBracket(text string, open int, opening, closing byte) int {
	depth := 0
	var quote byte
	for i := open; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0 && c == '\\':
			i++
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == opening:
			depth++
		case c == closing:
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(text)
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// inertMarker reports a built-in marker that registers nothing.
func inertMarker(marker string) bool {
	if inner, ok := strings.CutPrefix(marker, "#["); ok {
		return inertRustAttribute(strings.TrimSuffix(strings.TrimSpace(inner), "]"))
	}
	name := strings.TrimPrefix(marker, "@")
	if cut := strings.IndexAny(name, "( "); cut >= 0 {
		name = name[:cut]
	}
	return inertAnnotations[name]
}

// inertRustAttribute reports a Rust attribute, without its #[ ], that
// registers nothing. #[cfg_attr(pred, a, b)] is inert when every attribute
// it applies is.
func inertRustAttribute(attr string) bool {
	name, args := attr, ""
	if cut := strings.IndexAny(attr, "( ="); cut >= 0 {
		name, args = attr[:cut], strings.TrimSpace(attr[cut:])
	}
	switch {
	case name == "cfg_attr":
		applied := splitTopLevelCommaList(trimOuterParens(args))
		if len(applied) < 2 {
			return false
		}
		for _, inner := range applied[1:] {
			inner = strings.TrimSpace(inner)
			if !testMarker("#["+inner+"]") && !inertRustAttribute(inner) {
				return false
			}
		}
		return true
	case inertRustAttributes[name]:
		return true
	}
	for _, prefix := range inertRustToolPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
