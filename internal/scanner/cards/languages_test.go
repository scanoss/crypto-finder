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
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestLanguageTableIsConsistent(t *testing.T) {
	seen := map[string]string{}
	ecosystems := map[string]bool{}
	for _, l := range Languages() {
		if l.Name == "" || l.Ecosystem == "" {
			t.Fatalf("language %+v has no name or ecosystem", l)
		}
		if ecosystems[l.Ecosystem] {
			t.Errorf("ecosystem %q listed twice", l.Ecosystem)
		}
		ecosystems[l.Ecosystem] = true
		for _, n := range append([]string{l.Name}, l.Aliases...) {
			if other, dup := seen[n]; dup {
				t.Errorf("%q names both %s and %s", n, other, l.Name)
			}
			seen[n] = l.Name
			if got, ok := ForName(n); !ok || got.Name != l.Name {
				t.Errorf("ForName(%q) = %v, %v", n, got.Name, ok)
			}
		}
		if got, ok := ForEcosystem(l.Ecosystem); !ok || got.Name != l.Name {
			t.Errorf("ForEcosystem(%q) = %v, %v", l.Ecosystem, got.Name, ok)
		}
		if err := checkLanguage(l.Name); err != nil {
			t.Error(err)
		}
	}
	if _, ok := ForEcosystem(""); ok {
		t.Error("the empty ecosystem must not resolve (it used to mean Java)")
	}
	if err := checkLanguage(""); err == nil {
		t.Error("an unset language must be rejected, not read as Java")
	}
}

// A scanned language has a ruleset layout: its directory is found under
// semgrep-rules/ and cards/ of a release-shaped ruleset.
func TestScannedLanguagesHaveACardsLayout(t *testing.T) {
	root := t.TempDir()
	for _, l := range Languages() {
		for _, dir := range []string{"semgrep-rules", "cards"} {
			if err := os.MkdirAll(filepath.Join(root, dir, l.Name), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, l := range Languages() {
		if !l.Scanned {
			continue
		}
		rules, cardsDir := rulesetLayout(root, l.Name)
		if rules != filepath.Join(root, "semgrep-rules", l.Name) || cardsDir != filepath.Join(root, "cards", l.Name) {
			t.Errorf("layout of %s = %s, %s", l.Name, rules, cardsDir)
		}
		if !slices.Contains(directoryNames(), l.Name) {
			t.Errorf("%s is not a ruleset language directory", l.Name)
		}
	}
}

// Rust is scanned by default.
func TestScannedRust(t *testing.T) {
	if l, ok := ForEcosystem("rust"); !ok || !l.IsScanned() || l.Name != "rust" {
		t.Errorf("rust = %+v, %v, want rust, scanned", l, ok)
	}
}

// C# is out of a production scan and admitted by CSharpEnv=1 for the
// ruleset's port tooling, as Ruby and C are.
func TestScannedGatesCSharp(t *testing.T) {
	l, ok := ForEcosystem("csharp")
	if !ok || l.Name != "csharp" {
		t.Fatalf("csharp = %+v, %v, want the csharp language", l, ok)
	}
	for _, env := range []string{"", "0", "1"} {
		t.Setenv(CSharpEnv, env)
		if got := l.IsScanned(); got != (env == "1") {
			t.Errorf("%s=%q: scanned = %v", CSharpEnv, env, got)
		}
	}
}

// Ruby is scanned by default.
func TestScannedRuby(t *testing.T) {
	l, ok := ForEcosystem("ruby")
	if !ok || !l.IsScanned() || l.Name != "ruby" || !l.Compiled {
		t.Errorf("ruby = %+v, %v; want name ruby, scanned, compiled", l, ok)
	}
}

// JavaScript/TypeScript (the node ecosystem) is scanned by default.
func TestScannedNode(t *testing.T) {
	if l, ok := ForEcosystem("node"); !ok || !l.IsScanned() || l.Name != "javascript" {
		t.Errorf("node = %+v, %v, want javascript, scanned", l, ok)
	}
}

// C and C++ are out of a production scan and admitted by CEnv=1 (fidelity
// runs).
func TestScannedGatesC(t *testing.T) {
	for _, tc := range []struct {
		env       string
		ecosystem string
		want      bool
	}{
		{"", "c", false},
		{"", "cpp", false},
		{"0", "c", false},
		{"1", "c", true},
		{"1", "cpp", true},
		{"1", "rust", true},
		{"1", "java", true},
	} {
		t.Setenv(CEnv, tc.env)
		l, ok := ForEcosystem(tc.ecosystem)
		if got := ok && l.IsScanned(); got != tc.want {
			t.Errorf("%s scanned with %s=%q = %v, want %v", tc.ecosystem, CEnv, tc.env, got, tc.want)
		}
	}
}

// Canonical names every spelling of a language the detector, --languages, a
// rule's languages or a ruleset directory may use by the table's name.
func TestCanonical(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"javascript", "javascript"},
		{"JavaScript", "javascript"},
		{"js", "javascript"},
		{"jsx", "javascript"},
		{"mjs", "javascript"},
		{"cjs", "javascript"},
		{"typescript", "javascript"},
		{"TypeScript", "javascript"},
		{"ts", "javascript"},
		{"tsx", "javascript"},
		{"c", "c"},
		{"h", "c"},
		{"cpp", "cpp"},
		{"c++", "cpp"},
		{"C++", "cpp"},
		{"cxx", "cpp"},
		{"cc", "cpp"},
		{"hpp", "cpp"},
		{"csharp", "csharp"},
		{"c#", "csharp"},
		{"cs", "csharp"},
		{"go", "go"},
		{"golang", "go"},
		{"python", "python"},
		{"py", "python"},
		{"rust", "rust"},
		{"rs", "rust"},
		{"ruby", "ruby"},
		{"rb", "ruby"},
		{"java", "java"},
		{"Java", "java"},
		{"kotlin", "kotlin"},
		{" XML ", "xml"},
		{"", ""},
	} {
		if got := Canonical(tc.in); got != tc.want {
			t.Errorf("Canonical(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
