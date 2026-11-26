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

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/crypto-finder/internal/entities"
)

func TestIsCPPHeader(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"namespace", "namespace Botan { class HashFunction {}; }\n", true},
		{"class", "class Hash;\n", true},
		{"template", "template <typename T> T f(T);\n", true},
		{"qualified name", "inline int g() { return std::max(1, 2); }\n", true},
		{"comment words", "/* the global namespace; this class of errors; a::b */\nint f(void);\n", false},
		{"line comment", "// std::string in C++\nint f(void);\n", false},
		{"string literal", "#define SEP \"::\"\nconst char *k = \"class A {\";\n", false},
		{"char literal", "int c = ':';\nint d = ':';\n", false},
		{"inline asm clobbers", "static void y(void) { __asm__ volatile(\"yield\" ::: \"memory\"); }\n", false},
		{"escaped quote", "const char *s = \"a\\\" class B {\";\nint f(void);\n", false},
		{"plain C", "struct ctx { int n; };\nint f(struct ctx *c);\n", false},
		{"C++ branch of a C header", "#if defined(__cplusplus)\n#ifndef X\ntemplate <class T> struct id { using type = T; };\n#else\nusing std::id;\n#endif\n#endif\nint f(void);\n", false},
		{"extern C guard", "#ifdef __cplusplus\nextern \"C\" {\n#endif\nint f(void);\n#ifdef __cplusplus\n}\n#endif\n", false},
		{"C++ in the else of a negated test", "#if !defined(__cplusplus)\nint f(void);\n#else\nnamespace n { int f(); }\n#endif\n", false},
		{"C++ in the else of ifndef", "#ifndef __cplusplus\nint f(void);\n#else\ntemplate <class T> T g(T);\n#endif\n", false},
		{"C++ outside the guard", "#ifdef __cplusplus\nextern \"C\" {\n#endif\nclass Hash { };\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "x.h")
			if err := os.WriteFile(path, []byte(tc.src), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := isCPPHeader(path); got != tc.want {
				t.Fatalf("isCPPHeader(%q) = %v, want %v", tc.src, got, tc.want)
			}
		})
	}
}

// A C repository whose headers say "namespace" in a comment and hold an
// inline asm clobber list keeps the c ecosystem under a c hint.
func TestEcosystemFromHints_CHeaderWithCPPWordsInComments(t *testing.T) {
	dir := t.TempDir()
	src := "/* do not pollute the global namespace */\n" +
		"static inline void pause(void) { __asm__ volatile(\"yield\" ::: \"memory\"); }\n"
	if err := os.WriteFile(filepath.Join(dir, "setup.h"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ecosystemFromHints(dir, []string{"c"}); got != "c" {
		t.Fatalf("ecosystemFromHints(c hint) = %q, want c", got)
	}
}

// A C repository that also holds C++ headers (a C++ wrapper, a C++ test, a
// namespace a macro opts into) keeps the c ecosystem under a c hint: its .c
// units are what the C graph is built from. The same headers without a .c
// file read as C++.
func TestEcosystemFromHints_CSourcesKeepCWithCPPHeaders(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("include/lib.h", "#ifdef LIB_CPP_NAMESPACE\nnamespace LIB_CPP_NAMESPACE {\n#endif\nint lib_hash(void);\n")
	write("wrappers/libxx.h", "namespace lib { class Hash { public: int run(); }; }\n")
	if got := ecosystemFromHints(dir, []string{"c"}); got != ecosystemCPP {
		t.Fatalf("headers only: ecosystemFromHints(c hint) = %q, want cpp", got)
	}
	write("src/lib.c", "int lib_hash(void) { return 0; }\n")
	if got := ecosystemFromHints(dir, []string{"c"}); got != "c" {
		t.Fatalf("with a .c unit: ecosystemFromHints(c hint) = %q, want c", got)
	}
	if got := ecosystemFromHints(filepath.Join(dir, "wrappers", "libxx.h"), []string{"c"}); got != ecosystemCPP {
		t.Fatalf("the C++ header alone: ecosystemFromHints(c hint) = %q, want cpp", got)
	}
}

// A C target with a C++ header keys its findings on the C graph alone, the
// graph its fragment stores, so annotate gives a finding in the header the
// key the scan gave it.
func TestReportOccurrenceKeyEcosystems_CTargetKeysOnC(t *testing.T) {
	dir := t.TempDir()
	headerPath := filepath.Join(dir, "libxx.h")
	if err := os.WriteFile(headerPath, []byte("namespace lib { class Hash {}; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib.c"), []byte("int lib_hash(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: headerPath, Language: "c"}}}
	if got := reportOccurrenceKeyEcosystems(dir, report, []string{"c"}); len(got) != 1 || got[0] != "c" {
		t.Fatalf("reportOccurrenceKeyEcosystems = %v, want [c]", got)
	}
}

// A C++ scan keys a finding of a C rule on the C++ graph alone, the graph
// its fragment stores, also in a header of a target with C units: anchors of
// a C parse of the header would key it on a function annotate does not know.
func TestReportOccurrenceKeyEcosystems_CPPScanKeysOnCPP(t *testing.T) {
	dir := t.TempDir()
	headerPath := filepath.Join(dir, "tls.h")
	if err := os.WriteFile(headerPath, []byte("namespace acme {\n#include <openssl/evp.h>\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "util.c"), []byte("int util(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, language := range []string{"c", "c++"} {
		report := &entities.InterimReport{Findings: []entities.Finding{{FilePath: headerPath, Language: language}}}
		for _, hints := range [][]string{{"cpp"}, {"c++"}} {
			if got := reportOccurrenceKeyEcosystems(dir, report, hints); len(got) != 1 || got[0] != ecosystemCPP {
				t.Errorf("finding in %s, hints %v: reportOccurrenceKeyEcosystems = %v, want [cpp]", language, hints, got)
			}
		}
	}
}
