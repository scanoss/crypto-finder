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

package leakguard

import (
	"strings"
	"testing"
)

// testGuard denies invented names only: a host, a two-token repository, a
// three-token service and an exact-spelling project.
func testGuard(t *testing.T) *Guard {
	t.Helper()
	var lines []string
	add := func(category string, exact bool, name string) {
		sum, err := Hash(name, exact)
		if err != nil {
			t.Fatalf("Hash(%q): %v", name, err)
		}
		kind := "loose"
		if exact {
			kind = "exact"
		}
		lines = append(lines, category+" "+kind+" "+sum)
	}
	add("host", false, "zq9host")
	add("repository", false, "plum_orchard")
	add("service", false, "teal-kite-relay")
	add("project", true, "violet-dune")
	d, err := ParseDenylist("# invented\n\n" + strings.Join(lines, "\n") + "\n")
	if err != nil {
		t.Fatal(err)
	}
	return New(d)
}

// realHome and realUsers start a person's home path; they are split so this
// file does not trip the guard it tests.
const (
	realHome  = "/home" + "/"
	realUsers = "/Users" + "/"
)

func diffOf(path string, added ...string) string {
	var b strings.Builder
	b.WriteString("diff --git a/" + path + " b/" + path + "\n--- a/" + path + "\n+++ b/" + path + "\n@@ -10,0 +11," + "3 @@\n")
	for _, l := range added {
		b.WriteString("+" + l + "\n")
	}
	return b.String()
}

func TestScanDiff(t *testing.T) {
	g := testGuard(t)
	cases := []struct {
		name  string
		diff  string
		wants []string // each finding's String(), in order
	}{
		{"single token on an added line", diffOf("a.go", "ok", "ssh ZQ9HOST now"), []string{"a.go:12: internal name (host)"}},
		{"separator variant", diffOf("a.md", "see plum.orchard/x", "plum orchard", "PlumOrchard"), []string{
			"a.md:11: internal name (repository)", "a.md:12: internal name (repository)", "a.md:13: internal name (repository)",
		}},
		{"three-token name", diffOf("b.yml", "url: teal_kite-relay.internal"), []string{"b.yml:11: internal name (service)"}},
		{"exact entry matches its spelling", diffOf("c.md", "the violet-dune port"), []string{"c.md:11: internal name (project)"}},
		{"exact entry ignores other spellings", diffOf("c.md", "violet dune", "VioletDune", "violet_dune"), nil},
		{"no partial token", diffOf("d.go", "zq9hosted plum orchards"), nil},
		{"home path", diffOf("e.sh", "cd "+realHome+"alice/src", "open "+realUsers+"bob/x"), []string{
			"e.sh:11: absolute home path", "e.sh:12: absolute home path",
		}},
		{"synthetic home path", diffOf("internal/x/testdata/f.json", `"/home/u/app"`, "/home/crypto/.cache", "/Users/tester/y", "/home/.local/z"), nil},
		{"removed lines are ignored", "diff --git a/g b/g\n--- a/g\n+++ b/g\n@@ -1 +0,0 @@\n-zq9host\n", nil},
		{"go.sum is skipped", diffOf("go.sum", "h1:zq9host/x="), nil},
		{"deleted file", "diff --git a/h b/h\n--- a/h\n+++ /dev/null\n@@ -1 +0,0 @@\n-zq9host\n", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strs(g.ScanDiff(c.diff))
			if strings.Join(got, "|") != strings.Join(c.wants, "|") {
				t.Errorf("got %q, want %q", got, c.wants)
			}
		})
	}
}

func TestScanText(t *testing.T) {
	g := testGuard(t)
	got := strs(g.ScanText("PR body", "## Summary\nDeployed to zq9host via "+realHome+"carol/bin.\n"))
	want := []string{"PR body:2: internal name (host)", "PR body:2: absolute home path"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
	if f := g.ScanText("PR title", "fix(scan): handle teal kite relay"); len(f) != 1 || f[0].String() != "PR title:1: internal name (service)" {
		t.Errorf("title: got %q", strs(f))
	}
}

func TestFindingNeverEchoesTheName(t *testing.T) {
	g := testGuard(t)
	for _, f := range g.ScanText("PR body", "zq9host plum_orchard "+realHome+"alice/") {
		if s := f.String(); strings.Contains(s, "zq9") || strings.Contains(s, "plum") || strings.Contains(s, "alice") {
			t.Errorf("finding echoes the match: %s", s)
		}
	}
}

const rulesetYAML = `rules:
  - id: invented-thing
    languages: [go]
    pattern: foo.Bar(...)
    metadata:
      crypto:
        assetType: algorithm
        algorithmFamily: INVENTED
`

func TestCheckRuleset(t *testing.T) {
	cases := []struct {
		name, path, content string
		flagged             bool
	}{
		{"ruleset outside testdata", "rules/go/x.yaml", rulesetYAML, true},
		{"ruleset inside testdata", "internal/rules/testdata/x.yaml", rulesetYAML, false},
		{"reviewed override", "examples/x.yml", "# leakguard: invented-rules\n" + rulesetYAML, false},
		{"rules without crypto metadata", "x.yaml", "rules:\n  - id: a\n    metadata:\n      category: style\n", false},
		{"knowledge base yaml", "internal/cryptokb/go/x.yaml", "schema_version: \"2\"\ncontracts:\n  - method: a\n", false},
		{"not yaml", "x.go", rulesetYAML, false},
		{"broken yaml", "x.yaml", "rules: [", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := CheckRuleset(c.path, []byte(c.content))
			if (f != nil) != c.flagged {
				t.Fatalf("flagged=%v, want %v", f != nil, c.flagged)
			}
			if f != nil && f.String() != c.path+": looks like private ruleset content (rules with crypto metadata)" {
				t.Errorf("finding: %s", f)
			}
		})
	}
}

func TestHash(t *testing.T) {
	a, _ := Hash("Plum-Orchard", false)
	b, _ := Hash("plum orchard", false)
	if a != b || len(a) != 64 {
		t.Errorf("loose hashes differ or malformed: %s %s", a, b)
	}
	e1, _ := Hash("violet-dune", true)
	e2, _ := Hash("violet_dune", true)
	if e1 == e2 {
		t.Error("exact hashes must keep the separator")
	}
	if _, err := Hash("a b c d e", false); err == nil {
		t.Error("a name of more than MaxTokens tokens must be refused")
	}
	if _, err := Hash(" -- ", false); err == nil {
		t.Error("an empty name must be refused")
	}
}

func TestParseDenylistRejectsMalformed(t *testing.T) {
	for _, in := range []string{"host loose nothex", "host fuzzy " + strings.Repeat("a", 64), "host loose"} {
		if _, err := ParseDenylist(in); err == nil {
			t.Errorf("ParseDenylist(%q): want an error", in)
		}
	}
}

func TestDefaultDenylistLoads(t *testing.T) {
	if _, err := Default(); err != nil {
		t.Fatal(err)
	}
}

func strs(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.String())
	}
	return out
}
