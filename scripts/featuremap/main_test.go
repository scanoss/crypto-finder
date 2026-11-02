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

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		glob, name string
		want       bool
	}{
		{"internal/cli/scan.go", "internal/cli/scan.go", true},
		{"internal/cli/scan.go", "internal/cli/scan_profile.go", false},
		{"internal/callgraph/*.go", "internal/callgraph/builder.go", true},
		{"internal/callgraph/*.go", "internal/callgraph/contracts/contracts.go", false},
		{"internal/dependency/**", "internal/dependency/maven/resolve.go", true},
		{"internal/dependency/**", "internal/dependencyx/a.go", false},
		{"pkg/graphfrag/stitch*.go", "pkg/graphfrag/stitch_merge.go", true},
		{"**/*_test.go", "a_test.go", true},
		{"**/*_test.go", "internal/scan/x_test.go", true},
		{"**/testdata/**", "internal/scan/testdata/a/b.json", true},
		{"**/testdata/**", "testdata/rules/x.yaml", true},
		{"cmd/*/main.go", "cmd/crypto-finder/main.go", true},
		{"internal/[", "internal/[", false},
	}
	for _, tt := range tests {
		if got := matchGlob(tt.glob, tt.name); got != tt.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.glob, tt.name, got, tt.want)
		}
	}
}

// prFeatures has a short id that is a prefix of a longer one, so whole-token
// matching is exercised.
var prFeatures = []feature{
	{id: "reachability", globs: []string{"internal/callgraph/*.go"}},
	{id: "reachability-dependencies", globs: []string{"internal/dependency/**"}},
	{id: "scan", globs: []string{"internal/scanner/**", "internal/cli/scan.go"}},
}

func TestCheckPR(t *testing.T) {
	tests := []struct {
		name     string
		changed  []string
		body     string
		problems []string // substrings, one per expected problem, in order
	}{
		{
			name:    "touched feature named with a link passes",
			changed: []string{"internal/scanner/run.go"},
			body:    "## Problem\nx\n\n## Evidence\n- scan: https://example.com/run/1\n",
		},
		{
			name:    "touched feature named with evidence text passes",
			changed: []string{"internal/cli/scan.go"},
			body:    "## Evidence\n\n`scan`: VERDICT: PASS (5 passed, 0 failed)\n",
		},
		{
			name:     "touched feature not named fails",
			changed:  []string{"internal/scanner/run.go"},
			body:     "## Evidence\n- nothing to see\n",
			problems: []string{"scan: not named (touched by internal/scanner/run.go)"},
		},
		{
			name:    "N/A with a reason passes",
			changed: []string{"internal/scanner/run.go"},
			body:    "## Evidence\n- scan: N/A: log wording only, no output change\n",
		},
		{
			name:     "N/A without a reason fails",
			changed:  []string{"internal/scanner/run.go"},
			body:     "## Evidence\n- scan: N/A\n",
			problems: []string{"scan: N/A needs a reason"},
		},
		{
			name:     "N/A with an empty reason fails",
			changed:  []string{"internal/scanner/run.go"},
			body:     "## Evidence\n- scan: N/A:   \n",
			problems: []string{"scan: N/A needs a reason"},
		},
		{
			name:     "bare id without evidence fails",
			changed:  []string{"internal/scanner/run.go"},
			body:     "## Evidence\n- `scan`\n",
			problems: []string{"scan: named without evidence"},
		},
		{
			name:     "a longer id does not name the shorter one",
			changed:  []string{"internal/callgraph/builder.go", "internal/dependency/go.go"},
			body:     "## Evidence\n- reachability-dependencies: https://example.com/run/2\n",
			problems: []string{"reachability: not named (touched by internal/callgraph/builder.go)"},
		},
		{
			name:    "tests and testdata only ask for nothing",
			changed: []string{"internal/scanner/run_test.go", "internal/scanner/testdata/a.json"},
			body:    "",
		},
		{
			name:    "files outside every glob ask for nothing",
			changed: []string{"README.md", ".github/workflows/lint.yml"},
			body:    "",
		},
		{
			name:     "named outside the Evidence section does not count",
			changed:  []string{"internal/scanner/run.go"},
			body:     "## Fix\nscan: changed the runner\n\n## Evidence\nnone\n\n## Not verified before merge\nscan: N/A: later\n",
			problems: []string{"scan: not named"},
		},
		{
			name:     "a name inside an HTML comment does not count",
			changed:  []string{"internal/scanner/run.go"},
			body:     "## Evidence\n<!-- scan: N/A: template example -->\n",
			problems: []string{"scan: not named"},
		},
		{
			name:    "CRLF bodies from GitHub parse",
			changed: []string{"internal/scanner/run.go"},
			body:    "## Evidence\r\n- scan: N/A: refactor\r\n",
		},
		{
			name:     "no Evidence heading is reported",
			changed:  []string{"internal/scanner/run.go"},
			body:     "## Fix\nx\n",
			problems: []string{"no ## Evidence heading", "scan: not named"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems, _ := checkPR(prFeatures, tt.changed, tt.body)
			if len(problems) != len(tt.problems) {
				t.Fatalf("problems = %q, want %d matching %q", problems, len(tt.problems), tt.problems)
			}
			for i, want := range tt.problems {
				if !strings.Contains(problems[i], want) {
					t.Errorf("problem %d = %q, want it to contain %q", i, problems[i], want)
				}
			}
		})
	}
}

func TestParseNameStatus(t *testing.T) {
	raw := "M\x00internal/a.go\x00R087\x00internal/scanner/old.go\x00internal/moved/new.go\x00D\x00gone.go\x00"
	got, err := parseNameStatus(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := "gone.go internal/a.go internal/moved/new.go internal/scanner/old.go"
	if strings.Join(got, " ") != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if _, err := parseNameStatus("R100\x00only-one\x00"); err == nil {
		t.Error("a truncated rename parsed without error")
	}
}

// TestRenamedFileOldPathCounts moves a file out of a feature's globs in a real
// repository and checks that check-pr still asks for that feature.
func TestRenamedFileOldPathCounts(t *testing.T) {
	root := t.TempDir()
	gitT(t, root, "init", "-q", "-b", "main")
	content := strings.Repeat("package scanner\n// line\n", 20)
	writeFile(t, root, "internal/scanner/run.go", content)
	gitT(t, root, "add", ".")
	gitT(t, root, "commit", "-q", "-m", "base")
	base := strings.TrimSpace(gitT(t, root, "rev-parse", "HEAD"))
	if err := os.MkdirAll(filepath.Join(root, "internal", "other"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitT(t, root, "mv", "internal/scanner/run.go", "internal/other/run.go")
	gitT(t, root, "commit", "-q", "-m", "move")

	changed, err := changedFiles(root, base+"...HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(changed, " ") != "internal/other/run.go internal/scanner/run.go" {
		t.Fatalf("changed = %q, want both sides of the rename", changed)
	}
	problems, _ := checkPR(prFeatures, changed, "## Evidence\n")
	if len(problems) != 1 || !strings.Contains(problems[0], "scan: not named (touched by internal/scanner/run.go)") {
		t.Errorf("problems = %q, want scan touched by the old path", problems)
	}
}

func gitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const goodFeature = "# Scan\n\nScans.\n\n" +
	"## Sub-features\n\n- `scan-json`\n\n" +
	"## How to get to it (user POV)\n\n- `crypto-finder scan`\n\n" +
	"## Driving it with run.sh\n\n```bash\n## not a section\n```\n\n" +
	"## Gotchas\n\n- none\n\n" +
	"## Code paths\n\n- `internal/scanner/**`\n- `internal/cli/scan.go`\n"

const goodIndex = "# Map\n\n## Features\n\n- [scan](./scan.md): scanning.\n\nSee [the skill](../SKILL.md).\n"

var trackedFixture = []string{"internal/scanner/run.go", "internal/cli/scan.go", "README.md"}

func TestCheckDocs(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string
		problems []string
	}{
		{
			name:  "consistent map passes",
			files: map[string]string{"scan.md": goodFeature, "README.md": goodIndex},
		},
		{
			name:     "dead glob fails",
			files:    map[string]string{"scan.md": goodFeature + "- `internal/gone/**`\n", "README.md": goodIndex},
			problems: []string{`scan.md: glob "internal/gone/**" matches no tracked file`},
		},
		{
			name:     "malformed glob fails",
			files:    map[string]string{"scan.md": goodFeature + "- `internal/[`\n", "README.md": goodIndex},
			problems: []string{`scan.md: malformed glob "internal/["`},
		},
		{
			name:     "missing section fails",
			files:    map[string]string{"scan.md": strings.Replace(goodFeature, "## Gotchas\n\n- none\n\n", "", 1), "README.md": goodIndex},
			problems: []string{`scan.md: missing section "## Gotchas"`},
		},
		{
			name:     "sections out of order fail",
			files:    map[string]string{"scan.md": strings.Replace(goodFeature, "## Sub-features", "## Extra\n\n## Sub-features", 1), "README.md": goodIndex},
			problems: []string{"scan.md: sections are"},
		},
		{
			name:     "code paths without a glob fail",
			files:    map[string]string{"scan.md": strings.Split(goodFeature, "- `internal/scanner/**`")[0], "README.md": goodIndex},
			problems: []string{`scan.md: "## Code paths" lists no backticked glob`},
		},
		{
			name:     "feature missing from the index fails",
			files:    map[string]string{"scan.md": goodFeature, "convert.md": strings.Replace(goodFeature, "# Scan", "# Convert", 1), "README.md": goodIndex},
			problems: []string{`README.md: "## Features" does not link convert.md`},
		},
		{
			name:     "index entry without a file fails",
			files:    map[string]string{"scan.md": goodFeature, "README.md": goodIndex + "- [gone](./gone.md): removed.\n"},
			problems: []string{"README.md: links gone.md, which is not a feature file"},
		},
		{
			name:     "missing index fails",
			files:    map[string]string{"scan.md": goodFeature},
			problems: []string{"README.md: missing"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for name, body := range tt.files {
				fsys[name] = &fstest.MapFile{Data: []byte(body)}
			}
			problems, err := checkDocs(fsys, trackedFixture)
			if err != nil {
				t.Fatal(err)
			}
			if len(problems) != len(tt.problems) {
				t.Fatalf("problems = %q, want %d matching %q", problems, len(tt.problems), tt.problems)
			}
			for i, want := range tt.problems {
				if !strings.Contains(problems[i], want) {
					t.Errorf("problem %d = %q, want it to contain %q", i, problems[i], want)
				}
			}
		})
	}
}

// TestRealMapIsConsistent runs check-docs on this repository's feature map.
func TestRealMapIsConsistent(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		t.Skip("not in a git checkout")
	}
	tracked := strings.Split(strings.TrimSuffix(gitT(t, root, "ls-files", "-z"), "\x00"), "\x00")
	problems, err := checkDocs(os.DirFS(filepath.Join(root, featureDir)), tracked)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) > 0 {
		t.Errorf("feature map problems:\n%s", strings.Join(problems, "\n"))
	}
	features, err := loadFeatures(os.DirFS(filepath.Join(root, featureDir)))
	if err != nil || len(features) < 6 {
		t.Fatalf("loaded %d features, err %v; want the six mapped features", len(features), err)
	}
}

func TestRunUsage(t *testing.T) {
	var out, errOut strings.Builder
	if code := run(nil, &out, &errOut); code != 2 {
		t.Errorf("no args: exit %d, want 2", code)
	}
	if code := run([]string{"check-pr", "--base", "x"}, &out, &errOut); code != 2 {
		t.Errorf("check-pr without --head/--body-file: exit %d, want 2", code)
	}
	if code := run([]string{"nope"}, &out, &errOut); code != 2 {
		t.Errorf("unknown command: exit %d, want 2", code)
	}
}
