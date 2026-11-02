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

package opengrep

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

const ignoredTargetSource = "package main\n\nimport \"crypto/des\"\n\nfunc main() { _, _ = des.NewCipher([]byte(\"12345678\")) }\n"

// TestScanner_Integration_TargetIgnoredByParentRepo pins #810: a target
// that its enclosing Git work tree ignores is scanned as a work tree of its
// own, so the .gitignore files above it never empty it and those inside it
// still apply. A target the work tree does not ignore keeps the parent's
// rules.
func TestScanner_Integration_TargetIgnoredByParentRepo(t *testing.T) {
	checkOpengrepAvailable(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	rules, err := filepath.Abs(filepath.Join("..", "..", "..", "testdata", "rules", "go.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, parentIgnore string
		want               []string
	}{
		// The target's own .gitignore drops skip.go; the parent's build/
		// rule is in the .gitignore above the target, so it does not apply.
		{name: "target ignored", parentIgnore: "sub/\nbuild/\n", want: []string{"build/generated.go", "inner/keep.go", "main.go"}},
		// Unchanged: the parent's build/ rule applies inside the target.
		{name: "target not ignored", parentIgnore: "build/\n", want: []string{"inner/keep.go", "main.go"}},
	} {
		for _, mode := range []scanner.OpengrepMode{scanner.OpengrepModeCLI, scanner.OpengrepModeCore} {
			t.Run(tc.name+"/"+mode.String(), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				root := t.TempDir()
				if out, err := exec.CommandContext(ctx, "git", "init", "--quiet", root).CombinedOutput(); err != nil {
					t.Fatalf("git init: %v: %s", err, out)
				}
				for rel, contents := range map[string]string{
					".gitignore":                 ".gitignore\n" + tc.parentIgnore,
					"sub/app/main.go":            ignoredTargetSource,
					"sub/app/inner/keep.go":      ignoredTargetSource,
					"sub/app/.gitignore":         "skip.go\n",
					"sub/app/skip.go":            ignoredTargetSource,
					"sub/app/build/generated.go": ignoredTargetSource,
				} {
					path := filepath.Join(root, filepath.FromSlash(rel))
					if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				target := filepath.Join(root, "sub", "app")
				s := NewScanner()
				if err := s.Initialize(ctx, scanner.Config{Timeout: time.Minute, WorkDir: target, OpengrepMode: mode}); err != nil {
					skipIfOpengrepEnvironmentIssue(t, err)
					t.Fatal(err)
				}
				if mode == scanner.OpengrepModeCore {
					if _, err := s.coreBinary(ctx); err != nil {
						t.Skipf("opengrep-core unavailable: %v", err)
					}
				}
				report, err := s.Scan(ctx, target, []string{rules}, entities.ToolInfo{Name: "opengrep"})
				if err != nil {
					t.Fatal(err)
				}
				if s.env != nil {
					t.Fatalf("the scan left GIT_* in the scanner's environment: %v", s.env)
				}
				got := make([]string, 0, len(report.Findings))
				for _, finding := range report.Findings {
					got = append(got, filepath.ToSlash(finding.FilePath))
				}
				slices.Sort(got)
				if strings.Join(got, ",") != strings.Join(tc.want, ",") {
					t.Fatalf("findings in %v, want %v", got, tc.want)
				}
			})
		}
	}
}
