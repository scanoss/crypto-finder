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

package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIgnoredTargetWorkTree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	for _, tc := range []struct {
		name, gitignore, target string
		repo, want              bool
	}{
		{name: "ignored parent directory", gitignore: "sub/\n", target: "sub/app", repo: true, want: true},
		{name: "ignored target", gitignore: "app/\n", target: "sub/app", repo: true, want: true},
		{name: "ignored contents of the parent", gitignore: "sub/*\n", target: "sub/app", repo: true, want: true},
		{name: "not ignored", gitignore: "build/\n", target: "sub/app", repo: true},
		{name: "repository root", gitignore: "sub/\n", target: ".", repo: true},
		{name: "no repository", gitignore: "sub/\n", target: "sub/app"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.repo {
				if out, err := exec.CommandContext(t.Context(), "git", "init", "--quiet", root).CombinedOutput(); err != nil {
					t.Fatalf("git init: %v: %s", err, out)
				}
			}
			target := filepath.Join(root, filepath.FromSlash(tc.target))
			if err := os.MkdirAll(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte(tc.gitignore), 0o600); err != nil {
				t.Fatal(err)
			}
			wt, err := IgnoredTargetWorkTree(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			if (wt != nil) != tc.want {
				t.Fatalf("IgnoredTargetWorkTree(%s) = %v, want a work tree: %v", tc.target, wt, tc.want)
			}
			if wt == nil {
				if wt.Env() != nil || wt.Close() != nil {
					t.Fatal("a nil WorkTree must add nothing and close cleanly")
				}
				return
			}
			gitDir := wt.Env()["GIT_DIR"]
			if wt.Env()["GIT_WORK_TREE"] == "" {
				t.Fatalf("env %v lacks GIT_WORK_TREE", wt.Env())
			}
			if err := wt.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(gitDir); !os.IsNotExist(err) {
				t.Fatalf("Close left %s behind: %v", gitDir, err)
			}
		})
	}
}
