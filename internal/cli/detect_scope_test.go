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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeScopeTree(t *testing.T, files ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
	}
	return root
}

func TestReadDetectionPathList(t *testing.T) {
	entries, err := readDetectionPathList("-", strings.NewReader("a.go\r\n\n  pkg/b.go  \n\n"))
	require.NoError(t, err)
	require.Equal(t, []string{"a.go", "pkg/b.go"}, entries, "blank lines and CRLF endings are ignored")

	list := filepath.Join(t.TempDir(), "list.txt")
	require.NoError(t, os.WriteFile(list, []byte("c.go\n"), 0o600))
	entries, err = readDetectionPathList(list, strings.NewReader("ignored"))
	require.NoError(t, err)
	require.Equal(t, []string{"c.go"}, entries)

	_, err = readDetectionPathList(filepath.Join(t.TempDir(), "absent.txt"), nil)
	require.Error(t, err)
}

func TestBuildDetectionScope(t *testing.T) {
	root := writeScopeTree(t, "a.go", "pkg/b.go", "pkg/c.go")

	scope, stats, err := buildDetectionScope(t.Context(), root, []string{
		"pkg/b.go",
		"./a.go",
		filepath.Join(root, "pkg", "c.go"),
		"pkg/../a.go",
		"deleted.go",
	})
	require.NoError(t, err)
	require.Equal(t, []string{"a.go", filepath.Join("pkg", "b.go"), filepath.Join("pkg", "c.go")}, scope.Paths,
		"relative and absolute entries resolve to sorted, de-duplicated target-relative files")
	require.Equal(t, 1, stats.missing, "a deleted file in a change list is skipped, not an error")

	scope, _, err = buildDetectionScope(t.Context(), root, []string{"deleted.go"})
	require.NoError(t, err)
	require.NotNil(t, scope, "a list with nothing left still scopes detection, to nothing")
	require.Empty(t, scope.Paths)

	for name, entry := range map[string]string{
		"outside the target": filepath.Join("..", filepath.Base(root)+"-sibling", "x.go"),
		"the target itself":  ".",
		"a directory":        "pkg",
	} {
		_, _, err := buildDetectionScope(t.Context(), root, []string{entry})
		require.Errorf(t, err, "%s must be rejected", name)
	}

	_, _, err = buildDetectionScope(t.Context(), filepath.Join(root, "a.go"), []string{"a.go"})
	require.ErrorContains(t, err, "directory scan target")
}

func TestBuildDetectionScope_DropsGitIgnoredUntrackedFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := writeScopeTree(t, "kept.go", "tracked.gen.go", "ignored.gen.go")
	require.NoError(t, os.WriteFile(filepath.Join(root, ".gitignore"), []byte("*.gen.go\n"), 0o600))
	for _, args := range [][]string{{"init", "-q"}, {"add", "kept.go", ".gitignore"}, {"add", "-f", "tracked.gen.go"}} {
		cmd := exec.CommandContext(t.Context(), "git", args...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		require.NoErrorf(t, err, "git %v: %s", args, out)
	}

	scope, stats, err := buildDetectionScope(t.Context(), root, []string{"kept.go", "tracked.gen.go", "ignored.gen.go"})
	require.NoError(t, err)
	require.Equal(t, []string{"kept.go", "tracked.gen.go"}, scope.Paths,
		"a git-aware walk lists tracked files even when they match .gitignore, and skips untracked ignored ones")
	require.Equal(t, 1, stats.gitIgnored)
}
