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
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, root, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

const sampleChangelog = `# Changelog

Intro.

## [Unreleased]
### Added
- old way added
### Fixed
- old way fixed

## [1.0.0] - 2026-01-01
### Added
- first
`

func TestRepoFragmentsAreWellFormed(t *testing.T) {
	if err := check("../.."); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseChangelogMergesOldEntriesAndFragments(t *testing.T) {
	root := t.TempDir()
	write(t, root, changelogFile, sampleChangelog)
	write(t, root, "changelog.d/b-lib.added.md", "- fragment b\n")
	write(t, root, "changelog.d/a-lib.added.md", "- fragment a\n")
	write(t, root, "changelog.d/c-bug.changed.md", "- fragment changed\n")
	write(t, root, "changelog.d/README.md", "ignored")

	if err := releaseChangelog(root, "1.1.0", "2026-02-02", false); err != nil {
		t.Fatal(err)
	}
	want := `# Changelog

Intro.

## [Unreleased]

## [1.1.0] - 2026-02-02
### Added
- old way added
- fragment a
- fragment b
### Changed
- fragment changed
### Fixed
- old way fixed

## [1.0.0] - 2026-01-01
### Added
- first
`
	if got := read(t, root, changelogFile); got != want {
		t.Fatalf("changelog mismatch\n--- got\n%s\n--- want\n%s", got, want)
	}
	entries, _ := os.ReadDir(filepath.Join(root, changelogDir))
	if len(entries) != 1 || entries[0].Name() != "README.md" {
		t.Fatalf("fragments were not removed: %v", entries)
	}
}

func TestReleaseChangelogRefusesEmptyRelease(t *testing.T) {
	root := t.TempDir()
	write(t, root, changelogFile, "## [Unreleased]\n\n## [1.0.0] - 2026-01-01\n")
	write(t, root, "changelog.d/README.md", "x")
	if err := releaseChangelog(root, "1.1.0", "2026-02-02", false); err == nil {
		t.Fatal("expected an error for an empty release")
	}
}

func TestBadChangelogFragmentsAreRejected(t *testing.T) {
	for name, body := range map[string]string{
		"x.added.md":    "not a bullet",
		"x.nonsense.md": "- ok",
		"x.md":          "- ok",
		"x.added.txt":   "- ok",
		"x.added.md ":   "- ok",
	} {
		root := t.TempDir()
		write(t, root, "changelog.d/"+name, body)
		if _, err := readChangelogFragments(root); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
}

func TestFoldGuideAppendsInOrderAndIsStable(t *testing.T) {
	root := t.TempDir()
	write(t, root, guideFile, "<p>old</p>\n"+guideBegin+"\n<p>prev</p>\n"+guideEnd+"\n<div></div>\n")
	write(t, root, guideFragmentDir+"/b.html", "<p>b</p>\n")
	write(t, root, guideFragmentDir+"/a.html", "<p>a</p>\n")
	if err := foldGuide(root, false); err != nil {
		t.Fatal(err)
	}
	want := "<p>old</p>\n" + guideBegin + "\n<p>prev</p>\n<p>a</p>\n<p>b</p>\n" + guideEnd + "\n<div></div>\n"
	if got := read(t, root, guideFile); got != want {
		t.Fatalf("guide mismatch\n--- got\n%s\n--- want\n%s", got, want)
	}
	if err := foldGuide(root, false); err == nil || !strings.Contains(err.Error(), "nothing to fold") {
		t.Fatalf("second fold should refuse, got %v", err)
	}
}

func TestBadGuideFragmentsAreRejected(t *testing.T) {
	for name, body := range map[string]string{
		"a.html": "<p>one</p><p>two</p>",
		"b.html": "<p>multi\nline</p>",
		"c.html": "text",
		"d.txt":  "<p>x</p>",
	} {
		root := t.TempDir()
		write(t, root, guideFragmentDir+"/"+name, body)
		if _, err := readGuideFragments(root); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
}
