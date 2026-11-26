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

	"github.com/scanoss/crypto-finder/scripts/internal/leakguard"
)

// TestCheckLeaks runs the guard over a real repository: a name on an added
// line, the same name on a line that only existed before, a home path, a
// ruleset-shaped file outside and inside testdata, the commit message, the
// title and the body.
func TestCheckLeaks(t *testing.T) {
	root := t.TempDir()
	gitT(t, root, "init", "-q", "-b", "main")
	writeFile(t, root, "docs/a.md", "old zq9host line\n")
	gitT(t, root, "add", ".")
	gitT(t, root, "commit", "-q", "-m", "base")
	base := strings.TrimSpace(gitT(t, root, "rev-parse", "HEAD"))

	writeFile(t, root, "docs/a.md", "old zq9host line\nnew line\nmore on ZQ9-host\n")
	writeFile(t, root, "scripts/run.sh", "cd /home"+"/alice/src\ncd /home/u/src\n")
	ruleset := "rules:\n  - id: invented\n    metadata:\n      crypto:\n        assetType: algorithm\n"
	writeFile(t, root, "rules/x.yaml", ruleset)
	writeFile(t, root, "internal/rules/testdata/x.yaml", ruleset)
	gitT(t, root, "add", ".")
	gitT(t, root, "commit", "-q", "-m", "feat: talk to zq9host")
	head := strings.TrimSpace(gitT(t, root, "rev-parse", "HEAD"))

	sum, err := leakguard.Hash("zq9host", false)
	if err != nil {
		t.Fatal(err)
	}
	d, err := leakguard.ParseDenylist("host loose " + sum)
	if err != nil {
		t.Fatal(err)
	}
	got, err := checkLeaks(root, base, head, "fix: zq9host", "## Summary\nclean\nsee zq9_host\n", leakguard.New(d))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"PR title:1: internal name (host)",
		"PR body:3: internal name (host)",
		"commit " + head[:12] + ":1: internal name (host)",
		"docs/a.md:3: internal name (host)",
		"scripts/run.sh:1: absolute home path",
		"rules/x.yaml: looks like private ruleset content (rules with crypto metadata)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestPRTitleFromEvent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(p, []byte(`{"pull_request":{"title":"feat: x","body":"b"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := prTitle("", p); err != nil || got != "feat: x" {
		t.Errorf("prTitle from event = %q, %v", got, err)
	}
	if got, err := prTitle("", ""); err != nil || got != "" {
		t.Errorf("prTitle without event = %q, %v", got, err)
	}
	tf := filepath.Join(t.TempDir(), "title")
	if err := os.WriteFile(tf, []byte("chore: y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := prTitle(tf, p); err != nil || got != "chore: y" {
		t.Errorf("prTitle from --title-file = %q, %v", got, err)
	}
}
