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
	writeFile(t, root, "internal/rules/testdata/y.yaml", "# leakguard: invented-rules\n"+ruleset)
	gitT(t, root, "add", ".")
	gitT(t, root, "commit", "-q", "-m", "feat: talk to zq9host")
	first := strings.TrimSpace(gitT(t, root, "rev-parse", "HEAD"))

	// A commit the branch merges in, written by someone else, is not scanned;
	// the merge commit itself is.
	gitT(t, root, "checkout", "-q", "-b", "other", base)
	writeFile(t, root, "docs/b.md", "b\n")
	gitT(t, root, "add", ".")
	gitT(t, root, "commit", "-q", "-m", "chore: zq9host elsewhere")
	gitT(t, root, "checkout", "-q", "main")
	gitT(t, root, "merge", "-q", "--no-ff", "-m", "merge zq9host", "other")
	merged := strings.TrimSpace(gitT(t, root, "rev-parse", "HEAD"))
	head := merged

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
		"commit " + merged[:12] + ":1: internal name (host)",
		"commit " + first[:12] + ":1: internal name (host)",
		"docs/a.md:3: internal name (host)",
		"scripts/run.sh:1: absolute home path",
		"internal/rules/testdata/x.yaml: looks like private ruleset content (rules with crypto metadata)",
		"rules/x.yaml: looks like private ruleset content (rules with crypto metadata)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestPRFromEvent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "event.json")
	if err := os.WriteFile(p, []byte(`{"pull_request":{"title":"feat: x","body":"b","user":{"type":"User"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, bot, err := prMeta("", p); err != nil || got != "feat: x" || bot {
		t.Errorf("prMeta from event = %q, %v, %v", got, bot, err)
	}
	if got, bot, err := prMeta("", ""); err != nil || got != "" || bot {
		t.Errorf("prMeta without event = %q, %v, %v", got, bot, err)
	}
	tf := filepath.Join(dir, "title")
	if err := os.WriteFile(tf, []byte("chore: y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _, err := prMeta(tf, p); err != nil || got != "chore: y" {
		t.Errorf("prMeta from --title-file = %q, %v", got, err)
	}
	bp := filepath.Join(dir, "bot.json")
	if err := os.WriteFile(bp, []byte(`{"pull_request":{"title":"build(deps): bump","user":{"login":"dependabot[bot]","type":"Bot"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, bot, err := prMeta("", bp); err != nil || !bot {
		t.Errorf("prMeta of a bot PR: bot=%v, %v", bot, err)
	}
}
