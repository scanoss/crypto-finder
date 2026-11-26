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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/scanoss/crypto-finder/scripts/internal/leakguard"
)

// checkLeaks runs the leak guard over what a pull request makes public: its
// title, its body, its commit messages, the lines it adds and the YAML files it
// adds or changes. It returns one line per finding, never the matched text.
func checkLeaks(root, base, head, title, body string, g *leakguard.Guard) ([]string, error) {
	var findings []leakguard.Finding
	findings = append(findings, g.ScanText("PR title", title)...)
	findings = append(findings, g.ScanText("PR body", body)...)

	log, err := git(root, "log", "--format=%H%x00%B%x00", base+".."+head)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(log, "\x00")
	for i := 0; i+1 < len(parts); i += 2 {
		sha := strings.TrimSpace(parts[i])
		if len(sha) > 12 {
			sha = sha[:12]
		}
		findings = append(findings, g.ScanText("commit "+sha, strings.TrimSpace(parts[i+1]))...)
	}

	diff, err := git(root, "-c", "core.quotePath=false", "diff", "-U0", "--no-color", "--no-ext-diff", "-M", base+"..."+head)
	if err != nil {
		return nil, err
	}
	findings = append(findings, g.ScanDiff(diff)...)

	status, err := git(root, "diff", "--name-only", "-z", "--diff-filter=AMR", "-M", base+"..."+head)
	if err != nil {
		return nil, err
	}
	for _, name := range strings.Split(strings.TrimSuffix(status, "\x00"), "\x00") {
		if name == "" || !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		content, err := git(root, "show", head+":"+name)
		if err != nil {
			return nil, err
		}
		if f := leakguard.CheckRuleset(name, []byte(content)); f != nil {
			findings = append(findings, *f)
		}
	}

	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.String())
	}
	return out, nil
}

// prTitle returns the title in titleFile when given, else the pull request
// title of the GitHub Actions event payload at eventPath, else "".
func prTitle(titleFile, eventPath string) (string, error) {
	if titleFile != "" {
		b, err := os.ReadFile(titleFile) // #nosec G304 -- a path the caller passed on the command line
		if err != nil {
			return "", fmt.Errorf("read title: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if eventPath == "" {
		return "", nil
	}
	b, err := os.ReadFile(eventPath) // #nosec G304 -- GITHUB_EVENT_PATH, set by the Actions runner
	if err != nil {
		return "", fmt.Errorf("read event: %w", err)
	}
	var ev struct {
		PullRequest struct {
			Title string `json:"title"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(b, &ev); err != nil {
		return "", fmt.Errorf("parse event: %w", err)
	}
	return ev.PullRequest.Title, nil
}

// runCheckLeaks prints the guard's findings and returns errFailed when there
// are any.
func runCheckLeaks(root, base, head, title, body string, stdout *printer) error {
	d, err := leakguard.Default()
	if err != nil {
		return err
	}
	findings, err := checkLeaks(root, base, head, title, body, leakguard.New(d))
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		stdout.println("leakguard: no internal names, home paths or ruleset content")
		return nil
	}
	stdout.printf("leakguard: %d finding(s); this repository and its PRs are public:\n", len(findings))
	for _, f := range findings {
		stdout.println("  " + f)
	}
	stdout.println("Remove them (edit the PR title or body, amend the commit). See \"Leak guard\" in AGENTS.md.")
	return errFailed
}
