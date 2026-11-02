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
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestFindMerges(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		// want lists, per merge found, its gh pr view arguments, its
		// repo#number, or "unresolved".
		want []string
	}{
		{"squash merge", "gh pr merge 12 --squash", []string{"pr view 12 --json number,url"}},
		{"auto merge", "gh pr merge --auto 12", []string{"pr view 12 --json number,url"}},
		{"no argument", "gh pr merge --squash --delete-branch", []string{"pr view --json number,url"}},
		{"flag values skipped", "gh pr merge --subject fix -t y 12 -b z", []string{"pr view 12 --json number,url"}},
		{"flag value with spaces", "gh pr merge --subject 'fix: x' 12", []string{"unresolved"}},
		{"explicit repo", "gh pr merge -R o/r 12", []string{"pr view 12 -R o/r --json number,url"}},
		{"explicit repo, equals form", "gh pr merge --repo=o/r 12", []string{"pr view 12 -R o/r --json number,url"}},
		{"merge API", "gh api -X PUT repos/o/r/pulls/12/merge", []string{"o/r#12"}},
		{"merge API, leading slash", "gh api --method PUT /repos/o/r/pulls/12/merge -f merge_method=squash", []string{"o/r#12"}},
		{"merge API, placeholders", "gh api -X PUT repos/{owner}/{repo}/pulls/12/merge", []string{"unresolved"}},
		{"merge API, variable", "gh api -X PUT repos/o/r/pulls/$N/merge", []string{"unresolved"}},
		{"GraphQL merge", `gh api graphql -f query='mutation { mergePullRequest(input: {pullRequestId: "PR_x"}) { clientMutationId } }'`, []string{"unresolved"}},
		{"GraphQL auto-merge", `gh api graphql -f query='mutation { enablePullRequestAutoMerge(input: {pullRequestId: "PR_x"}) { clientMutationId } }'`, []string{"unresolved"}},
		{"line continuation", "gh pr \\\n  merge \\\n  12 --squash", []string{"pr view 12 --json number,url"}},
		{"bash -c", `bash -c "gh pr merge 12"`, []string{"pr view 12 --json number,url"}},
		{"quoted words", `gh 'pr' "merge" 12`, []string{"pr view 12 --json number,url"}},
		{"backslash inside a word", `gh pr mer\ge 12`, []string{"pr view 12 --json number,url"}},
		{"heredoc to a shell", "bash <<'EOF'\ngh pr merge 12\nEOF", []string{"pr view 12 --json number,url"}},
		{"after cd", "cd ../other && gh pr merge 12", []string{"unresolved"}},
		{"after cd, explicit repo", "cd ../other && gh pr merge 12 -R o/r", []string{"pr view 12 -R o/r --json number,url"}},
		{"after cd, URL", "cd ../other && gh pr merge https://github.com/o/r/pull/12", []string{"pr view https://github.com/o/r/pull/12 --json number,url"}},
		{"GH_REPO", "GH_REPO=o/x gh pr merge 12", []string{"unresolved"}},
		{"two merges", "gh pr merge 12; gh pr merge 13 --rebase", []string{"pr view 12 --json number,url", "pr view 13 --json number,url"}},
		{"disable-auto in another command", "gh pr merge 13 --disable-auto && gh pr merge 12", []string{"pr view 12 --json number,url"}},
		{"mention in an echo", `echo "then gh pr merge 12"`, []string{"pr view 12 --json number,url"}},
		{"mention in a commit message", `git commit -m "docs: run gh pr merge 12 after check"`, []string{"unresolved"}},

		{"git status", "git status", nil},
		{"disable auto-merge", "gh pr merge 12 --disable-auto", nil},
		{"view", "gh pr view 12", nil},
		{"checks", "gh pr checks 12 --watch", nil},
		{"git merge", "git merge origin/main", nil},
		{"pulls list", "gh api repos/o/r/pulls/12/comments", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, m := range findMerges(tc.cmd) {
				switch {
				case m.unresolved != "":
					got = append(got, "unresolved")
				case m.repo != "":
					got = append(got, m.repo+"#"+strconv.Itoa(m.number))
				default:
					got = append(got, strings.Join(m.viewArgs, " "))
				}
			}
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("findMerges(%q)\n got %q\nwant %q", tc.cmd, got, tc.want)
			}
		})
	}
}

func event(t *testing.T, tool, command string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"tool_name":  tool,
		"tool_input": map[string]string{"command": command},
		"cwd":        "/repo",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestRunHook(t *testing.T) {
	const view12 = "/repo: pr view 12 --json number,url"
	resolved := func(responses map[string]string) map[string]string {
		responses[view12] = `{"number":12,"url":"https://github.com/o/r/pull/12"}`
		return responses
	}
	notReady := readyPR()
	notReady[keyChecks] = `{"check_runs":[{"name":"test","status":"completed","conclusion":"failure"}]}`
	tests := []struct {
		name      string
		stdin     string
		responses map[string]string
		code      int
		stderr    string
		noCalls   bool
	}{
		{name: "not a merge", stdin: event(t, "Bash", "git status"), code: 0, noCalls: true},
		{name: "not Bash", stdin: event(t, "Write", "gh pr merge 12"), code: 0, noCalls: true},
		{name: "ready", stdin: event(t, "Bash", "gh pr merge 12 --squash"), responses: resolved(readyPR()), code: 0},
		{name: "ready via the API", stdin: event(t, "Bash", "gh api -X PUT repos/o/r/pulls/12/merge"), responses: readyPR(), code: 0},
		{
			name: "not ready", stdin: event(t, "Bash", "gh pr merge 12 --squash"), responses: resolved(notReady), code: 2,
			stderr: `o/r#12: check "test" finished with failure`,
		},
		{
			name: "unresolvable pull request", stdin: event(t, "Bash", "gh pr merge 12"), responses: map[string]string{}, code: 2,
			stderr: `cannot tell which pull request "pr merge 12" merges`,
		},
		{
			name: "GraphQL", stdin: event(t, "Bash", "gh api graphql -f query=mutation{mergePullRequest(input:{})}"), code: 2,
			stderr: "GraphQL merge mutations",
		},
		{name: "bad JSON", stdin: `{"tool_name":`, code: 2, stderr: "cannot read its event", noCalls: true},
		{name: "empty stdin", stdin: ``, code: 2, stderr: "cannot read its event", noCalls: true},
		{name: "no tool name", stdin: `{"tool_input":{"command":"gh pr merge 12"}}`, code: 2, stderr: "cannot read its event", noCalls: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeGH{responses: tc.responses}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"hook"}, strings.NewReader(tc.stdin), &stdout, &stderr, f)
			if code != tc.code {
				t.Fatalf("exit %d, want %d; stderr:\n%s", code, tc.code, stderr.String())
			}
			if tc.stderr != "" && !strings.Contains(stderr.String(), tc.stderr) {
				t.Fatalf("stderr lacks %q:\n%s", tc.stderr, stderr.String())
			}
			if code == 2 && !strings.Contains(stderr.String(), "never work around this hook") {
				t.Fatalf("block message lacks the rule:\n%s", stderr.String())
			}
			if tc.noCalls && len(f.calls) != 0 {
				t.Fatalf("want no gh calls, got %q", f.calls)
			}
		})
	}
}

type panicGH struct{}

func (panicGH) run(context.Context, string, ...string) ([]byte, error) { panic("boom") }

func TestRunHookPanicBlocks(t *testing.T) {
	var stderr bytes.Buffer
	code := runHook(context.Background(), strings.NewReader(event(t, "Bash", "gh pr merge 12")), &printer{w: &stderr}, panicGH{})
	if code != 2 || !strings.Contains(stderr.String(), "the merge hook failed: boom") {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr.String())
	}
}
