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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// hookBudget bounds the whole hook. Claude Code allows it 90 s, which also
// pays for compiling this command, and lets the tool call through when the
// hook times out, so the hook must decide well before.
const hookBudget = 60 * time.Second

// The hook reads the command as text and does not parse shell: wrappers,
// quoting, heredocs and line continuations all still contain these words.
var (
	prMergeRe    = regexp.MustCompile(`\bpr\s+merge\b`)
	pullsMergeRe = regexp.MustCompile(`(?:repos/([^/\s]+)/([^/\s]+)/)?pulls/([^/\s]*)/merge`)
	graphqlRe    = regexp.MustCompile(`(?i)mergePullRequest|enablePullRequestAutoMerge`)
	// segmentEndRe ends the arguments of one gh pr merge.
	segmentEndRe = regexp.MustCompile(`[;&|\n)]`)
	// elsewhereRe flags a command that may run gh in another repository than
	// the event's working directory.
	elsewhereRe = regexp.MustCompile(`\b(cd|pushd)\s|GH_REPO|GH_HOST`)
	nameRe      = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	pullURLRe   = regexp.MustCompile(`^https://[^/]+/([^/]+/[^/]+)/pull/(\d+)$`)
)

// prMergeValueFlags are the gh pr merge flags that take a value.
var prMergeValueFlags = map[string]bool{
	"-A": true, "--author-email": true, "-b": true, "--body": true, "-F": true, "--body-file": true,
	"--match-head-commit": true, "-R": true, "--repo": true, "-t": true, "--subject": true,
}

// mergeTarget is one merge found in a command.
type mergeTarget struct {
	match string
	// viewArgs resolve the pull request with gh pr view, when repo is empty.
	viewArgs []string
	repo     string
	number   int
	// unresolved says why the pull request cannot be identified.
	unresolved string
}

// normalize joins line continuations and drops quotes and backslashes, so
// that `gh "pr" mer\ge` reads as the merge it runs.
func normalize(cmd string) string {
	cmd = strings.ReplaceAll(cmd, "\\\r\n", " ")
	cmd = strings.ReplaceAll(cmd, "\\\n", " ")
	return strings.NewReplacer(`\`, "", `"`, "", `'`, "").Replace(cmd)
}

// findMerges returns every merge that cmd may run.
func findMerges(cmd string) []mergeTarget {
	text := normalize(cmd)
	var out []mergeTarget
	for _, loc := range prMergeRe.FindAllStringIndex(text, -1) {
		rest := text[loc[1]:]
		if end := segmentEndRe.FindStringIndex(rest); end != nil {
			rest = rest[:end[0]]
		}
		if t, ok := prMergeTarget(text, rest); ok {
			out = append(out, t)
		}
	}
	for _, m := range pullsMergeRe.FindAllStringSubmatch(text, -1) {
		t := mergeTarget{match: m[0]}
		n, err := strconv.Atoi(m[3])
		if !nameRe.MatchString(m[1]) || !nameRe.MatchString(m[2]) || err != nil || n <= 0 {
			t.unresolved = "the command calls the merge API but the hook cannot read its owner, repository and number as text"
		} else {
			t.repo, t.number = m[1]+"/"+m[2], n
		}
		out = append(out, t)
	}
	for _, m := range graphqlRe.FindAllString(text, -1) {
		out = append(out, mergeTarget{
			match:      m,
			unresolved: "GraphQL merge mutations name the pull request by node id, which the hook cannot check; use gh pr merge <n>",
		})
	}
	return out
}

// prMergeTarget reads the arguments of one gh pr merge. It reports false for
// a merge that only disables auto-merge.
func prMergeTarget(text, args string) (mergeTarget, bool) {
	fields := strings.Fields(args)
	t := mergeTarget{match: strings.Join(append([]string{"pr", "merge"}, fields...), " ")}
	var positional []string
	var repo string
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		switch {
		case f == "--disable-auto":
			return t, false
		case strings.HasPrefix(f, "--repo="):
			repo = strings.TrimPrefix(f, "--repo=")
		case prMergeValueFlags[f]:
			if (f == "-R" || f == "--repo") && i+1 < len(fields) {
				repo = fields[i+1]
			}
			i++
		case strings.HasPrefix(f, "-"):
		default:
			positional = append(positional, f)
		}
	}
	switch {
	case len(positional) > 1:
		// Quotes are dropped, so a flag value with spaces leaves words behind.
		t.unresolved = "the hook cannot tell which argument is the pull request (a flag value with spaces?); " +
			"run gh pr merge <n> with single-word flag values"
		return t, true
	case repo == "" && (len(positional) == 0 || !strings.HasPrefix(positional[0], "https://")) && elsewhereRe.MatchString(text):
		t.unresolved = "the command changes directory or sets GH_REPO, so the hook cannot tell which repository it merges in; " +
			"pass -R owner/name or the pull request URL"
		return t, true
	}
	t.viewArgs = append([]string{"pr", "view"}, positional...)
	if repo != "" {
		t.viewArgs = append(t.viewArgs, "-R", repo)
	}
	t.viewArgs = append(t.viewArgs, "--json", "number,url")
	return t, true
}

// resolve fills in the repository and number of t with gh pr view in dir.
func resolve(ctx context.Context, g gh, dir string, t mergeTarget) (repo string, number int, err error) {
	if t.unresolved != "" {
		return "", 0, fmt.Errorf("%s", t.unresolved)
	}
	if t.repo != "" {
		return t.repo, t.number, nil
	}
	raw, err := g.run(ctx, dir, t.viewArgs...)
	if err != nil {
		return "", 0, err
	}
	var v struct {
		Number int    `json:"number"`
		URL    string `json:"url"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", 0, fmt.Errorf("unparseable gh pr view output: %w", err)
	}
	m := pullURLRe.FindStringSubmatch(v.URL)
	if len(m) != 3 || m[2] != strconv.Itoa(v.Number) {
		return "", 0, fmt.Errorf("unexpected gh pr view output %s", raw)
	}
	return m[1], v.Number, nil
}

type hookEvent struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
	Cwd string `json:"cwd"`
}

// runHook is the PreToolUse hook. It exits 0 to let the tool call run and 2
// to block it. Anything else lets the call through, so every failure,
// including a panic, exits 2.
func runHook(ctx context.Context, stdin io.Reader, stderr *printer, g gh) (code int) {
	var problems []string
	defer func() {
		if r := recover(); r != nil {
			problems = append(problems, fmt.Sprintf("the merge hook failed: %v", r))
		}
		if len(problems) > 0 {
			blockMessage(stderr, problems)
			code = 2
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, hookBudget)
	defer cancel()
	var ev hookEvent
	if err := json.NewDecoder(stdin).Decode(&ev); err != nil || ev.ToolName == "" {
		problems = append(problems, fmt.Sprintf("the merge hook cannot read its event (%v)", err))
		return 2
	}
	if ev.ToolName != "Bash" {
		return 0
	}
	seen := map[string]bool{}
	for _, t := range findMerges(ev.ToolInput.Command) {
		repo, number, err := resolve(ctx, g, ev.Cwd, t)
		if err != nil {
			problems = append(problems, fmt.Sprintf("cannot tell which pull request %q merges: %v", t.match, err))
			continue
		}
		key := repo + "#" + strconv.Itoa(number)
		if seen[key] {
			continue
		}
		seen[key] = true
		for _, r := range checkPR(ctx, client{gh: g, repo: repo}, number) {
			problems = append(problems, key+": "+r)
		}
	}
	return 0
}

func blockMessage(w *printer, problems []string) {
	w.println("Merge blocked by scripts/mergeready:")
	for _, p := range problems {
		w.println("- " + p)
	}
	w.println("Fix these reasons and retry; never work around this hook.")
	w.println("The hook reads commands as text: a command that only mentions a merge " +
		"(an echo, a commit message, a PR body) is checked too, so write such text with a file tool.")
}
