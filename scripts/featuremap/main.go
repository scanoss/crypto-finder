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

// Command featuremap keeps the verify skill's feature map
// (.claude/skills/verify/features/) honest and ties pull requests to it.
//
// Usage (from the repository root):
//
//	go run ./scripts/featuremap check-docs
//	go run ./scripts/featuremap check-pr --base <sha> --head <sha> --body-file <path>
//	go run ./scripts/featuremap replay [--rev origin/main] [-n 60]
//
// check-docs fails unless every feature file has the five H2 sections of the
// map's README, in order, its "## Code paths" lists at least one backticked glob,
// every glob matches a file of `git ls-files`, and the README's "## Features"
// links every feature file and nothing else.
//
// check-pr reads the files changed between the merge base of base and head and
// head (a rename counts its old and new path; tests and testdata never count).
// For every feature with a glob matching a changed file, the body must name the
// feature id under "## Evidence", as "<id>: <link or evidence>" or
// "<id>: N/A: <reason>". An id is named only as a whole token: naming
// "reachability-dependencies" does not name "reachability". HTML comments in
// the body are ignored.
//
// replay runs the check-pr matching over each of the last n first-parent
// commits of rev against its parent, with an empty body, and prints how many
// features each commit would have asked for and which globs matched most often.
// Run it after changing globs.
//
// Globs follow git pathspec glob rules, anchored at the repository root: "*",
// "?" and "[...]" match within one path segment, and a "**" segment matches
// zero or more segments.
//
// Every command exits 0 when the check passes, 1 when it fails (listing every
// problem) and 2 on a usage error.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// gitTimeout bounds one git call; replay makes one per commit.
const gitTimeout = time.Minute

// printer writes output and keeps the first write error.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) println(a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintln(p.w, a...)
	}
}

func (p *printer) printf(format string, a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, a...) //nolint:gosec // G705: plain text to a terminal or a CI log, not a web page
	}
}

// errFailed marks a check that ran and found problems, already printed.
var errFailed = errors.New("check failed")

const usage = "usage: featuremap check-docs | check-pr --base SHA --head SHA --body-file PATH | replay [--rev REV] [-n N]"

// run runs one subcommand and returns its exit code. Output that could not be
// written turns a success into a failure.
func run(args []string, stdoutW, stderrW io.Writer) int {
	stdout, stderr := &printer{w: stdoutW}, &printer{w: stderrW}
	code := dispatch(args, stdout, stderr)
	if code == 0 && (stdout.err != nil || stderr.err != nil) {
		return 1
	}
	return code
}

func dispatch(args []string, stdout, stderr *printer) int {
	if len(args) == 0 {
		stderr.println(usage)
		return 2
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(stderr.w)
	root := fs.String("root", ".", "repository root")
	base := fs.String("base", "", "base commit, for check-pr")
	head := fs.String("head", "", "head commit, for check-pr")
	bodyFile := fs.String("body-file", "", "file holding the PR body, for check-pr")
	rev := fs.String("rev", "origin/main", "branch to replay, for replay")
	n := fs.Int("n", 60, "number of first-parent commits to replay, for replay")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	var err error
	switch args[0] {
	case "check-docs":
		err = runCheckDocs(*root, stdout)
	case "check-pr":
		if *base == "" || *head == "" || *bodyFile == "" {
			stderr.println("check-pr needs --base, --head and --body-file")
			return 2
		}
		err = runCheckPR(*root, *base, *head, *bodyFile, stdout)
	case "replay":
		err = runReplay(*root, *rev, *n, stdout)
	default:
		stderr.println(usage)
		return 2
	}
	if err == nil {
		return 0
	}
	if !errors.Is(err, errFailed) {
		stderr.println("featuremap:", err)
	}
	return 1
}

func git(root string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...) //nolint:gosec // G702: fixed git subcommands; only revisions and the root come from flags
	cmd.Dir = root
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

func trackedFiles(root string) ([]string, error) {
	out, err := git(root, "ls-files", "-z")
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSuffix(out, "\x00"), "\x00"), nil
}

// changedFiles lists the paths that the diff of revs reports ("A...B" for a
// pull request, "C^1 C" for one commit), renames counted on both sides.
func changedFiles(root string, revs ...string) ([]string, error) {
	out, err := git(root, append([]string{"diff", "--name-status", "-z", "-M"}, revs...)...)
	if err != nil {
		return nil, err
	}
	return parseNameStatus(out)
}

func featureFS(root string) (string, error) {
	dir := filepath.Join(root, featureDir)
	if _, err := os.Stat(dir); err != nil { //nolint:gosec // G703: maintainer CLI; the path comes from the repo root flag
		return "", fmt.Errorf("feature map: %w", err)
	}
	return dir, nil
}

func runCheckDocs(root string, stdout *printer) error {
	dir, err := featureFS(root)
	if err != nil {
		return err
	}
	tracked, err := trackedFiles(root)
	if err != nil {
		return err
	}
	problems, err := checkDocs(os.DirFS(dir), tracked)
	if err != nil {
		return err
	}
	if len(problems) > 0 {
		stdout.printf("featuremap: %d problem(s) in %s:\n", len(problems), featureDir)
		for _, p := range problems {
			stdout.println("  " + p)
		}
		return errFailed
	}
	stdout.printf("featuremap: %s is consistent\n", featureDir)
	return nil
}

func loadRepoFeatures(root string) ([]feature, error) {
	dir, err := featureFS(root)
	if err != nil {
		return nil, err
	}
	return loadFeatures(os.DirFS(dir))
}

func runCheckPR(root, base, head, bodyFile string, stdout *printer) error {
	features, err := loadRepoFeatures(root)
	if err != nil {
		return err
	}
	changed, err := changedFiles(root, base+"..."+head)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(bodyFile) //nolint:gosec // G703: maintainer CLI; the body file is a flag
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	problems, accepted := checkPR(features, changed, string(body))
	if len(problems) > 0 {
		stdout.printf("featuremap: the PR body must name every touched feature under %q:\n", evidenceHeader)
		for _, p := range problems {
			stdout.println("  " + p)
		}
		stdout.println("Evidence comes from .claude/skills/verify/scripts/run.sh <id>; see .github/pull_request_template.md.")
		return errFailed
	}
	if len(accepted) == 0 {
		stdout.println("featuremap: the change touches no feature")
		return nil
	}
	stdout.printf("featuremap: every touched feature is named: %s\n", strings.Join(accepted, ", "))
	return nil
}

func runReplay(root, rev string, n int, stdout *printer) error {
	features, err := loadRepoFeatures(root)
	if err != nil {
		return err
	}
	out, err := git(root, "log", "--first-parent", "--format=%H %P%x09%h %s", "-n", fmt.Sprint(n), rev)
	if err != nil {
		return err
	}
	var rows []replayRow
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		commit, rest, _ := strings.Cut(line, "\t")
		sha, parents, _ := strings.Cut(commit, " ")
		short, subject, _ := strings.Cut(rest, " ")
		if parents == "" {
			continue // the root commit has nothing to diff against
		}
		changed, err := changedFiles(root, sha+"^1", sha)
		if err != nil {
			return err
		}
		rows = append(rows, replayRow{short: short, subject: subject, changed: changed})
	}
	printReplay(stdout, features, rows)
	return nil
}

type replayRow struct {
	short, subject string
	changed        []string
}

// printReplay prints, per commit, the features it would ask for; then the
// distribution of that count and the globs that matched the most commits.
func printReplay(w *printer, features []feature, rows []replayRow) {
	dist := map[int]int{}
	globCommits := map[string]int{}
	for _, r := range rows {
		hits := touched(features, r.changed)
		dist[len(hits)]++
		w.printf("%s %d %-60.60s %s\n", r.short, len(hits), r.subject, strings.Join(sortedKeys(hits), ","))
		for _, f := range features {
			for _, g := range f.globs {
				for _, name := range r.changed {
					if !isIgnored(name) && matchGlob(g, name) {
						globCommits[f.id+" "+g]++
						break
					}
				}
			}
		}
	}
	w.printf("\n%d commits; features asked for -> commits:\n", len(rows))
	counts := make([]int, 0, len(dist))
	for k := range dist {
		counts = append(counts, k)
	}
	sort.Ints(counts)
	for _, k := range counts {
		w.printf("  %d -> %d\n", k, dist[k])
	}
	w.println("\nglobs by commits matched:")
	globs := sortedKeys(globCommits)
	sort.SliceStable(globs, func(i, j int) bool { return globCommits[globs[i]] > globCommits[globs[j]] })
	for _, g := range globs {
		w.printf("  %3d %s\n", globCommits[g], g)
	}
}
