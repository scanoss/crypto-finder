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
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The GitHub API shapes the metrics read, cut down to the fields they use.

type pull struct {
	Number         int        `json:"number"`
	Title          string     `json:"title"`
	Body           string     `json:"body"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	MergedAt       *time.Time `json:"merged_at"`
	MergeCommitSHA string     `json:"merge_commit_sha"`
	Head           struct {
		Ref string `json:"ref"`
	} `json:"head"`
}

type workflowRun struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Event        string    `json:"event"`
	HeadBranch   string    `json:"head_branch"`
	HeadSHA      string    `json:"head_sha"`
	CreatedAt    time.Time `json:"created_at"`
	CheckSuiteID int64     `json:"check_suite_id"`
}

type checkRun struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	DetailsURL  string     `json:"details_url"`
	CheckSuite  struct {
		ID int64 `json:"id"`
	} `json:"check_suite"`
}

type commit struct {
	SHA    string `json:"sha"`
	Commit struct {
		Message   string `json:"message"`
		Committer struct {
			Date time.Time `json:"date"`
		} `json:"committer"`
	} `json:"commit"`
}

type comment struct {
	ID   int64 `json:"id"`
	User struct {
		Login string `json:"login"`
	} `json:"user"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
	IssueURL  string    `json:"issue_url"`
}

type issue struct {
	Number    int        `json:"number"`
	Title     string     `json:"title"`
	CreatedAt time.Time  `json:"created_at"`
	ClosedAt  *time.Time `json:"closed_at"`
}

const (
	botLogin = "github-actions[bot]"
	// auditMarker starts the comment scripts/mergeready audit leaves on a PR
	// merged before it was green.
	auditMarker = "<!-- merge-audit -->"
	// qaHeader starts the comment post-merge-qa.yml leaves on a merged PR.
	qaHeader = "<!-- post-merge-qa -->"
)

// redMainTitles are the issues test.yml and nightly-e2e.yml open when main
// goes red and close on the next green run, so each one is one incident.
var redMainTitles = []string{"Test & Coverage is red on main", "Nightly e2e is red"}

// weekStart is the Monday 00:00 UTC that starts the week of t.
func weekStart(t time.Time) time.Time {
	t = t.UTC()
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	return day.AddDate(0, 0, -((int(day.Weekday()) + 6) % 7))
}

// sample is n PRs evenly spaced by number, or all of them when n is 0 or
// covers them.
func sample(prs []pull, n int) []pull {
	sorted := slices.Clone(prs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Number < sorted[j].Number })
	if n <= 0 || n >= len(sorted) {
		return sorted
	}
	out := make([]pull, 0, n)
	for i := range n {
		out = append(out, sorted[i*len(sorted)/n])
	}
	return out
}

// phases names each run of pr by "<workflow> (PR)" or "<workflow> (main)",
// keyed by its check suite: pull_request runs on its branch between opening
// and merge, and push runs on branch at its merge commit. Any other event is
// left out, which leaves out Dependabot's own runs (event "dynamic").
func phases(pr pull, runs []workflowRun, branch string) map[int64]string {
	out := map[int64]string{}
	for _, r := range runs {
		switch {
		case r.Event == "pull_request" && r.HeadBranch == pr.Head.Ref && inOpenLife(pr, r.CreatedAt):
			out[r.CheckSuiteID] = r.Name + " (PR)"
		case r.Event == "push" && r.HeadBranch == branch && r.HeadSHA == pr.MergeCommitSHA:
			out[r.CheckSuiteID] = r.Name + " (main)"
		}
	}
	return out
}

func inOpenLife(pr pull, t time.Time) bool {
	return pr.MergedAt != nil && !t.Before(pr.CreatedAt) && !t.After(*pr.MergedAt)
}

// commitsToCost are the commits whose check runs hold pr's jobs: the heads
// of its PR-phase runs and its merge commit.
func commitsToCost(pr pull, runs []workflowRun) []string {
	seen := map[string]bool{pr.MergeCommitSHA: true}
	for _, r := range runs {
		if r.Event == "pull_request" && r.HeadBranch == pr.Head.Ref && inOpenLife(pr, r.CreatedAt) {
			seen[r.HeadSHA] = true
		}
	}
	out := make([]string, 0, len(seen))
	for sha := range seen {
		out = append(out, sha)
	}
	sort.Strings(out)
	return out
}

// ciSeconds sums the job time of pr per phase. A job is a check run that
// GitHub Actions ran (its details URL is a job page), mapped to its run by
// check suite; a check run an action creates through the API is not a job.
func ciSeconds(pr pull, runs []workflowRun, checks []checkRun, branch string) map[string]float64 {
	names := phases(pr, runs, branch)
	out := map[string]float64{}
	seen := map[int64]bool{}
	for _, c := range checks {
		name, ok := names[c.CheckSuite.ID]
		if !ok || seen[c.ID] || c.StartedAt == nil || c.CompletedAt == nil || !strings.Contains(c.DetailsURL, "/job/") {
			continue
		}
		seen[c.ID] = true
		// A skipped job can end a second "before" it started.
		out[name] += math.Max(0, c.CompletedAt.Sub(*c.StartedAt).Seconds())
	}
	return out
}

var (
	revertQuoted       = regexp.MustCompile(`^Revert "(.*)"`)
	revertConventional = regexp.MustCompile(`^revert(?:\([^)]*\))?!?: (.+)$`)
	revertsSHA         = regexp.MustCompile(`This reverts commit ([0-9a-f]{7,40})`)
	revertsPR          = regexp.MustCompile(`Reverts [\w.-]+/[\w.-]+#(\d+)`)
	trailingPRRef      = regexp.MustCompile(`\s*\(#(\d+)\)\s*$`)
	conventionalType   = regexp.MustCompile(`^[a-z]+(?:\([^)]*\))?!?: `)
)

// reverts maps each merged PR later reverted on main to when it was first
// reverted. A revert is a `Revert "<title>"` commit (by its "(#N)" or by
// the title), its Conventional Commits form `revert: <description>`, a
// "This reverts commit <sha>" body, or a merged PR whose body says
// "Reverts owner/repo#N".
func reverts(prs []pull, commits []commit) map[int]time.Time {
	r := reverter{prs: prs, found: map[int]time.Time{}, byNumber: map[int]*pull{}}
	for i := range prs {
		r.byNumber[prs[i].Number] = &prs[i]
	}
	for _, c := range commits {
		r.commit(c)
	}
	for i := range prs {
		p := &prs[i]
		for _, m := range revertsPR.FindAllStringSubmatch(p.Body, -1) {
			if target := r.number(m[1]); target != nil && p.MergedAt != nil {
				r.hit(target, *p.MergedAt)
			}
		}
	}
	return r.found
}

type reverter struct {
	prs      []pull
	byNumber map[int]*pull
	found    map[int]time.Time
}

func (r reverter) number(digits string) *pull {
	n, err := strconv.Atoi(digits)
	if err != nil {
		return nil
	}
	return r.byNumber[n]
}

func (r reverter) commit(c commit) {
	at := c.Commit.Committer.Date
	subject, _, _ := strings.Cut(c.Commit.Message, "\n")
	if m := revertQuoted.FindStringSubmatch(subject); m != nil {
		r.byReference(m[1], at)
	} else if m := revertConventional.FindStringSubmatch(subject); m != nil {
		// Squash-merging the revert PR appends its own number: drop it.
		r.byReference(trailingPRRef.ReplaceAllString(m[1], ""), at)
	}
	for _, m := range revertsSHA.FindAllStringSubmatch(c.Commit.Message, -1) {
		for i := range r.prs {
			if sha := r.prs[i].MergeCommitSHA; sha != "" && strings.HasPrefix(sha, m[1]) {
				r.hit(&r.prs[i], at)
			}
		}
	}
}

// byReference resolves what a revert subject names: "<title> (#N)" is PR N,
// anything else is the latest PR merged before at with that title, or with
// that description after its Conventional Commits type.
func (r reverter) byReference(ref string, at time.Time) {
	if m := trailingPRRef.FindStringSubmatch(ref); m != nil {
		if p := r.number(m[1]); p != nil {
			r.hit(p, at)
		}
		return
	}
	var best *pull
	for i := range r.prs {
		p := &r.prs[i]
		named := p.Title == ref || conventionalType.ReplaceAllString(p.Title, "") == ref
		if named && p.MergedAt != nil && p.MergedAt.Before(at) && (best == nil || p.MergedAt.After(*best.MergedAt)) {
			best = p
		}
	}
	if best != nil {
		r.hit(best, at)
	}
}

func (r reverter) hit(p *pull, at time.Time) {
	if p.MergedAt == nil || !at.After(*p.MergedAt) {
		return
	}
	if prev, ok := r.found[p.Number]; !ok || at.Before(prev) {
		r.found[p.Number] = at
	}
}

// qaMarker is the usage post-merge-qa.yml hides in its comment: turns,
// tokens and Claude Code's own cost_usd estimate, with the run id.
var qaMarker = regexp.MustCompile(`<!-- post-merge-qa-usage (\{.*?\}) -->`)

type qaUsage struct {
	CostUSD *float64 `json:"cost_usd"`
	Turns   int      `json:"turns"`
	Run     int64    `json:"run"`
	Tokens  struct {
		Input         int `json:"input_tokens"`
		Output        int `json:"output_tokens"`
		CacheRead     int `json:"cache_read_input_tokens"`
		CacheCreation int `json:"cache_creation_input_tokens"`
	} `json:"tokens"`
}

// qaPR is the post-merge QA of one PR.
type qaPR struct {
	Comments int     // QA comments on the PR
	Runs     int     // distinct QA runs with a usage marker
	Turns    int     // summed over Runs
	Tokens   int     // summed over Runs
	USD      float64 // Claude Code's estimate, summed over the priced runs
	Unpriced int     // runs with a marker but no estimate
}

// qaByPR reads post-merge-qa.yml's own comments (the bot's, starting with its
// header; no one else's marker counts). A comment without a usage marker is
// a QA run with no data, and a marker without a positive cost_usd is
// unpriced: neither is ever $0.
func qaByPR(comments []comment) map[int]qaPR {
	out := map[int]qaPR{}
	seen := map[string]bool{}
	for _, c := range comments {
		if c.User.Login != botLogin || !strings.HasPrefix(c.Body, qaHeader) {
			continue
		}
		n := issueNumber(c.IssueURL)
		if n == 0 {
			continue
		}
		q := out[n]
		q.Comments++
		for _, m := range qaMarker.FindAllStringSubmatch(c.Body, -1) {
			var u qaUsage
			if json.Unmarshal([]byte(m[1]), &u) != nil {
				continue
			}
			// A re-run of the report job repeats its run's marker: count it once.
			key := strconv.Itoa(n) + "/" + strconv.FormatInt(u.Run, 10)
			if u.Run == 0 {
				key += "/" + m[1]
			}
			if !seen[key] {
				seen[key] = true
				q.add(&u)
			}
		}
		out[n] = q
	}
	return out
}

func (q *qaPR) add(u *qaUsage) {
	q.Runs++
	q.Turns += u.Turns
	q.Tokens += u.Tokens.Input + u.Tokens.Output + u.Tokens.CacheRead + u.Tokens.CacheCreation
	if u.CostUSD == nil || *u.CostUSD <= 0 {
		q.Unpriced++
	} else {
		q.USD += *u.CostUSD
	}
}

func issueNumber(url string) int {
	n, err := strconv.Atoi(url[strings.LastIndex(url, "/")+1:])
	if err != nil {
		return 0
	}
	return n
}

// audits are the merge-audit comments: one per PR merged before it was green.
func audits(comments []comment) []comment {
	var out []comment
	for _, c := range comments {
		if c.User.Login == botLogin && strings.HasPrefix(c.Body, auditMarker) {
			out = append(out, c)
		}
	}
	return out
}

// redMain keeps the red-on-main incident issues.
func redMain(issues []issue) []issue {
	var out []issue
	for _, i := range issues {
		if slices.Contains(redMainTitles, i.Title) {
			out = append(out, i)
		}
	}
	return out
}
