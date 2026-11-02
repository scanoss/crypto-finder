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
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func at(t *testing.T, stamp string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func load[T any](t *testing.T, rel string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatal(err)
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return v
}

func merged(t *testing.T, number int, title, mergedAt string) pull {
	t.Helper()
	m := at(t, mergedAt)
	p := pull{Number: number, Title: title, MergedAt: &m, CreatedAt: m.Add(-time.Hour), UpdatedAt: m}
	p.MergeCommitSHA = strings.Repeat(string(rune('a'+number%6)), 40)
	return p
}

func TestWeekStart(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2026-11-02T00:00:00Z", "2026-11-02"}, // Monday midnight starts its own week
		{"2026-11-04T15:00:00Z", "2026-11-02"}, // midweek
		{"2026-11-08T23:59:59Z", "2026-11-02"}, // Sunday's last second
		{"2026-11-09T00:00:00Z", "2026-11-09"},
		{"2026-11-02T00:30:00+02:00", "2026-10-26"}, // Sunday 22:30 in UTC
		{"2026-01-01T12:00:00Z", "2025-12-29"},      // across a year
	}
	for _, c := range cases {
		if got := weekStart(at(t, c.in)).Format(time.DateOnly); got != c.want {
			t.Errorf("weekStart(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}

// The rows are Monday to Monday UTC, the last one partial, and a merge falls
// in the week of its UTC time.
func TestWeeklyBuckets(t *testing.T) {
	prs := []pull{
		merged(t, 1, "a", "2026-10-26T00:00:00Z"),      // first second of week 1
		merged(t, 2, "b", "2026-11-01T23:59:59Z"),      // last second of week 1
		merged(t, 3, "c", "2026-11-02T01:30:00+02:00"), // Sunday in UTC: week 1
		merged(t, 4, "d", "2026-11-02T00:00:00Z"),      // week 2, the partial one
		merged(t, 5, "e", "2026-10-25T23:59:59Z"),      // before the start
	}
	rows := weekly(inputs{prs: prs}, at(t, "2026-10-26T00:00:00Z"), 2)
	if len(rows) != 2 || rows[0].Week != "2026-10-26" || rows[1].Week != "2026-11-02" {
		t.Fatalf("weeks = %+v", rows)
	}
	if rows[0].Merged != 3 || rows[1].Merged != 1 {
		t.Errorf("merged = %d, %d, want 3, 1", rows[0].Merged, rows[1].Merged)
	}
	if rows[0].CIMinutesPerPR != nil || rows[0].Costed != 0 {
		t.Errorf("no PR was costed, got %v (%d)", rows[0].CIMinutesPerPR, rows[0].Costed)
	}
}

func TestSample(t *testing.T) {
	prs := make([]pull, 0, 10)
	for _, n := range []int{17, 11, 12, 13, 14, 15, 16, 10, 18, 19} {
		prs = append(prs, pull{Number: n})
	}
	numbers := func(ps []pull) []int {
		out := make([]int, 0, len(ps))
		for _, p := range ps {
			out = append(out, p.Number)
		}
		return out
	}
	cases := []struct {
		n    int
		want []int
	}{
		{3, []int{10, 13, 16}},
		{5, []int{10, 12, 14, 16, 18}},
		{0, []int{10, 11, 12, 13, 14, 15, 16, 17, 18, 19}},
		{15, []int{10, 11, 12, 13, 14, 15, 16, 17, 18, 19}},
	}
	for _, c := range cases {
		if got := numbers(sample(prs, c.n)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("sample(%d) = %v, want %v", c.n, got, c.want)
		}
	}
}

// PR #819 as the API returned it: two pushes to its branch, then the merge.
func recordedPR819(t *testing.T) (pull, []workflowRun, []checkRun) {
	t.Helper()
	p := load[pull](t, "pr819/pull.json")
	runs := load[runsPage](t, "pr819/runs-pr.json").WorkflowRuns
	runs = append(runs, load[runsPage](t, "pr819/runs-main.json").WorkflowRuns...)
	checks := make([]checkRun, 0, 15)
	for _, sha := range []string{"af840bf52", "fdf6bc0e0", "907d32dfa"} {
		checks = append(checks, load[checksPage](t, "pr819/check-runs-"+sha+".json").CheckRuns...)
	}
	return p, runs, checks
}

func TestCISecondsRecorded(t *testing.T) {
	p, runs, checks := recordedPR819(t)
	want := map[string]float64{
		"Test & Coverage (PR)":   579 + 528, // test on each push; red-main skipped (ends before it starts)
		"Lint (PR)":              110 + 115,
		"SCANOSS (PR)":           39 + 40, // the action's "Policy Check" check run is not a job
		"Test & Coverage (main)": 465 + 5,
		"SCANOSS (main)":         46,
		"Merge audit (main)":     20,
	}
	if got := ciSeconds(p, runs, checks, "main"); !maps.Equal(got, want) {
		t.Errorf("ciSeconds = %v, want %v", got, want)
	}
	shas := commitsToCost(p, runs)
	wantSHAs := []string{"907d32dfa0ce1596b8230bd7a8fe788b64457380", "af840bf5277073ae504c5c76b765b3562a9b8cec", "fdf6bc0e0ac9d58585606c5169ac60782ab0438f"}
	if !reflect.DeepEqual(shas, wantSHAs) {
		t.Errorf("commitsToCost = %v, want %v", shas, wantSHAs)
	}
}

// Only the PR's own pull_request runs in its open life and the push runs on
// its merge commit count; everything else on the same commits does not.
func TestCISecondsPhases(t *testing.T) {
	p, runs, checks := recordedPR819(t)
	stray := func(id, suite int64, name, event, branch, sha, created string) {
		runs = append(runs, workflowRun{ID: id, Name: name, Event: event, HeadBranch: branch, HeadSHA: sha, CreatedAt: at(t, created), CheckSuiteID: suite})
		s, e := at(t, created), at(t, created).Add(10*time.Minute)
		c := checkRun{ID: id, Name: "job", StartedAt: &s, CompletedAt: &e, DetailsURL: "https://github.com/o/r/actions/runs/1/job/2"}
		c.CheckSuite.ID = suite
		checks = append(checks, c)
	}
	stray(1, 901, "Dependabot Updates", "dynamic", "main", p.MergeCommitSHA, "2026-11-02T14:45:00Z")
	stray(2, 902, "Nightly e2e", "schedule", "main", p.MergeCommitSHA, "2026-11-03T02:00:00Z")
	stray(3, 903, "Lint", "pull_request", p.Head.Ref, "f00", "2026-11-03T09:00:00Z")     // after the merge
	stray(4, 904, "Lint", "pull_request", "someone-else", "f01", "2026-11-02T14:30:00Z") // another branch
	stray(5, 905, "Post-merge QA", "push", "main", p.MergeCommitSHA, "2026-11-02T14:44:05Z")
	got := ciSeconds(p, runs, checks, "main")
	if got["Post-merge QA (main)"] != 600 {
		t.Errorf("Post-merge QA (main) = %v, want 600", got["Post-merge QA (main)"])
	}
	if got["Lint (PR)"] != 225 || len(got) != 7 {
		t.Errorf("strays counted: %v", got)
	}
	for _, sha := range commitsToCost(p, runs) {
		if sha == "f00" || sha == "f01" {
			t.Errorf("commitsToCost includes %s", sha)
		}
	}
}

func revertCommit(t *testing.T, message, when string) commit {
	t.Helper()
	var c commit
	c.Commit.Message = message
	c.Commit.Committer.Date = at(t, when)
	return c
}

func TestReverts(t *testing.T) {
	base := func() []pull {
		return []pull{
			merged(t, 10, "feat(scan): add the thing", "2026-10-01T10:00:00Z"),
			merged(t, 11, "fix: same title", "2026-10-02T10:00:00Z"),
			merged(t, 12, "fix: same title", "2026-10-05T10:00:00Z"),
			merged(t, 13, "docs: unrelated", "2026-10-06T10:00:00Z"),
		}
	}
	cases := []struct {
		name    string
		commits []commit
		pr      *pull // a revert PR, merged
		want    map[int]string
	}{
		{
			"quoted with its number",
			[]commit{revertCommit(t, "Revert \"feat(scan): add the thing (#10)\" (#20)", "2026-10-03T10:00:00Z")},
			nil,
			map[int]string{10: "2026-10-03T10:00:00Z"},
		},
		{
			"quoted by title, latest merged before it",
			[]commit{revertCommit(t, "Revert \"fix: same title\"\n\nbody", "2026-10-06T10:00:00Z")},
			nil,
			map[int]string{12: "2026-10-06T10:00:00Z"},
		},
		{
			"quoted by title before the second merge",
			[]commit{revertCommit(t, "Revert \"fix: same title\"", "2026-10-04T10:00:00Z")},
			nil,
			map[int]string{11: "2026-10-04T10:00:00Z"},
		},
		{
			"conventional by description, squashed",
			[]commit{revertCommit(t, "revert: add the thing (#21)", "2026-10-03T10:00:00Z")},
			nil,
			map[int]string{10: "2026-10-03T10:00:00Z"},
		},
		{
			"conventional naming the PR",
			[]commit{revertCommit(t, "revert(scan): feat(scan): add the thing (#10) (#21)", "2026-10-03T10:00:00Z")},
			nil,
			map[int]string{10: "2026-10-03T10:00:00Z"},
		},
		{
			"this reverts commit",
			[]commit{revertCommit(t, "chore: back out\n\nThis reverts commit "+strings.Repeat("b", 12)+".", "2026-10-07T10:00:00Z")},
			nil,
			map[int]string{13: "2026-10-07T10:00:00Z"},
		},
		{"revert PR body", nil, ptr(func() pull {
			p := merged(t, 30, "chore: undo", "2026-10-08T10:00:00Z")
			p.Body = "Reverts scanoss/crypto-finder#12\n\nIt broke main."
			return p
		}()), map[int]string{12: "2026-10-08T10:00:00Z"}},
		{"earliest of two", []commit{
			revertCommit(t, "Revert \"feat(scan): add the thing (#10)\"", "2026-10-09T10:00:00Z"),
			revertCommit(t, "Revert \"feat(scan): add the thing (#10)\"", "2026-10-03T10:00:00Z"),
		}, nil, map[int]string{10: "2026-10-03T10:00:00Z"}},
		{"not after the merge", []commit{revertCommit(t, "Revert \"docs: unrelated (#13)\"", "2026-10-06T09:00:00Z")}, nil, map[int]string{}},
		{"not a revert", []commit{
			revertCommit(t, "fix: Revert \"x\" handling (#10)", "2026-10-03T10:00:00Z"),
			revertCommit(t, "feat: revertible config", "2026-10-03T10:00:00Z"),
			revertCommit(t, "Revert \"a PR outside the window (#5)\"", "2026-10-03T10:00:00Z"),
		}, nil, map[int]string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prs := base()
			if c.pr != nil {
				prs = append(prs, *c.pr)
			}
			got := map[int]string{}
			for n, when := range reverts(prs, c.commits) {
				got[n] = when.UTC().Format(time.RFC3339)
			}
			if !maps.Equal(got, c.want) {
				t.Errorf("reverts = %v, want %v", got, c.want)
			}
		})
	}
}

func TestWeeklyRevertRate(t *testing.T) {
	prs := []pull{
		merged(t, 1, "a", "2026-10-26T10:00:00Z"),
		merged(t, 2, "b", "2026-10-27T10:00:00Z"),
		merged(t, 3, "c", "2026-10-28T10:00:00Z"),
		merged(t, 4, "d", "2026-10-29T10:00:00Z"),
	}
	reverted := map[int]time.Time{2: at(t, "2026-10-27T13:00:00Z"), 4: at(t, "2026-11-03T10:00:00Z")}
	rows := weekly(inputs{prs: prs, reverted: reverted}, at(t, "2026-10-26T00:00:00Z"), 2)
	w := rows[0]
	if !reflect.DeepEqual(w.Reverted, []int{2, 4}) || *w.RevertRate != 0.5 || *w.MedianHoursToRevert != 61.5 {
		t.Errorf("week = %v %v %v", w.Reverted, *w.RevertRate, *w.MedianHoursToRevert)
	}
	if rows[1].RevertRate != nil || rows[1].MedianHoursToRevert != nil {
		t.Errorf("a week with no merges has no revert rate, got %v", rows[1].RevertRate)
	}
}

func qaComment(t *testing.T, login string, pr int, body string) comment {
	t.Helper()
	c := comment{Body: body, CreatedAt: at(t, "2026-11-02T15:00:00Z"), IssueURL: "https://api.github.com/repos/o/r/issues/" + strconv.Itoa(pr)}
	c.User.Login = login
	return c
}

func TestQAByPRRecorded(t *testing.T) {
	got := qaByPR(load[[]comment](t, "pr819/comments.json"))
	want := qaPR{Comments: 1, Runs: 1, Turns: 15, Tokens: 24 + 4523 + 363072 + 29581, USD: 0.01181082}
	if got[819] != want {
		t.Errorf("qaByPR = %+v, want %+v", got[819], want)
	}
}

func TestQAByPR(t *testing.T) {
	usage := func(cost string, run int) string {
		return `<!-- post-merge-qa-usage {"cost_usd":` + cost + `,"tokens":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":0,"cache_creation_input_tokens":0},"turns":3,"run":` + strconv.Itoa(run) + `} -->`
	}
	comments := []comment{
		qaComment(t, botLogin, 1, qaHeader+"\nAgent: 3 turns. "+usage("0.5", 100)),
		qaComment(t, botLogin, 1, qaHeader+"\nre-run of the report job. "+usage("0.5", 100)), // same run: once
		qaComment(t, botLogin, 2, qaHeader+"\nno agent usage"),                               // no data
		qaComment(t, botLogin, 3, qaHeader+"\n"+usage("null", 101)),                          // unpriced
		qaComment(t, botLogin, 4, qaHeader+"\n"+usage("0", 102)),                             // unpriced, not $0
		qaComment(t, "someone", 5, qaHeader+"\n"+usage("9", 103)),                            // not the bot
		qaComment(t, botLogin, 6, "quoting "+qaHeader+" "+usage("9", 104)),                   // not the QA comment
		qaComment(t, botLogin, 7, qaHeader+"\n<!-- post-merge-qa-usage {broken} -->"),        // unparseable: no data
	}
	got := qaByPR(comments)
	want := map[int]qaPR{
		1: {Comments: 2, Runs: 1, Turns: 3, Tokens: 15, USD: 0.5},
		2: {Comments: 1},
		3: {Comments: 1, Runs: 1, Turns: 3, Tokens: 15, Unpriced: 1},
		4: {Comments: 1, Runs: 1, Turns: 3, Tokens: 15, Unpriced: 1},
		7: {Comments: 1},
	}
	if !maps.Equal(got, want) {
		t.Errorf("qaByPR = %+v\nwant %+v", got, want)
	}
}

// A week whose QA has no usage, or no estimate, never reads as $0.
func TestWeeklyQANeverZero(t *testing.T) {
	prs := []pull{
		merged(t, 1, "a", "2026-10-26T10:00:00Z"), // no QA at all
		merged(t, 2, "b", "2026-10-27T10:00:00Z"), // QA comment, no usage
		merged(t, 3, "c", "2026-10-28T10:00:00Z"), // usage, unpriced
		merged(t, 4, "d", "2026-11-02T10:00:00Z"), // priced
		merged(t, 5, "e", "2026-11-03T10:00:00Z"), // unpriced
	}
	qa := map[int]qaPR{
		2: {Comments: 1},
		3: {Comments: 1, Runs: 1, Turns: 10, Tokens: 1000, Unpriced: 1},
		4: {Comments: 1, Runs: 1, Turns: 20, Tokens: 3_000_000, USD: 0.25},
		5: {Comments: 1, Runs: 1, Turns: 30, Tokens: 1000, Unpriced: 1},
	}
	rows := weekly(inputs{prs: prs, qa: qa}, at(t, "2026-10-26T00:00:00Z"), 3)
	w := rows[0]
	if w.QAPRs != 2 || w.QANoData != 1 || w.QAUnpriced != 1 || w.QAEstimatedUSDPerPR != nil || *w.QATurnsPerPR != 10 {
		t.Errorf("week 1 = %+v", w)
	}
	if got := *rows[1].QAEstimatedUSDPerPR; got != 0.25 { // over the priced PR only
		t.Errorf("week 2 estimate = %v, want 0.25", got)
	}
	if *rows[1].QATurnsPerPR != 25 {
		t.Errorf("week 2 turns = %v, want 25", *rows[1].QATurnsPerPR)
	}
	out := markdown(report{Weeks: 1, Sample: 8, Reserve: 300, Rows: []week{rows[2], rows[0]}})
	if strings.Contains(out, "$0.000") || !strings.Contains(out, "| 2 (1) | 10.0 | 1k | unpriced |") {
		t.Errorf("markdown week 1:\n%s", out)
	}
	if !strings.Contains(out, "| 0 (0) | no data | no data | no data |") {
		t.Errorf("markdown, a week with no QA:\n%s", out)
	}
	out = markdown(report{Weeks: 1, Sample: 8, Reserve: 300, Rows: []week{rows[0], rows[1]}})
	if !strings.Contains(out, "| 2 (0) | 25.0 | 1.5M | ~$0.250 (1 unpriced) |") {
		t.Errorf("markdown week 2:\n%s", out)
	}
}

func TestRedMainAndAudits(t *testing.T) {
	closed := at(t, "2026-10-27T16:00:00Z")
	issues := []issue{
		{Number: 1, Title: "Test & Coverage is red on main", CreatedAt: at(t, "2026-10-27T10:00:00Z"), ClosedAt: &closed},
		{Number: 2, Title: "Nightly e2e is red", CreatedAt: at(t, "2026-10-28T02:00:00Z")},
		{Number: 3, Title: "main is red: something by hand", CreatedAt: at(t, "2026-10-28T02:00:00Z")},
	}
	audit := qaComment(t, botLogin, 9, auditMarker+"\n**Merge audit:** this pull request merged before every check was green.")
	audit.CreatedAt = at(t, "2026-10-29T10:00:00Z")
	notAudit := qaComment(t, "someone", 9, auditMarker)
	rows := weekly(inputs{red: redMain(issues), audits: audits([]comment{audit, notAudit})}, at(t, "2026-10-26T00:00:00Z"), 1)
	if rows[0].RedMainIssues != 2 || *rows[0].MedianHoursRed != 6 || rows[0].MergedBeforeGreen != 1 {
		t.Errorf("week = %+v", rows[0])
	}
}
