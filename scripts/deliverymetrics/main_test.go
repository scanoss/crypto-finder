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
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeGH answers gh calls from recorded responses: the first route whose
// substring is in the call answers it, and rate_limit answers from rate in
// turn. A call no route answers fails, like an unreachable API.
type fakeGH struct {
	mu     sync.Mutex
	routes [][2]string
	rate   []int
	calls  []string
}

func (f *fakeGH) run(_ context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.Join(args, " ")
	f.calls = append(f.calls, key)
	if key == "api rate_limit" {
		if len(f.rate) == 0 {
			return nil, errors.New("no recorded rate limit")
		}
		left := f.rate[0]
		f.rate = f.rate[1:]
		return []byte(`{"resources":{"core":{"limit":1000,"remaining":` + strconv.Itoa(left) + `}}}`), nil
	}
	for _, r := range f.routes {
		if strings.Contains(key, r[0]) {
			return []byte(r[1]), nil
		}
	}
	return nil, errors.New("no recorded response for " + key)
}

func (f *fakeGH) called(sub string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func fixture(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// sunday is the last second of the week of 2026-10-26.
const sunday = "2026-11-01T23:59:59Z"

// repoFake is the repository o/r over the week of 2026-10-26 and the partial
// one of 2026-11-02: #819 as recorded, plus synthetic PRs around it.
func repoFake(t *testing.T, merged900 string, rate ...int) *fakeGH {
	t.Helper()
	pr819 := load[map[string]any](t, "pr819/pull.json")
	other := func(n int, mergedAt string) map[string]any {
		return map[string]any{
			"number": n, "title": "chore: pr " + strconv.Itoa(n), "body": "", "created_at": "2026-10-20T10:00:00Z",
			"updated_at": mergedAt, "merged_at": mergedAt, "merge_commit_sha": strings.Repeat("c", 40),
			"head": map[string]any{"ref": "branch-" + strconv.Itoa(n)},
		}
	}
	closedUnmerged := map[string]any{"number": 899, "title": "x", "updated_at": "2026-10-30T10:00:00Z", "merged_at": nil}
	pulls, err := json.Marshal([]any{pr819, other(900, merged900), closedUnmerged, other(901, "2026-10-25T10:00:00Z")})
	if err != nil {
		t.Fatal(err)
	}
	return &fakeGH{rate: rate, routes: [][2]string{
		{"pulls?state=closed&base=main&sort=updated&direction=desc&per_page=100&page=1", string(pulls)},
		{"repos/o/r/commits?sha=main&since=2026-10-26T00%3A00%3A00Z&per_page=100", `[]`},
		{"repos/o/r/issues/comments?since=2026-10-26T00%3A00%3A00Z&per_page=100", fixture(t, "pr819/comments.json")},
		{"search/issues?per_page=100&q=repo%3Ao%2Fr+is%3Aissue+in%3Atitle+%22is+red%22+created%3A%3E%3D2026-10-26", `{"items":[]}`},
		{"actions/runs?branch=fix%2Fscan-target-under-ignored-dir&event=pull_request", fixture(t, "pr819/runs-pr.json")},
		{"actions/runs?head_sha=907d32dfa0ce1596b8230bd7a8fe788b64457380&event=push", fixture(t, "pr819/runs-main.json")},
		{"commits/af840bf5277073ae504c5c76b765b3562a9b8cec/check-runs?filter=all", fixture(t, "pr819/check-runs-af840bf52.json")},
		{"commits/fdf6bc0e0ac9d58585606c5169ac60782ab0438f/check-runs?filter=all", fixture(t, "pr819/check-runs-fdf6bc0e0.json")},
		{"commits/907d32dfa0ce1596b8230bd7a8fe788b64457380/check-runs?filter=all", fixture(t, "pr819/check-runs-907d32dfa.json")},
		{"actions/runs?branch=branch-900", `{"workflow_runs":[]}`},
		{"head_sha=cccccccccccccccccccccccccccccccccccccccc", `{"workflow_runs":[]}`},
		{"commits/cccccccccccccccccccccccccccccccccccccccc/check-runs", `{"check_runs":[]}`},
	}}
}

func measureJSON(t *testing.T, g *fakeGH, args ...string) (report, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC) // a Wednesday
	args = append([]string{"--repo", "o/r", "--weeks", "1", "--workers", "1", "--json"}, args...)
	if code := run(context.Background(), args, now, &stdout, &stderr, g); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var r report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatalf("%v: %s", err, stdout.String())
	}
	return r, stderr.String()
}

func TestMeasureRecorded(t *testing.T) {
	r, _ := measureJSON(t, repoFake(t, sunday, 1000, 1000))
	if r.Start != "2026-10-26" || len(r.Rows) != 2 {
		t.Fatalf("start %s, %d rows", r.Start, len(r.Rows))
	}
	last, partial := r.Rows[0], r.Rows[1]
	if last.Merged != 1 || last.Costed != 1 || *last.CIMinutesPerPR != 0 { // #900, no runs
		t.Errorf("week of 2026-10-26 = %+v", last)
	}
	if partial.Merged != 1 || partial.Costed != 1 || *partial.CIMinutesPerPR != 32.5 {
		t.Errorf("week of 2026-11-02 = %+v", partial)
	}
	if partial.QAPRs != 1 || *partial.QATurnsPerPR != 15 || *partial.QAEstimatedUSDPerPR != 0.0118 {
		t.Errorf("QA of #819 = %+v", partial)
	}
	if got := partial.CIMinutesByWorkflow["Test & Coverage (PR)"]; got != 18.5 { // 1107 s
		t.Errorf("Test & Coverage (PR) = %v, want 18.5", got)
	}
}

// Costing stops while fewer than --reserve requests are left: the PR is left
// out with its reason and makes no call, and the report still comes out.
func TestMeasureReserve(t *testing.T) {
	g := repoFake(t, sunday, 1000, 299)
	r, stderr := measureJSON(t, g, "--reserve", "300")
	if len(r.NotCosted) != 1 || r.NotCosted[0].PR != 900 || r.NotCosted[0].Reason != "API reserve: 299 requests left" {
		t.Errorf("not costed = %+v", r.NotCosted)
	}
	if g.called("branch=branch-900") {
		t.Error("#900 was costed under the reserve")
	}
	if r.Rows[1].Costed != 1 || r.Rows[0].Costed != 0 || r.Rows[0].Merged != 1 {
		t.Errorf("rows = %+v", r.Rows)
	}
	if !strings.Contains(stderr, "#900 not costed: API reserve") {
		t.Errorf("stderr = %q", stderr)
	}
}

// An API error costs one PR, never the table.
func TestMeasureAPIError(t *testing.T) {
	g := repoFake(t, sunday, 1000, 1000)
	g.routes = g.routes[:len(g.routes)-1] // #900's merge commit check runs fail
	r, _ := measureJSON(t, g)
	if len(r.NotCosted) != 1 || r.NotCosted[0].PR != 900 || !strings.HasPrefix(r.NotCosted[0].Reason, "API error") {
		t.Errorf("not costed = %+v", r.NotCosted)
	}
	if r.Rows[1].Costed != 1 {
		t.Errorf("#819 not costed: %+v", r.Rows[1])
	}
}

// --sample 1 costs one of the two PRs merged in the same week, the lower
// number, and says so.
func TestMeasureSample(t *testing.T) {
	g := repoFake(t, "2026-11-03T10:00:00Z", 1000, 1000)
	r, _ := measureJSON(t, g, "--sample", "1", "--until", "2026-11-04")
	if r.Sample != 1 || r.Rows[1].Merged != 2 || r.Rows[1].Costed != 1 || *r.Rows[1].CIMinutesPerPR != 32.5 {
		t.Errorf("rows = %+v", r.Rows)
	}
	if g.called("branch=branch-900") {
		t.Error("#900 was costed outside the sample")
	}
}

func TestRunMarkdownAndUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	code := run(context.Background(), []string{"--repo", "o/r", "--weeks", "1", "--workers", "1"}, now, &stdout, &stderr, repoFake(t, sunday, 1000, 1000))
	if code != 0 || !strings.Contains(stdout.String(), "| 2026-11-02 | 1 | 32.5 (1) | 1 (0) | 15.0 | 397k | ~$0.012 |") {
		t.Errorf("exit %d, stdout:\n%s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	for _, args := range [][]string{{"--weeks", "0"}, {"--until", "11/04/2026"}, {"extra"}, {"--sample", "-1"}} {
		if code := run(context.Background(), append([]string{"--repo", "o/r"}, args...), now, &stdout, &stderr, &fakeGH{}); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code := run(context.Background(), []string{"--repo", "o/r"}, now, &stdout, &stderr, &fakeGH{}); code != 1 {
		t.Errorf("unreachable API: exit %d, want 1", code)
	}
}
