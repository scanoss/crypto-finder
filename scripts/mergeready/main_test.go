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
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGH answers gh calls from recorded responses keyed by their arguments.
// A call with no recorded response fails, like an unreachable API.
type fakeGH struct {
	responses map[string]string
	calls     []string
}

func (f *fakeGH) run(_ context.Context, dir string, args ...string) ([]byte, error) {
	key := strings.Join(args, " ")
	if dir != "" {
		key = dir + ": " + key
	}
	f.calls = append(f.calls, key)
	body, ok := f.responses[key]
	if !ok {
		return nil, errors.New("no recorded response for " + key)
	}
	return []byte(body), nil
}

func fixture(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

const (
	repo = "o/r"
	head = "abc123"
	// Keys of the calls checkPR makes for repo#12 at head.
	keyView     = "pr view 12 -R o/r --json number,state,isDraft,mergeable,headRefOid"
	keyRuns     = "api --paginate repos/o/r/actions/runs?head_sha=abc123&per_page=100"
	keyChecks   = "api --paginate repos/o/r/commits/abc123/check-runs?filter=latest&per_page=100"
	keyStatus   = "api --paginate repos/o/r/commits/abc123/status?per_page=100"
	keyReviews  = "api --paginate repos/o/r/pulls/12/reviews?per_page=100"
	keyComments = "api --paginate repos/o/r/pulls/12/comments?per_page=100"
)

// readyPR is a pull request that passes every readiness check.
func readyPR() map[string]string {
	return map[string]string{
		keyView:     `{"number":12,"state":"OPEN","isDraft":false,"mergeable":"MERGEABLE","headRefOid":"abc123"}`,
		keyRuns:     `{"total_count":1,"workflow_runs":[{"name":"Lint","status":"completed","conclusion":"success"}]}`,
		keyChecks:   `{"total_count":1,"check_runs":[{"name":"build","status":"completed","conclusion":"success"}]}`,
		keyStatus:   `{"state":"pending","total_count":0,"statuses":[]}`,
		keyReviews:  `[]`,
		keyComments: `[]`,
	}
}

func TestCheckPR(t *testing.T) {
	tests := []struct {
		name string
		key  string
		body string // "" removes the response: the call fails
		want string // "" means ready
	}{
		{"ready", "", "", ""},

		{"closed", keyView, `{"number":12,"state":"CLOSED","mergeable":"MERGEABLE","headRefOid":"abc123"}`, "not open (state CLOSED)"},
		{"draft", keyView, `{"number":12,"state":"OPEN","isDraft":true,"mergeable":"MERGEABLE","headRefOid":"abc123"}`, "is a draft"},
		{"pr unreadable", keyView, "", "cannot read the pull request"},
		{"pr unparseable", keyView, `not json`, "cannot read the pull request: unparseable"},
		{"pr wrong number", keyView, `{"number":13,"state":"OPEN","mergeable":"MERGEABLE","headRefOid":"abc123"}`, "unexpected response"},

		{"conflict", keyView, `{"number":12,"state":"OPEN","mergeable":"CONFLICTING","headRefOid":"abc123"}`, "merge conflict"},
		{"mergeability unknown", keyView, `{"number":12,"state":"OPEN","mergeable":"UNKNOWN","headRefOid":"abc123"}`, "still computing mergeability, retry"},

		{"workflow running", keyRuns, `{"workflow_runs":[{"name":"Lint","status":"in_progress"}]}`, `workflow "Lint" has not finished`},
		{"workflow queued on a later page", keyRuns, `{"workflow_runs":[{"name":"A","status":"completed"}]}{"workflow_runs":[{"name":"B","status":"queued"}]}`, `workflow "B" has not finished`},
		{"workflow runs unreadable", keyRuns, "", "cannot read the workflow runs"},
		{"workflow runs missing key", keyRuns, `{"message":"Not Found"}`, "no workflow_runs"},
		{"no workflow runs", keyRuns, `{"workflow_runs":[]}`, ""},

		{"no check runs", keyChecks, `{"check_runs":[]}`, "no check runs"},
		{"check running", keyChecks, `{"check_runs":[{"name":"test","status":"in_progress"}]}`, `check "test" has not finished`},
		{"check failed", keyChecks, `{"check_runs":[{"name":"test","status":"completed","conclusion":"failure"}]}`, `check "test" finished with failure`},
		{"check timed out", keyChecks, `{"check_runs":[{"name":"test","status":"completed","conclusion":"timed_out"}]}`, "finished with timed_out"},
		{"check needs action", keyChecks, `{"check_runs":[{"name":"test","status":"completed","conclusion":"action_required"}]}`, "finished with action_required"},
		{"check neutral and skipped", keyChecks, `{"check_runs":[{"name":"a","status":"completed","conclusion":"neutral"},{"name":"b","status":"completed","conclusion":"skipped"}]}`, ""},
		{"check failed on a later page", keyChecks, `{"check_runs":[{"name":"a","status":"completed","conclusion":"success"}]}{"check_runs":[{"name":"b","status":"completed","conclusion":"failure"}]}`, `check "b" finished with failure`},
		{"check runs unreadable", keyChecks, "", "cannot read the check runs"},
		{"check runs unparseable", keyChecks, `{"check_runs":[`, "cannot read the check runs: unparseable"},
		{"check runs empty output", keyChecks, ` `, "empty response"},

		{"status pending", keyStatus, `{"statuses":[{"context":"ci/x","state":"pending"}]}`, `status "ci/x" has not finished`},
		{"status failed", keyStatus, `{"statuses":[{"context":"ci/x","state":"failure"}]}`, `status "ci/x" finished with failure`},
		{"status success", keyStatus, `{"statuses":[{"context":"ci/x","state":"success"}]}`, ""},
		{"statuses unreadable", keyStatus, "", "cannot read the commit statuses"},

		{"changes requested", keyReviews, `[{"user":{"login":"amy"},"state":"CHANGES_REQUESTED"}]`, "amy requested changes"},
		{"changes requested then a comment", keyReviews, `[{"user":{"login":"amy"},"state":"CHANGES_REQUESTED"},{"user":{"login":"amy"},"state":"COMMENTED"}]`, "amy requested changes"},
		{"changes requested then approved", keyReviews, `[{"user":{"login":"amy"},"state":"CHANGES_REQUESTED"},{"user":{"login":"amy"},"state":"APPROVED"}]`, ""},
		{"changes requested then dismissed", keyReviews, `[{"user":{"login":"amy"},"state":"DISMISSED"}]`, ""},
		{"another reviewer approved", keyReviews, `[{"user":{"login":"amy"},"state":"CHANGES_REQUESTED"},{"user":{"login":"bob"},"state":"APPROVED"}]`, "amy requested changes"},
		{"reviews unreadable", keyReviews, "", "cannot read the reviews"},

		{"bot comment without reply", keyComments, `[{"id":1,"user":{"login":"claude[bot]"},"path":"a.go","line":3}]`, "by claude[bot] on a.go:3 has no reply"},
		{"bot comment with reply", keyComments, `[{"id":1,"user":{"login":"claude[bot]"}},{"id":2,"in_reply_to_id":1,"user":{"login":"amy"}}]`, ""},
		{"bot comment answered by the bot", keyComments, `[{"id":1,"user":{"login":"claude[bot]"}},{"id":2,"in_reply_to_id":1,"user":{"login":"claude[bot]"},"path":"a.go","line":4}]`, "a.go:4 has no reply"},
		{"bot reply in a human thread", keyComments, `[{"id":1,"user":{"login":"amy"}},{"id":2,"in_reply_to_id":1,"user":{"login":"claude[bot]"},"path":"b.go","line":5}]`, "b.go:5 has no reply"},
		{"reply to another thread", keyComments, `[{"id":1,"user":{"login":"claude[bot]"},"path":"a.go","line":3},{"id":5,"user":{"login":"amy"}},{"id":6,"in_reply_to_id":5,"user":{"login":"amy"}}]`, "a.go:3 has no reply"},
		{"human comment without reply", keyComments, `[{"id":1,"user":{"login":"amy"}}]`, ""},
		{"comments unreadable", keyComments, "", "cannot read the review comments"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			responses := readyPR()
			if tc.key != "" {
				if tc.body == "" {
					delete(responses, tc.key)
				} else {
					responses[tc.key] = tc.body
				}
			}
			reasons := checkPR(context.Background(), client{gh: &fakeGH{responses: responses}, repo: repo}, 12)
			if tc.want == "" {
				if len(reasons) != 0 {
					t.Fatalf("want ready, got %q", reasons)
				}
				return
			}
			if len(reasons) != 1 || !strings.Contains(reasons[0], tc.want) {
				t.Fatalf("want one reason containing %q, got %q", tc.want, reasons)
			}
		})
	}
}

// recordedPR803 is scanoss/crypto-finder#803 as recorded just after it merged.
func recordedPR803(t *testing.T) map[string]string {
	const sha = "18a6545eb3bce9f5ee30826fb886457d27e14e92"
	const base = "api --paginate repos/scanoss/crypto-finder/"
	return map[string]string{
		"pr view 803 -R scanoss/crypto-finder --json number,state,isDraft,mergeable,headRefOid": fixture(t, "pr803/pr.json"),
		base + "actions/runs?head_sha=" + sha + "&per_page=100":                                 fixture(t, "pr803/runs.json"),
		base + "commits/" + sha + "/check-runs?filter=latest&per_page=100":                      fixture(t, "pr803/check-runs.json"),
		base + "commits/" + sha + "/status?per_page=100":                                        fixture(t, "pr803/status.json"),
		base + "pulls/803/reviews?per_page=100":                                                 fixture(t, "pr803/reviews.json"),
		base + "pulls/803/comments?per_page=100":                                                fixture(t, "pr803/comments.json"),
	}
}

func TestCheckPRRecorded(t *testing.T) {
	responses := recordedPR803(t)
	c := client{gh: &fakeGH{responses: responses}, repo: "scanoss/crypto-finder"}
	reasons := checkPR(context.Background(), c, 803)
	want := []string{"the pull request is not open (state MERGED)"}
	if strings.Join(reasons, "\n") != strings.Join(want, "\n") {
		t.Fatalf("merged #803: got %q, want %q", reasons, want)
	}

	// The same recorded checks on an open, mergeable pull request are ready.
	responses["pr view 803 -R scanoss/crypto-finder --json number,state,isDraft,mergeable,headRefOid"] = `{"headRefOid":"18a6545eb3bce9f5ee30826fb886457d27e14e92","isDraft":false,"mergeable":"MERGEABLE","number":803,"state":"OPEN"}`
	if reasons := checkPR(context.Background(), c, 803); len(reasons) != 0 {
		t.Fatalf("open #803: want ready, got %q", reasons)
	}
}

func TestRunCheckExitCodes(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), []string{"check", "--pr", "12", "--repo", repo}, nil, &out, &out, &fakeGH{responses: readyPR()}); code != 0 {
		t.Fatalf("ready: exit %d, output %s", code, out.String())
	}
	out.Reset()
	responses := readyPR()
	responses[keyView] = `{"number":12,"state":"OPEN","isDraft":true,"mergeable":"CONFLICTING","headRefOid":"abc123"}`
	code := run(context.Background(), []string{"check", "--pr", "12", "--repo", repo}, nil, &out, &out, &fakeGH{responses: responses})
	if code != 1 || !strings.Contains(out.String(), "- the pull request is a draft\n- the pull request has a merge conflict") {
		t.Fatalf("not ready: exit %d, want 1 and every reason on its own line, output:\n%s", code, out.String())
	}
}

const (
	mergeSHA      = "m1"
	keyPulls      = "api --paginate repos/o/r/commits/m1/pulls?per_page=100"
	keyIssueNotes = "api --paginate repos/o/r/issues/12/comments?per_page=100"
	pulls12       = `[{"number":12,"merged_at":"2026-10-30T19:32:04Z","merge_commit_sha":"m1","head":{"sha":"abc123"}}]`
)

func TestAudit(t *testing.T) {
	tests := []struct {
		name      string
		responses map[string]string
		comment   bool
		want      string
		posted    bool
	}{
		{
			name: "green before merge",
			responses: map[string]string{
				keyPulls:  pulls12,
				keyChecks: `{"check_runs":[{"name":"test","status":"completed","conclusion":"success","completed_at":"2026-10-30T19:31:35Z"}]}`,
				keyStatus: `{"statuses":[{"context":"ci/x","state":"success","updated_at":"2026-10-30T19:00:00Z"}]}`,
			},
			comment: true,
			want:    "#12 merged with every check green",
		},
		{
			name: "check finished after the merge",
			responses: map[string]string{
				keyPulls:      pulls12,
				keyChecks:     `{"check_runs":[{"name":"test","status":"completed","conclusion":"success","completed_at":"2026-10-30T19:40:00Z"}]}`,
				keyStatus:     `{"statuses":[]}`,
				keyIssueNotes: `[{"body":"lgtm"}]`,
			},
			comment: true,
			want:    `check "test" finished at 2026-10-30T19:40:00Z, after the merge at 2026-10-30T19:32:04Z`,
			posted:  true,
		},
		{
			name: "status finished after the merge, no comment asked",
			responses: map[string]string{
				keyPulls:  pulls12,
				keyChecks: `{"check_runs":[{"name":"test","status":"completed","conclusion":"success","completed_at":"2026-10-30T19:00:00Z"}]}`,
				keyStatus: `{"statuses":[{"context":"ci/x","state":"success","updated_at":"2026-10-30T19:33:00Z"}]}`,
			},
			want: `status "ci/x" finished at 2026-10-30T19:33:00Z, after the merge`,
		},
		{
			name: "red check, already commented",
			responses: map[string]string{
				keyPulls:      pulls12,
				keyChecks:     `{"check_runs":[{"name":"test","status":"completed","conclusion":"failure","completed_at":"2026-10-30T19:00:00Z"}]}`,
				keyStatus:     `{"statuses":[]}`,
				keyIssueNotes: `[{"body":"x"}][{"body":"<!-- merge-audit -->\nold"}]`,
			},
			comment: true,
			want:    "already commented on #12",
		},
		{
			name:      "no pull request merged as the commit",
			responses: map[string]string{keyPulls: `[{"number":9,"merged_at":"2026-10-30T19:32:04Z","merge_commit_sha":"other"}]`},
			comment:   true,
			want:      "no pull request was merged as this commit",
		},
		{
			name:      "pull requests unreadable",
			responses: map[string]string{},
			comment:   true,
			want:      "cannot find the pull request",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeGH{responses: tc.responses}
			var out bytes.Buffer
			code := run(context.Background(), append([]string{"audit", "--sha", mergeSHA, "--repo", repo}, commentFlag(tc.comment)...), nil, &out, &out, f)
			if code != 0 {
				t.Fatalf("audit exits 0 whatever it finds, got %d", code)
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("want output containing %q, got:\n%s", tc.want, out.String())
			}
			posted := false
			for _, call := range f.calls {
				if strings.HasPrefix(call, "api --method POST repos/o/r/issues/12/comments -f body=<!-- merge-audit -->") {
					posted = true
				}
			}
			if posted != tc.posted {
				t.Fatalf("posted a comment: %v, want %v; calls %q", posted, tc.posted, f.calls)
			}
		})
	}
}

func commentFlag(on bool) []string {
	if on {
		return []string{"--comment"}
	}
	return nil
}

// TestAuditRecorded judges the merge of scanoss/crypto-finder#800, whose
// last check finished 29 s before it merged.
func TestAuditRecorded(t *testing.T) {
	const sha = "5ee6d7b9f9d71afe6dfdc6cc1b0e5c204dbcd179"
	const pullHead = "0d9e78a28461e10140ab837744abe0fbdd3d380f"
	const base = "api --paginate repos/scanoss/crypto-finder/"
	responses := map[string]string{
		base + "commits/" + sha + "/pulls?per_page=100":                         fixture(t, "merge800/pulls.json"),
		base + "commits/" + pullHead + "/check-runs?filter=latest&per_page=100": fixture(t, "merge800/check-runs.json"),
		base + "commits/" + pullHead + "/status?per_page=100":                   fixture(t, "merge800/status.json"),
	}
	var out bytes.Buffer
	run(context.Background(), []string{"audit", "--sha", sha, "--repo", "scanoss/crypto-finder"}, nil, &out, &out, &fakeGH{responses: responses})
	if want := "#800 merged with every check green"; !strings.Contains(out.String(), want) {
		t.Fatalf("want %q, got:\n%s", want, out.String())
	}

	// Had it merged before the test check finished, the audit says so.
	early := maps.Clone(responses)
	early[base+"commits/"+sha+"/pulls?per_page=100"] = strings.Replace(
		fixture(t, "merge800/pulls.json"), `"merged_at":"2026-10-30T19:32:04Z"`, `"merged_at":"2026-10-30T19:20:00Z"`, 1)
	if early[base+"commits/"+sha+"/pulls?per_page=100"] == responses[base+"commits/"+sha+"/pulls?per_page=100"] {
		t.Fatal("fixture no longer holds the merged_at this test rewrites")
	}
	out.Reset()
	run(context.Background(), []string{"audit", "--sha", sha, "--repo", "scanoss/crypto-finder"}, nil, &out, &out, &fakeGH{responses: early})
	if want := `check "test" finished at 2026-10-30T19:31:35Z, after the merge at 2026-10-30T19:20:00Z`; !strings.Contains(out.String(), want) {
		t.Fatalf("want %q, got:\n%s", want, out.String())
	}
}
