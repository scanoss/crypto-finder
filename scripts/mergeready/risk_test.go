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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPathFloor(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  riskLevel
		why   string // a substring of the first reason
	}{
		{"plain code", []string{"internal/scan/export.go", "changelog.d/x.fixed.md"}, riskLow, ""},
		{"knowledge base", []string{"internal/callgraph/contracts/go/stdlib-crypto.yaml"}, riskLow, ""},
		{"workflow", []string{".github/workflows/test.yml"}, riskHigh, "CI, release and tagging workflows (`.github/workflows/test.yml`)"},
		{"release workflow", []string{".github/workflows/release.yml"}, riskHigh, "CI, release and tagging workflows"},
		{"merge gate", []string{"scripts/mergeready/check.go"}, riskHigh, "the merge gate"},
		{"hook settings", []string{".claude/settings.json"}, riskHigh, "the merge gate"},
		{"goreleaser", []string{".goreleaser.yml"}, riskHigh, "release packaging"},
		{"published image", []string{"Dockerfile.goreleaser.slim"}, riskHigh, "release packaging"},
		{"local image", []string{"Dockerfile.test", "Dockerfile"}, riskLow, ""},
		{"release prep", []string{"scripts/relprep/main.go"}, riskHigh, "release packaging"},
		{"go.mod", []string{"go.mod"}, riskMedium, "a dependency"},
		{"go.sum", []string{"go.sum"}, riskMedium, "a dependency"},
		{"interim report", []string{"pkg/schema/interim.go"}, riskMedium, "an output contract"},
		{"published schema", []string{"schemas/callgraph-schema-6.18.json"}, riskMedium, "an output contract"},
		{"failure codes", []string{"pkg/failure/error.go"}, riskMedium, "an output contract"},
		{"fragment format", []string{"pkg/graphfrag/export.go"}, riskMedium, "an output contract"},
		{"callgraph format", []string{"pkg/graphfrag/callgraph_export.go"}, riskMedium, "an output contract"},
		{"stitching", []string{"pkg/graphfrag/stitch.go"}, riskLow, ""},
		{"lint config", []string{".golangci.yml"}, riskMedium, "a CI check's configuration"},
		{"tests of the gate", []string{"scripts/mergeready/check_test.go", "scripts/mergeready/testdata/pr803/pr.json"}, riskLow, ""},
		{"highest wins", []string{"go.mod", ".github/workflows/lint.yml"}, riskHigh, "a dependency"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reasons := pathFloor(tc.paths)
			if got != tc.want {
				t.Fatalf("pathFloor(%q) = %s, want %s (%q)", tc.paths, got, tc.want, reasons)
			}
			if tc.why == "" {
				if len(reasons) != 0 {
					t.Fatalf("want no reasons, got %q", reasons)
				}
				return
			}
			if len(reasons) == 0 || !strings.Contains(reasons[0], tc.why) {
				t.Fatalf("want a first reason containing %q, got %q", tc.why, reasons)
			}
		})
	}
}

// judge builds verdicts in category order: alignment, impact, verification,
// rollback, error_detection.
func judge(a, i, v, r, e string) verdicts {
	return verdicts{
		"alignment": {Verdict: a}, "impact": {Verdict: i}, "verification": {Verdict: v},
		"rollback": {Verdict: r}, "error_detection": {Verdict: e},
	}
}

func TestScore(t *testing.T) {
	tests := []struct {
		name string
		v    verdicts
		want riskLevel
	}{
		{"all best", judge("good", "small", "good", "low", "n/a"), riskLow},
		// Weighted mean 1.27.
		{"medium impact alone", judge("good", "medium", "good", "low", "good"), riskLow},
		// Weighted mean 1.53.
		{"medium impact, decent verification", judge("good", "medium", "decent", "low", "good"), riskMedium},
		// Weighted mean 3.
		{"all worst", judge("poor", "large", "poor", "high", "poor"), riskHigh},
		// Weighted mean 2.47.
		{"large, one-way", judge("decent", "large", "decent", "high", "decent"), riskHigh},
		// Weighted mean 2.
		{"all middling", judge("decent", "medium", "decent", "medium", "decent"), riskMedium},
		{"case does not matter", judge("Good", "SMALL", "good", "Low", "N/A"), riskLow},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if errs := tc.v.validate(); len(errs) != 0 {
				t.Fatalf("valid verdicts rejected: %q", errs)
			}
			if got := tc.v.score(); got != tc.want {
				t.Fatalf("score = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	v := judge("good", "huge", "good", "low", "")
	delete(v, "alignment")
	errs := v.validate()
	want := []string{"alignment: want", "impact: want", "error_detection: want"}
	if len(errs) != len(want) {
		t.Fatalf("got %q, want one error each for %q", errs, want)
	}
	for i := range want {
		if !strings.HasPrefix(errs[i], want[i]) {
			t.Fatalf("error %d is %q, want it to start with %q", i, errs[i], want[i])
		}
	}
	if !strings.Contains(errs[1], "large, medium, small") {
		t.Fatalf("the error names the allowed verdicts: %q", errs[1])
	}
}

func TestRenderAssessment(t *testing.T) {
	v := judge("good", "small", "good", "low", "n/a")
	v["verification"] = verdict{Verdict: "good", Gaps: []string{"no run on a large graph"}}
	body := renderAssessment(head, v, riskLow, riskHigh, []string{"the merge gate (`scripts/mergeready/x.go`) sets at least high"})
	for _, want := range []string{
		"<!-- merge-risk sha=" + head + " level=high -->\n**Merge risk: high** (head abc123000)\n",
		"Judged low; the changed paths raise it:\n- the merge gate (`scripts/mergeready/x.go`) sets at least high\n",
		"**Verification:** good ✅\n- no run on a large graph\n",
		"**Error detection:** n/a ✅\n",
		"A person decides this merge",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body lacks %q:\n%s", want, body)
		}
	}
	m := riskMarker.FindStringSubmatch(body)
	if len(m) != 3 || m[1] != head || m[2] != "high" {
		t.Fatalf("the gate cannot read the marker of:\n%s", body)
	}
	low := renderAssessment(head, judge("good", "small", "good", "low", "n/a"), riskLow, riskLow, nil)
	if strings.Contains(low, "Judged") || strings.Contains(low, "A person decides") {
		t.Fatalf("a low assessment names no floor and asks no one:\n%s", low)
	}
}

// TestPersonGates covers the two checks this gate added: Claude's review and
// the merge-risk assessment with a person's say-so.
func TestPersonGates(t *testing.T) {
	const (
		perm      = "api --paginate repos/o/r/collaborators/%s/permission"
		writer    = `{"permission":"write","role_name":"write"}`
		reader    = `{"permission":"read","role_name":"read"}`
		older     = "0000000000000000000000000000000000000000"
		labeled   = `{"number":12,"state":"OPEN","isDraft":false,"mergeable":"MERGEABLE","headRefOid":"` + head + `","author":{"login":"ann"},"labels":[{"name":"risk-accepted"}]}`
		bobApprov = `[{"user":{"login":"bob","type":"User"},"state":"APPROVED","commit_id":"` + head + `"}]`
	)
	permOf := func(login, body string) (string, string) {
		return strings.Replace(perm, "%s", login, 1), body
	}
	notes := func(items ...string) string { return "[" + strings.Join(items, ",") + "]" }
	labelEvent := func(actor, at string) string {
		return `[{"event":"labeled","actor":{"login":"` + actor + `"},"label":{"name":"risk-accepted"},"created_at":"` + at + `"}]`
	}
	tests := []struct {
		name string
		set  map[string]string
		want string // "" means ready
	}{
		{"ready: reviewed, low", nil, ""},

		{"no Claude review", map[string]string{keyNotes: notes(assessment(head, "low", "2026-11-01T10:00:00Z"))}, "Claude has not reviewed"},
		{"Claude reviewed as a pull request review", map[string]string{
			keyNotes:   notes(assessment(head, "low", "2026-11-01T10:00:00Z")),
			keyReviews: `[{"user":{"login":"claude[bot]","type":"Bot"},"state":"COMMENTED"}]`,
		}, ""},
		{"a person approved instead of Claude", func() map[string]string {
			k, v := permOf("bob", writer)
			return map[string]string{keyNotes: notes(assessment(head, "low", "2026-11-01T10:00:00Z")), keyReviews: bobApprov, k: v}
		}(), ""},
		{"comments unreadable", map[string]string{keyNotes: ""}, "cannot read the comments"},

		{"no assessment", map[string]string{keyNotes: notes(claudeSummary)}, "no merge-risk assessment of the head commit abc123000"},
		{"assessment of an older commit", map[string]string{keyNotes: notes(claudeSummary, assessment(older, "low", "2026-11-01T10:00:00Z"))}, "no merge-risk assessment"},
		{"assessment by someone else", map[string]string{keyNotes: notes(claudeSummary,
			`{"id":3,"user":{"login":"mallory"},"body":"<!-- merge-risk sha=`+head+` level=low -->"}`)}, "no merge-risk assessment"},
		{"latest assessment counts", map[string]string{keyNotes: notes(claudeSummary,
			assessment(head, "low", "2026-11-01T10:00:00Z"), assessment(head, "medium", "2026-11-01T11:00:00Z"))}, "merge risk is medium: a person decides"},
		{"files unreadable", map[string]string{keyFiles: ""}, "cannot read the changed files"},

		{
			"medium, nobody decided",
			map[string]string{keyNotes: notes(claudeSummary, assessment(head, "medium", "2026-11-01T10:00:00Z"))},
			"merge risk is medium: a person decides this merge. Ask for an approving review from someone other than ann",
		},
		{
			"judged low, floor high",
			map[string]string{keyFiles: `[{"filename":".github/workflows/lint.yml"}]`},
			"merge risk is high (CI, release and tagging workflows (`.github/workflows/lint.yml`) sets at least high)",
		},
		{
			"renamed out of the workflows",
			map[string]string{keyFiles: `[{"filename":"docs/old.yml","previous_filename":".github/workflows/lint.yml"}]`},
			"merge risk is high",
		},

		{"high, approved by a writer", func() map[string]string {
			k, v := permOf("bob", writer)
			return map[string]string{keyNotes: notes(claudeSummary, assessment(head, "high", "2026-11-01T10:00:00Z")), keyReviews: bobApprov, k: v}
		}(), ""},
		{"high, approved by a reader", func() map[string]string {
			k, v := permOf("bob", reader)
			return map[string]string{keyNotes: notes(claudeSummary, assessment(head, "high", "2026-11-01T10:00:00Z")), keyReviews: bobApprov, k: v}
		}(), "merge risk is high"},
		{"high, approval unjudgeable", map[string]string{
			keyNotes: notes(claudeSummary, assessment(head, "high", "2026-11-01T10:00:00Z")), keyReviews: bobApprov,
		}, "merge risk is high"},
		{"high, approved by the author", func() map[string]string {
			k, v := permOf("ann", writer)
			return map[string]string{
				keyNotes:   notes(claudeSummary, assessment(head, "high", "2026-11-01T10:00:00Z")),
				keyReviews: `[{"user":{"login":"ann","type":"User"},"state":"APPROVED","commit_id":"` + head + `"}]`, k: v,
			}
		}(), "merge risk is high"},
		{"high, approved an older commit", func() map[string]string {
			k, v := permOf("bob", writer)
			return map[string]string{
				keyNotes:   notes(claudeSummary, assessment(head, "high", "2026-11-01T10:00:00Z")),
				keyReviews: `[{"user":{"login":"bob","type":"User"},"state":"APPROVED","commit_id":"` + older + `"}]`, k: v,
			}
		}(), "merge risk is high"},
		{"high, approved by a bot", func() map[string]string {
			k, v := permOf("ci[bot]", writer)
			return map[string]string{
				keyNotes:   notes(claudeSummary, assessment(head, "high", "2026-11-01T10:00:00Z")),
				keyReviews: `[{"user":{"login":"ci[bot]","type":"Bot"},"state":"APPROVED","commit_id":"` + head + `"}]`, k: v,
			}
		}(), "merge risk is high"},

		{"high, labeled after the assessment", func() map[string]string {
			k, v := permOf("bob", writer)
			return map[string]string{
				keyView: labeled, keyNotes: notes(claudeSummary, assessment(head, "high", "2026-11-01T10:00:00Z")),
				keyEvents: labelEvent("bob", "2026-11-01T10:05:00Z"), k: v,
			}
		}(), ""},
		{"high, labeled before the assessment", func() map[string]string {
			k, v := permOf("bob", writer)
			return map[string]string{
				keyView: labeled, keyNotes: notes(claudeSummary, assessment(head, "high", "2026-11-01T10:00:00Z")),
				keyEvents: labelEvent("bob", "2026-11-01T09:30:00Z"), k: v,
			}
		}(), "merge risk is high"},
		{"high, label since removed", func() map[string]string {
			k, v := permOf("bob", writer)
			return map[string]string{
				keyNotes:  notes(claudeSummary, assessment(head, "high", "2026-11-01T10:00:00Z")),
				keyEvents: labelEvent("bob", "2026-11-01T10:05:00Z"), k: v,
			}
		}(), "merge risk is high"},
		{"high, labeled by a reader", func() map[string]string {
			k, v := permOf("eve", reader)
			return map[string]string{
				keyView: labeled, keyNotes: notes(claudeSummary, assessment(head, "high", "2026-11-01T10:00:00Z")),
				keyEvents: labelEvent("eve", "2026-11-01T10:05:00Z"), k: v,
			}
		}(), "merge risk is high"},
		{"high, events unreadable", map[string]string{
			keyNotes: notes(claudeSummary, assessment(head, "high", "2026-11-01T10:00:00Z")), keyEvents: "",
		}, "cannot read the events"},

		{"the review job failed", map[string]string{
			keyChecks: `{"check_runs":[{"name":"build","status":"completed","conclusion":"success"},{"name":"claude review","status":"completed","conclusion":"failure"}]}`,
		}, ""},
		{"the review workflow is running", map[string]string{
			keyRuns: `{"workflow_runs":[{"name":"PR review","status":"in_progress"}]}`,
		}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			responses := readyPR()
			for k, v := range tc.set {
				if v == "" {
					delete(responses, k)
				} else {
					responses[k] = v
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

func TestRunRisk(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{
		"alignment": {"verdict": "good", "gaps": []},
		"impact": {"verdict": "small", "gaps": []},
		"verification": {"verdict": "good", "gaps": []},
		"rollback": {"verdict": "low", "gaps": []},
		"error_detection": {"verdict": "n/a", "gaps": []}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"alignment": {"verdict": "fine"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	const (
		keyUser  = "api user"
		postKey  = "api --method POST repos/o/r/issues/12/comments -f body=<!-- merge-risk sha=" + head + " level="
		patchKey = "api --method PATCH repos/o/r/issues/comments/2 -f body=<!-- merge-risk sha=" + head + " level="
	)
	tests := []struct {
		name   string
		args   []string
		set    map[string]string
		code   int
		out    string
		called string // a gh call that must have happened
	}{
		{
			name: "dry run, floored", args: []string{"--verdicts", good, "--dry-run"},
			set:  map[string]string{keyFiles: `[{"filename":"go.mod"}]`},
			code: 0, out: "level=medium -->\n**Merge risk: medium**",
		},
		{name: "invalid verdicts", args: []string{"--verdicts", bad}, code: 2, out: `alignment: want {"verdict": one of decent, good, poor`},
		{name: "missing verdicts file", args: []string{"--verdicts", filepath.Join(dir, "none.json")}, code: 2, out: "cannot read the verdicts"},
		{name: "no --verdicts", args: nil, code: 2, out: "risk needs --pr and --verdicts"},
		{
			name: "edits the runner's comment", args: []string{"--verdicts", good},
			set: map[string]string{keyUser: `{"login":"ann"}`},
			// gh's response to the edit: fakeGH keys calls by their whole argument list.
			code: 0, called: patchKey + "low",
		},
		{
			name: "posts when the runner has none", args: []string{"--verdicts", good},
			set:  map[string]string{keyUser: `{"login":"ann"}`, keyNotes: "[" + claudeSummary + "]"},
			code: 0, called: postKey + "low",
		},
		{
			name: "warns when the runner is not the author", args: []string{"--verdicts", good},
			set:  map[string]string{keyUser: `{"login":"bob"}`},
			code: 0, out: "the gate reads only ann's assessment, and this posts as bob", called: postKey + "low",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			responses := readyPR()
			for k, v := range tc.set {
				responses[k] = v
			}
			f := &recordingGH{fakeGH: fakeGH{responses: responses}, url: "https://github.com/o/r/pull/12#issuecomment-2"}
			var out bytes.Buffer
			args := append([]string{"risk", "--pr", "12", "--repo", repo}, tc.args...)
			code := run(context.Background(), args, nil, &out, &out, f)
			if code != tc.code {
				t.Fatalf("exit %d, want %d; output:\n%s", code, tc.code, out.String())
			}
			if tc.out != "" && !strings.Contains(out.String(), tc.out) {
				t.Fatalf("output lacks %q:\n%s", tc.out, out.String())
			}
			if tc.called == "" {
				for _, call := range f.calls {
					if strings.Contains(call, "--method") {
						t.Fatalf("want nothing posted, got %q", call)
					}
				}
				return
			}
			found := false
			for _, call := range f.calls {
				found = found || strings.HasPrefix(call, tc.called)
			}
			if !found {
				t.Fatalf("want a call starting %q, got %q", tc.called, f.calls)
			}
			if !strings.Contains(out.String(), f.url) {
				t.Fatalf("want the comment URL printed, got:\n%s", out.String())
			}
		})
	}
}

// recordingGH answers a comment write with the comment's URL and every other
// call from its recorded responses.
type recordingGH struct {
	fakeGH
	url string
}

func (r *recordingGH) run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	if len(args) > 2 && args[1] == "--method" {
		r.calls = append(r.calls, strings.Join(args, " "))
		return []byte(`{"html_url":"` + r.url + `"}`), nil
	}
	return r.fakeGH.run(ctx, dir, args...)
}

func TestLabelProblems(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string // "" means allowed
	}{
		{"add the label", "gh pr edit 12 --add-label risk-accepted", "a person's decision"},
		{"remove the label", "gh pr edit 12 --remove-label risk-accepted", "a person's decision"},
		{"quoted and split", `gh pr edit 12 --add-label "risk"-'accepted'`, "a person's decision"},
		{"other spelling", "gh pr edit 12 --add-label Risk_Accepted", "a person's decision"},
		{"labels endpoint", `gh api repos/o/r/issues/12/labels -f "labels[]=risk-accepted"`, "a person's decision"},
		{"GraphQL", `gh api graphql -f query='mutation { addLabelsToLabelable(input:{labelIds:["risk-accepted"]}) { clientMutationId } }'`, "a person's decision"},
		{"create with the label", "gh pr create --label risk-accepted", "a person's decision"},
		{"labels from a variable", "gh pr edit 12 --add-label $L", "cannot be checked"},
		{"labels from a file", "gh api repos/o/r/issues/12/labels --input labels.json", "cannot be checked"},
		{"labels from stdin", "gh api repos/o/r/issues/12/labels -F labels[]=@-", "cannot be checked"},

		{"another label", "gh pr edit 12 --add-label bug", ""},
		{"read the labels", "gh pr view 12 --json labels", ""},
		{"no label", "gh pr view 12", ""},
		{"a variable without a label write", "echo $HOME label", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := labelProblems(tc.cmd)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("labelProblems(%q) = %q, want none", tc.cmd, got)
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0], tc.want) {
				t.Fatalf("labelProblems(%q) = %q, want one containing %q", tc.cmd, got, tc.want)
			}
		})
	}
}

func TestRunHookBlocksTheLabel(t *testing.T) {
	f := &fakeGH{}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"hook"}, strings.NewReader(event(t, "Bash", "gh pr edit 12 --add-label risk-accepted")), &stdout, &stderr, f)
	if code != 2 || !strings.Contains(stderr.String(), "an agent never adds or removes it") {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr.String())
	}
	if len(f.calls) != 0 {
		t.Fatalf("want no gh calls, got %q", f.calls)
	}
}
