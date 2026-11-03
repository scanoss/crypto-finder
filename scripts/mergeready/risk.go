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
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// riskLevel orders the merge-risk levels: a higher one needs more say-so.
type riskLevel int

const (
	riskLow riskLevel = iota
	riskMedium
	riskHigh
)

var riskNames = [...]string{"low", "medium", "high"}

func (l riskLevel) String() string { return riskNames[l] }

func parseRiskLevel(s string) (riskLevel, bool) {
	for i, name := range riskNames {
		if s == name {
			return riskLevel(i), true
		}
	}
	return riskLow, false
}

// riskMarker is hidden in the merge-risk comment, one per pull request, and
// names the head commit it assessed and the level it gave.
var riskMarker = regexp.MustCompile(`<!-- merge-risk sha=([0-9a-f]{40}) level=(low|medium|high) -->`)

// riskLabel is a person accepting a medium or high merge risk. An agent never
// adds or removes it; the hook refuses a command that could.
const riskLabel = "risk-accepted"

// riskFloor is a path whose change carries risk whatever the diff looks like.
// The gate recomputes the floor itself, so no comment can talk it down.
type riskFloor struct {
	level riskLevel
	why   string
	re    *regexp.Regexp
}

// riskFloors lists the floors, highest first; a path takes the first match.
// .claude/skills/merge-risk/SKILL.md explains each one.
var riskFloors = []riskFloor{
	{riskHigh, "CI, release and tagging workflows", regexp.MustCompile(`^\.github/(workflows|actions)/`)},
	{riskHigh, "the merge gate", regexp.MustCompile(`^(scripts/mergeready/|\.claude/settings\.json$)`)},
	{riskHigh, "release packaging", regexp.MustCompile(`^(\.goreleaser|Dockerfile\.goreleaser|scripts/relprep/)`)},
	{riskMedium, "a dependency", regexp.MustCompile(`(^|/)go\.(mod|sum)$`)},
	{riskMedium, "an output contract other tools read", regexp.MustCompile(
		`^(schemas/|pkg/schema/|pkg/failure/|pkg/graphfrag/(export|callgraph_export|findings_envelope|intern_functions|model)\.go$)`)},
	{riskMedium, "a CI check's configuration", regexp.MustCompile(`^(\.golangci\.yml|\.golangci-lint-version|\.testcoverage\.yml)$`)},
}

// riskExempt holds tests and their fixtures, which set no floor.
var riskExempt = regexp.MustCompile(`(^|/)testdata/|_test\.go$`)

// pathFloor returns the lowest level the changed paths allow, and why.
func pathFloor(paths []string) (riskLevel, []string) {
	level, seen := riskLow, map[string]bool{}
	var reasons []string
	for _, p := range paths {
		if riskExempt.MatchString(p) {
			continue
		}
		for _, f := range riskFloors {
			if !f.re.MatchString(p) {
				continue
			}
			r := fmt.Sprintf("%s (`%s`) sets at least %s", f.why, p, f.level)
			if !seen[r] {
				seen[r] = true
				reasons = append(reasons, r)
			}
			level = max(level, f.level)
			break
		}
	}
	return level, reasons
}

// riskCategory is one of the five things the merge-risk skill judges.
type riskCategory struct {
	key, label string
	weight     float64
	// values maps each verdict to its value: 3 is the worst, 1 the best.
	values map[string]int
}

// riskCategories come from Warp's merge-risk skill (credited to Matt Pocock),
// as scanoss/earnie scores them.
var riskCategories = []riskCategory{
	{"alignment", "Alignment", 1, map[string]int{"poor": 3, "decent": 2, "good": 1}},
	{"impact", "Impact", 2, map[string]int{"large": 3, "medium": 2, "small": 1}},
	{"verification", "Verification", 2, map[string]int{"poor": 3, "decent": 2, "good": 1}},
	{"rollback", "Rollback cost", 1.5, map[string]int{"high": 3, "medium": 2, "low": 1}},
	{"error_detection", "Error detection", 1, map[string]int{"poor": 3, "decent": 2, "good": 1, "n/a": 1}},
}

var riskIcons = map[int]string{3: "⚠️", 2: "👀", 1: "✅"}

// verdict is the agent's judgement of one category.
type verdict struct {
	Verdict string   `json:"verdict"`
	Gaps    []string `json:"gaps"`
}

type verdicts map[string]verdict

func (v verdicts) value(c riskCategory) (int, bool) {
	n, ok := c.values[strings.ToLower(v[c.key].Verdict)]
	return n, ok
}

// validate returns one line per category the verdicts miss or misname.
func (v verdicts) validate() []string {
	var errs []string
	for _, c := range riskCategories {
		if _, ok := v.value(c); !ok {
			allowed := make([]string, 0, len(c.values))
			for k := range c.values {
				allowed = append(allowed, k)
			}
			sort.Strings(allowed)
			errs = append(errs, fmt.Sprintf(`%s: want {"verdict": one of %s, "gaps": [...]}`, c.key, strings.Join(allowed, ", ")))
		}
	}
	return errs
}

// score is the level the verdicts give: the weighted mean of their values.
func (v verdicts) score() riskLevel {
	var total, weights float64
	for _, c := range riskCategories {
		n, _ := v.value(c)
		total += float64(n) * c.weight
		weights += c.weight
	}
	switch mean := total / weights; {
	case mean < 1.5:
		return riskLow
	case mean < 2.25:
		return riskMedium
	default:
		return riskHigh
	}
}

// renderAssessment is the body of the merge-risk comment.
func renderAssessment(sha string, v verdicts, judged, level riskLevel, reasons []string) string {
	var b strings.Builder
	b.WriteString("<!-- merge-risk sha=" + sha + " level=" + level.String() + " -->\n")
	b.WriteString("**Merge risk: " + level.String() + "** (head " + short(sha) + ")\n\n")
	if level != judged {
		b.WriteString("Judged " + judged.String() + "; the changed paths raise it:\n")
		for _, r := range reasons {
			b.WriteString("- " + r + "\n")
		}
		b.WriteString("\n")
	}
	for _, c := range riskCategories {
		n, _ := v.value(c)
		b.WriteString("**" + c.label + ":** " + strings.ToLower(v[c.key].Verdict) + " " + riskIcons[n] + "\n")
		for _, g := range v[c.key].Gaps {
			b.WriteString("- " + g + "\n")
		}
		b.WriteString("\n")
	}
	if level != riskLow {
		b.WriteString("A person decides this merge: an approving review from someone other than the author, " +
			"or the `" + riskLabel + "` label added after this assessment (`go run ./scripts/mergeready check`).\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

type prFile struct {
	Filename         string `json:"filename"`
	PreviousFilename string `json:"previous_filename"`
}

// changedPaths lists every path the pull request touches. A rename counts its
// old path too, so moving a workflow out of .github/workflows keeps its floor.
func changedPaths(ctx context.Context, c client, number int) ([]string, error) {
	files, err := fetchAll[prFile](ctx, c, "pulls/"+strconv.Itoa(number)+"/files?per_page=100")
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, f := range files {
		paths = append(paths, f.Filename)
		if f.PreviousFilename != "" {
			paths = append(paths, f.PreviousFilename)
		}
	}
	return paths, nil
}

// runRisk scores the verdicts of the merge-risk skill, floors them by path and
// keeps one merge-risk comment on the pull request, by the account running it.
func runRisk(ctx context.Context, c client, number int, verdictsFile string, dryRun bool, stdout, stderr *printer) int {
	raw, err := os.ReadFile(verdictsFile) //nolint:gosec // G304: the agent names its own verdicts file
	if err != nil {
		stderr.println("cannot read the verdicts:", err)
		return 2
	}
	var v verdicts
	if err := json.Unmarshal(raw, &v); err != nil {
		stderr.println("cannot read the verdicts:", err)
		return 2
	}
	if errs := v.validate(); len(errs) > 0 {
		for _, e := range errs {
			stderr.println(e)
		}
		return 2
	}
	pr, err := viewPR(ctx, c, number)
	if err != nil {
		stderr.println(err)
		return 1
	}
	paths, err := changedPaths(ctx, c, number)
	if err != nil {
		stderr.println("cannot read the changed files:", err)
		return 1
	}
	judged := v.score()
	least, reasons := pathFloor(paths)
	body := renderAssessment(pr.HeadRefOid, v, judged, max(judged, least), reasons)
	if dryRun {
		stdout.printf("%s", body)
		return 0
	}
	url, err := upsertAssessment(ctx, c, pr, body, stderr)
	if err != nil {
		stderr.println("cannot post the assessment:", err)
		return 1
	}
	stdout.println(url)
	return 0
}

// upsertAssessment edits the runner's merge-risk comment, or posts one.
func upsertAssessment(ctx context.Context, c client, pr pullRequest, body string, stderr *printer) (string, error) {
	raw, err := c.gh.run(ctx, "", "api", "user")
	if err != nil {
		return "", err
	}
	var me user
	if err := json.Unmarshal(raw, &me); err != nil || me.Login == "" {
		return "", fmt.Errorf("cannot tell who runs this from %q", raw)
	}
	if me.Login != pr.Author.Login {
		stderr.printf("warning: the gate reads only %s's assessment, and this posts as %s\n", pr.Author.Login, me.Login)
	}
	comments, err := fetchIssueComments(ctx, c, pr.Number)
	if err != nil {
		return "", err
	}
	args := []string{"api", "--method", "POST", "repos/" + c.repo + "/issues/" + strconv.Itoa(pr.Number) + "/comments"}
	for _, cm := range comments {
		if cm.User.Login == me.Login && riskMarker.MatchString(cm.Body) {
			args = []string{"api", "--method", "PATCH", "repos/" + c.repo + "/issues/comments/" + strconv.FormatInt(cm.ID, 10)}
			break
		}
	}
	out, err := c.gh.run(ctx, "", append(args, "-f", "body="+body)...)
	if err != nil {
		return "", err
	}
	var posted struct {
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(out, &posted); err != nil || posted.HTMLURL == "" {
		return "", fmt.Errorf("unexpected response %q", out)
	}
	return posted.HTMLURL, nil
}
