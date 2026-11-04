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
	"strconv"
	"strings"
	"time"
)

// writers are the repository roles whose approval or label is a person's say-so.
var writers = map[string]bool{"admin": true, "maintain": true, "write": true}

type issueComment struct {
	ID        int64  `json:"id"`
	User      user   `json:"user"`
	Body      string `json:"body"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type issueEvent struct {
	Event string `json:"event"`
	Actor user   `json:"actor"`
	Label struct {
		Name string `json:"name"`
	} `json:"label"`
	CreatedAt string `json:"created_at"`
}

func fetchIssueComments(ctx context.Context, c client, number int) ([]issueComment, error) {
	return fetchAll[issueComment](ctx, c, "issues/"+strconv.Itoa(number)+"/comments?per_page=100")
}

func fetchEvents(ctx context.Context, c client, number int) ([]issueEvent, error) {
	return fetchAll[issueEvent](ctx, c, "issues/"+strconv.Itoa(number)+"/events?per_page=100")
}

// fetchAll reads every page of a list endpoint.
func fetchAll[T any](ctx context.Context, c client, path string) ([]T, error) {
	pages, err := fetch[[]T](ctx, c, path)
	if err != nil {
		return nil, err
	}
	var out []T
	for _, p := range pages {
		out = append(out, p...)
	}
	return out, nil
}

// canWrite reports whether login may write to the repository. An account the
// API cannot judge cannot decide a merge.
func canWrite(ctx context.Context, c client, login string) bool {
	if login == "" {
		return false
	}
	raw, err := c.get(ctx, "collaborators/"+login+"/permission")
	if err != nil {
		return false
	}
	var p struct {
		Permission string `json:"permission"`
		RoleName   string `json:"role_name"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return false
	}
	return writers[p.RoleName] || writers[p.Permission]
}

// approvedByPerson reports whether someone other than the author, a person
// who can write, has the head commit approved as their latest verdict.
func approvedByPerson(ctx context.Context, c client, pr pullRequest, reviews []review) bool {
	for _, r := range latestVerdicts(reviews) {
		if r.State == "APPROVED" && r.CommitID == pr.HeadRefOid && r.User.Login != pr.Author.Login &&
			r.User.Type != "Bot" && canWrite(ctx, c, r.User.Login) {
			return true
		}
	}
	return false
}

// labeledByPerson reports whether riskLabel is on the pull request and someone
// who can write added it, at or after since when since is set.
func labeledByPerson(ctx context.Context, c client, pr pullRequest, events []issueEvent, since time.Time) bool {
	on := false
	for _, l := range pr.Labels {
		on = on || strings.EqualFold(l.Name, riskLabel)
	}
	if !on {
		return false
	}
	for _, e := range events {
		if e.Event != "labeled" || !strings.EqualFold(e.Label.Name, riskLabel) {
			continue
		}
		at, err := time.Parse(time.RFC3339, e.CreatedAt)
		if err != nil || (!since.IsZero() && at.Before(since)) {
			continue
		}
		if canWrite(ctx, c, e.Actor.Login) {
			return true
		}
	}
	return false
}

// checkClaudeReview requires that Claude reviewed the pull request: a comment
// or a review from reviewBot. pr-review.yml leaves a summary comment on every
// pull request it reviews. A review that failed, or was skipped (the action
// does not run on a pull request that changes pr-review.yml), leaves neither;
// a person's approval or the risk label then stands in for it.
func checkClaudeReview(ctx context.Context, c client, pr pullRequest) []string {
	comments, err := fetchIssueComments(ctx, c, pr.Number)
	if err != nil {
		return []string{"cannot read the comments: " + err.Error()}
	}
	reviews, err := fetchReviews(ctx, c, pr.Number)
	if err != nil {
		return []string{"cannot read the reviews: " + err.Error()}
	}
	for _, cm := range comments {
		if cm.User.Login == reviewBot {
			return nil
		}
	}
	for _, r := range reviews {
		if r.User.Login == reviewBot {
			return nil
		}
	}
	if approvedByPerson(ctx, c, pr, reviews) {
		return nil
	}
	events, err := fetchEvents(ctx, c, pr.Number)
	if err != nil {
		return []string{"cannot read the events: " + err.Error()}
	}
	if labeledByPerson(ctx, c, pr, events, time.Time{}) {
		return nil
	}
	return []string{"Claude has not reviewed this pull request (no comment or review from " + reviewBot + "): " +
		"comment `@claude review` on it and wait for the review. If pr-review.yml cannot review it " +
		"(a pull request that changes that workflow), a person decides: an approving review or the '" +
		riskLabel + "' label"}
}

// checkMergeRisk requires a merge-risk assessment of the head commit, written
// by the author's account (the agent opens pull requests as the author and
// runs mergeready risk). Low passes. Medium or high needs a person: the latest
// review of someone other than the author approving the head commit, or
// riskLabel added after the assessment, both by an account that can write.
// The level is never below the path floor, which is recomputed here.
func checkMergeRisk(ctx context.Context, c client, pr pullRequest) []string {
	comments, err := fetchIssueComments(ctx, c, pr.Number)
	if err != nil {
		return []string{"cannot read the comments: " + err.Error()}
	}
	judged, assessed := latestAssessment(pr, comments)
	if assessed == nil {
		return []string{fmt.Sprintf("no merge-risk assessment of the head commit %s: "+
			"run the merge-risk skill (.claude/skills/merge-risk/SKILL.md)", short(pr.HeadRefOid))}
	}
	paths, err := changedPaths(ctx, c, pr.Number)
	if err != nil {
		return []string{"cannot read the changed files: " + err.Error()}
	}
	least, reasons := pathFloor(paths)
	level := max(judged, least)
	if level == riskLow {
		return nil
	}
	if accepted, err := riskAccepted(ctx, c, pr, assessed); err != nil || accepted {
		if err != nil {
			return []string{err.Error()}
		}
		return nil
	}
	why := ""
	if level != judged {
		why = " (" + strings.Join(reasons, "; ") + ")"
	}
	return []string{fmt.Sprintf("merge risk is %s%s: a person decides this merge. Ask for an approving review "+
		"from someone other than %s, or for the '%s' label added after the latest assessment. "+
		"An agent never adds that label", level, why, pr.Author.Login, riskLabel)}
}

// latestAssessment returns the level of the author's latest merge-risk
// comment on the head commit, and that comment; nil when there is none.
func latestAssessment(pr pullRequest, comments []issueComment) (riskLevel, *issueComment) {
	judged, assessed := riskLow, (*issueComment)(nil)
	for i, cm := range comments {
		m := riskMarker.FindStringSubmatch(cm.Body)
		if cm.User.Login != pr.Author.Login || len(m) != 3 || m[1] != pr.HeadRefOid {
			continue
		}
		judged, _ = parseRiskLevel(m[2])
		assessed = &comments[i]
	}
	return judged, assessed
}

// riskAccepted reports whether a person accepted the assessed risk: approved
// the head commit, or added riskLabel after the assessment.
func riskAccepted(ctx context.Context, c client, pr pullRequest, assessed *issueComment) (bool, error) {
	reviews, err := fetchReviews(ctx, c, pr.Number)
	if err != nil {
		return false, fmt.Errorf("cannot read the reviews: %w", err)
	}
	if approvedByPerson(ctx, c, pr, reviews) {
		return true, nil
	}
	events, err := fetchEvents(ctx, c, pr.Number)
	if err != nil {
		return false, fmt.Errorf("cannot read the events: %w", err)
	}
	stamp := assessed.UpdatedAt
	if stamp == "" {
		stamp = assessed.CreatedAt
	}
	at, err := time.Parse(time.RFC3339, stamp)
	return err == nil && labeledByPerson(ctx, c, pr, events, at), nil
}

func short(sha string) string {
	if len(sha) > 9 {
		return sha[:9]
	}
	return sha
}
