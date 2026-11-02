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
)

// reviewBot is the login whose inline review comments each need a reply.
const reviewBot = "claude[bot]"

type pullRequest struct {
	Number     int    `json:"number"`
	State      string `json:"state"`
	IsDraft    bool   `json:"isDraft"`
	Mergeable  string `json:"mergeable"`
	HeadRefOid string `json:"headRefOid"`
}

// readinessCheck returns why pr is not ready, or nothing. A check that cannot
// read what it needs returns that as its reason: the gate fails closed.
type readinessCheck func(ctx context.Context, c client, pr pullRequest) []string

// readinessChecks are independent; checkPR runs every one and reports every
// reason. A new merge condition is one more function here.
var readinessChecks = []readinessCheck{
	checkOpen,
	checkMergeable,
	checkWorkflowRuns,
	checkCheckRuns,
	checkStatuses,
	checkReviews,
	checkBotComments,
}

// checkPR returns every reason pull request number is not ready to merge.
func checkPR(ctx context.Context, c client, number int) []string {
	raw, err := c.gh.run(ctx, "", "pr", "view", strconv.Itoa(number), "-R", c.repo,
		"--json", "number,state,isDraft,mergeable,headRefOid")
	if err != nil {
		return []string{fmt.Sprintf("cannot read the pull request: %v", err)}
	}
	var pr pullRequest
	if err := json.Unmarshal(raw, &pr); err != nil {
		return []string{fmt.Sprintf("cannot read the pull request: unparseable response: %v", err)}
	}
	if pr.Number != number || pr.HeadRefOid == "" {
		return []string{fmt.Sprintf("cannot read the pull request: unexpected response %s", raw)}
	}
	var reasons []string
	for _, check := range readinessChecks {
		reasons = append(reasons, check(ctx, c, pr)...)
	}
	return reasons
}

func checkOpen(_ context.Context, _ client, pr pullRequest) []string {
	var reasons []string
	if pr.State != "OPEN" {
		reasons = append(reasons, fmt.Sprintf("the pull request is not open (state %s)", pr.State))
	}
	if pr.IsDraft {
		reasons = append(reasons, "the pull request is a draft")
	}
	return reasons
}

// checkMergeable reports conflicts. GitHub stops computing mergeability once a
// pull request closes, and checkOpen already says it is not open.
func checkMergeable(_ context.Context, _ client, pr pullRequest) []string {
	if pr.State != "OPEN" {
		return nil
	}
	switch pr.Mergeable {
	case "MERGEABLE":
		return nil
	case "CONFLICTING":
		return []string{"the pull request has a merge conflict with its base branch"}
	case "UNKNOWN":
		return []string{"GitHub is still computing mergeability, retry"}
	default:
		return []string{fmt.Sprintf("unexpected mergeable state %q", pr.Mergeable)}
	}
}

type workflowRunPage struct {
	WorkflowRuns []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"workflow_runs"`
}

// checkWorkflowRuns closes the window between a push and the creation of the
// check runs: a workflow run that has not finished may not have created its
// check runs yet.
func checkWorkflowRuns(ctx context.Context, c client, pr pullRequest) []string {
	pages, err := fetch[workflowRunPage](ctx, c, "actions/runs?head_sha="+pr.HeadRefOid+"&per_page=100")
	if err != nil {
		return []string{"cannot read the workflow runs: " + err.Error()}
	}
	var reasons []string
	for _, p := range pages {
		if p.WorkflowRuns == nil {
			return []string{"cannot read the workflow runs: the response has no workflow_runs"}
		}
		for _, r := range p.WorkflowRuns {
			if r.Status != statusCompleted {
				reasons = append(reasons, fmt.Sprintf("workflow %q has not finished (status %s)", r.Name, r.Status))
			}
		}
	}
	return reasons
}

type checkRun struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Conclusion  string `json:"conclusion"`
	CompletedAt string `json:"completed_at"`
}

type checkRunPage struct {
	CheckRuns []checkRun `json:"check_runs"`
}

// greenConclusion holds the check run conclusions that allow a merge.
var greenConclusion = map[string]bool{"success": true, "neutral": true, "skipped": true}

// checkCheckRuns judges the latest attempt of every check run on the head.
func checkCheckRuns(ctx context.Context, c client, pr pullRequest) []string {
	runs, err := fetchCheckRuns(ctx, c, pr.HeadRefOid)
	if err != nil {
		return []string{"cannot read the check runs: " + err.Error()}
	}
	if len(runs) == 0 {
		return []string{"there are no check runs on the head commit yet"}
	}
	var reasons []string
	for _, r := range runs {
		switch {
		case r.Status != statusCompleted:
			reasons = append(reasons, fmt.Sprintf("check %q has not finished (status %s)", r.Name, r.Status))
		case !greenConclusion[r.Conclusion]:
			reasons = append(reasons, fmt.Sprintf("check %q finished with %s", r.Name, r.Conclusion))
		}
	}
	return reasons
}

func fetchCheckRuns(ctx context.Context, c client, sha string) ([]checkRun, error) {
	pages, err := fetch[checkRunPage](ctx, c, "commits/"+sha+"/check-runs?filter=latest&per_page=100")
	if err != nil {
		return nil, err
	}
	var runs []checkRun
	for _, p := range pages {
		if p.CheckRuns == nil {
			return nil, fmt.Errorf("the response has no check_runs")
		}
		runs = append(runs, p.CheckRuns...)
	}
	return runs, nil
}

type commitStatus struct {
	Context   string `json:"context"`
	State     string `json:"state"`
	UpdatedAt string `json:"updated_at"`
}

type statusPage struct {
	Statuses []commitStatus `json:"statuses"`
}

// checkStatuses judges each commit status context; the combined state is not
// used because it reads "pending" when there are no statuses at all.
func checkStatuses(ctx context.Context, c client, pr pullRequest) []string {
	statuses, err := fetchStatuses(ctx, c, pr.HeadRefOid)
	if err != nil {
		return []string{"cannot read the commit statuses: " + err.Error()}
	}
	var reasons []string
	for _, s := range statuses {
		switch s.State {
		case "success":
		case "pending":
			reasons = append(reasons, fmt.Sprintf("status %q has not finished", s.Context))
		default:
			reasons = append(reasons, fmt.Sprintf("status %q finished with %s", s.Context, s.State))
		}
	}
	return reasons
}

func fetchStatuses(ctx context.Context, c client, sha string) ([]commitStatus, error) {
	pages, err := fetch[statusPage](ctx, c, "commits/"+sha+"/status?per_page=100")
	if err != nil {
		return nil, err
	}
	var statuses []commitStatus
	for _, p := range pages {
		if p.Statuses == nil {
			return nil, fmt.Errorf("the response has no statuses")
		}
		statuses = append(statuses, p.Statuses...)
	}
	return statuses, nil
}

type review struct {
	User  user   `json:"user"`
	State string `json:"state"`
}

type user struct {
	Login string `json:"login"`
}

// checkReviews blocks while a reviewer's latest verdict asks for changes. Only
// verdicts count: a COMMENTED review, which a reply to a thread also creates,
// does not lift a request for changes; approving or dismissing it does.
func checkReviews(ctx context.Context, c client, pr pullRequest) []string {
	pages, err := fetch[[]review](ctx, c, "pulls/"+strconv.Itoa(pr.Number)+"/reviews?per_page=100")
	if err != nil {
		return []string{"cannot read the reviews: " + err.Error()}
	}
	latest := map[string]string{}
	var order []string
	for _, p := range pages {
		for _, r := range p {
			if r.State == "COMMENTED" || r.State == "PENDING" {
				continue
			}
			if _, seen := latest[r.User.Login]; !seen {
				order = append(order, r.User.Login)
			}
			latest[r.User.Login] = r.State
		}
	}
	var reasons []string
	for _, login := range order {
		if latest[login] == "CHANGES_REQUESTED" {
			reasons = append(reasons, fmt.Sprintf("%s requested changes", login))
		}
	}
	return reasons
}

type reviewComment struct {
	ID          int64  `json:"id"`
	InReplyToID int64  `json:"in_reply_to_id"`
	User        user   `json:"user"`
	Path        string `json:"path"`
	Line        int    `json:"line"`
	HTMLURL     string `json:"html_url"`
}

// checkBotComments requires a reply to every inline comment of reviewBot.
// GitHub points in_reply_to_id of every reply at the first comment of its
// thread, so a bot comment is answered when a later comment exists in the same
// thread; for a bot comment that opens a thread, that is a comment whose
// in_reply_to_id is its id.
func checkBotComments(ctx context.Context, c client, pr pullRequest) []string {
	pages, err := fetch[[]reviewComment](ctx, c, "pulls/"+strconv.Itoa(pr.Number)+"/comments?per_page=100")
	if err != nil {
		return []string{"cannot read the review comments: " + err.Error()}
	}
	lastInThread := map[int64]int64{}
	var comments []reviewComment
	for _, p := range pages {
		for _, cm := range p {
			thread := threadOf(cm)
			lastInThread[thread] = max(lastInThread[thread], cm.ID)
			comments = append(comments, cm)
		}
	}
	var reasons []string
	for _, cm := range comments {
		if cm.User.Login == reviewBot && lastInThread[threadOf(cm)] == cm.ID {
			reasons = append(reasons, fmt.Sprintf("review comment by %s on %s:%d has no reply: %s",
				reviewBot, cm.Path, cm.Line, cm.HTMLURL))
		}
	}
	return reasons
}

func threadOf(cm reviewComment) int64 {
	if cm.InReplyToID != 0 {
		return cm.InReplyToID
	}
	return cm.ID
}

func fetch[T any](ctx context.Context, c client, path string) ([]T, error) {
	raw, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	return decodePages[T](raw)
}
