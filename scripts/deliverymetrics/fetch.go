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
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"
)

// maxPullPages bounds the walk back through closed PRs (100 a page).
const maxPullPages = 50

type options struct {
	weeks, sample, reserve, workers int
	until                           time.Time
	branch                          string
}

// client is the gh CLI bound to one repository. Every call is a GET.
type client struct {
	gh   gh
	repo string // owner/name
}

// pages fetches a REST path of the repository, following every page.
func pages[T any](ctx context.Context, c client, path string) ([]T, error) {
	raw, err := c.gh.run(ctx, "api", "--paginate", "repos/"+c.repo+"/"+path)
	if err != nil {
		return nil, err
	}
	return decodePages[T](raw)
}

// list fetches every item of a paginated REST list.
func list[T any](ctx context.Context, c client, path string) ([]T, error) {
	ps, err := pages[[]T](ctx, c, path)
	if err != nil {
		return nil, err
	}
	var out []T
	for _, p := range ps {
		out = append(out, p...)
	}
	return out, nil
}

// remaining is how many core API requests the token has left this hour.
// Reading it costs none.
func remaining(ctx context.Context, c client) (int, error) {
	raw, err := c.gh.run(ctx, "api", "rate_limit")
	if err != nil {
		return 0, err
	}
	var v struct {
		Resources struct {
			Core struct {
				Remaining *int `json:"remaining"`
			} `json:"core"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.Resources.Core.Remaining == nil {
		return 0, fmt.Errorf("cannot read the rate limit from %q", raw)
	}
	return *v.Resources.Core.Remaining, nil
}

// measure fetches the inputs of both windows and computes the report.
func measure(ctx context.Context, c client, o options, log *printer) (report, error) {
	start := weekStart(o.until).AddDate(0, 0, -7*(2*o.weeks-1))
	since := url.QueryEscape(start.Format(time.RFC3339))
	prs, err := mergedPulls(ctx, c, o.branch, start)
	if err != nil {
		return report{}, fmt.Errorf("pull requests: %w", err)
	}
	commits, err := list[commit](ctx, c, "commits?sha="+url.QueryEscape(o.branch)+"&since="+since+"&per_page=100")
	if err != nil {
		return report{}, fmt.Errorf("commits: %w", err)
	}
	comments, err := list[comment](ctx, c, "issues/comments?since="+since+"&per_page=100")
	if err != nil {
		return report{}, fmt.Errorf("comments: %w", err)
	}
	issues, err := redIssues(ctx, c, start)
	if err != nil {
		return report{}, fmt.Errorf("red-main issues: %w", err)
	}
	byWeek := map[time.Time][]pull{}
	for i := range prs {
		w := weekStart(*prs[i].MergedAt)
		byWeek[w] = append(byWeek[w], prs[i])
	}
	var chosen []pull
	for _, group := range byWeek {
		chosen = append(chosen, sample(group, o.sample)...)
	}
	sort.Slice(chosen, func(i, j int) bool { return chosen[i].Number < chosen[j].Number })
	costs, notCosted := costAll(ctx, c, chosen, o, log)
	in := inputs{
		prs: prs, costs: costs, qa: qaByPR(comments), reverted: reverts(prs, commits),
		red: redMain(issues), audits: audits(comments),
	}
	return report{
		Repo: c.repo, Start: start.Format(time.DateOnly), Weeks: o.weeks, Sample: o.sample, Reserve: o.reserve,
		NotCosted: notCosted, Rows: weekly(in, start, 2*o.weeks),
	}, nil
}

// mergedPulls walks closed PRs into branch, most recently updated first, and
// keeps the ones merged since start. A PR merged since start was updated
// since, so the walk stops at the first page that reaches back before it.
func mergedPulls(ctx context.Context, c client, branch string, start time.Time) ([]pull, error) {
	var out []pull
	for page := 1; page <= maxPullPages; page++ {
		raw, err := c.gh.run(ctx, "api", "repos/"+c.repo+"/pulls?state=closed&base="+url.QueryEscape(branch)+
			"&sort=updated&direction=desc&per_page=100&page="+strconv.Itoa(page))
		if err != nil {
			return nil, err
		}
		var ps []pull
		if err := json.Unmarshal(raw, &ps); err != nil {
			return nil, fmt.Errorf("unparseable response: %w", err)
		}
		for i := range ps {
			if ps[i].MergedAt != nil && !ps[i].MergedAt.Before(start) {
				out = append(out, ps[i])
			}
		}
		if len(ps) < 100 || ps[len(ps)-1].UpdatedAt.Before(start) {
			return out, nil
		}
	}
	return nil, fmt.Errorf("more than %d pages of closed pull requests", maxPullPages)
}

// redIssues searches for the red-on-main issues opened since start.
func redIssues(ctx context.Context, c client, start time.Time) ([]issue, error) {
	q := fmt.Sprintf(`repo:%s is:issue in:title "is red" created:>=%s`, c.repo, start.Format(time.DateOnly))
	raw, err := c.gh.run(ctx, "api", "--paginate", "search/issues?per_page=100&q="+url.QueryEscape(q))
	if err != nil {
		return nil, err
	}
	ps, err := decodePages[struct {
		Items []issue `json:"items"`
	}](raw)
	if err != nil {
		return nil, err
	}
	var out []issue
	for _, p := range ps {
		out = append(out, p.Items...)
	}
	return out, nil
}

// costAll costs the chosen PRs, o.workers at a time. A PR that hits an API
// error, or that would start with fewer than o.reserve requests left, is
// left out of the CI cost, never the whole report.
func costAll(ctx context.Context, c client, chosen []pull, o options, log *printer) (map[int]map[string]float64, []skipped) {
	costs := map[int]map[string]float64{}
	var notCosted []skipped
	var mu sync.Mutex
	work := make(chan pull)
	var wg sync.WaitGroup
	for range o.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range work {
				cost, reason := costPR(ctx, c, p, o)
				mu.Lock()
				if reason != "" {
					notCosted = append(notCosted, skipped{PR: p.Number, Reason: reason})
					log.printf("#%d not costed: %s\n", p.Number, reason)
				} else {
					costs[p.Number] = cost
				}
				mu.Unlock()
			}
		}()
	}
	for i := range chosen {
		work <- chosen[i]
	}
	close(work)
	wg.Wait()
	sort.Slice(notCosted, func(i, j int) bool { return notCosted[i].PR < notCosted[j].PR })
	return costs, notCosted
}

type runsPage struct {
	WorkflowRuns []workflowRun `json:"workflow_runs"`
}

type checksPage struct {
	CheckRuns []checkRun `json:"check_runs"`
}

// costPR is the CI seconds per phase of p, or why it was not costed.
func costPR(ctx context.Context, c client, p pull, o options) (cost map[string]float64, reason string) {
	left, err := remaining(ctx, c)
	if err != nil {
		return nil, "API error: " + err.Error()
	}
	if left < o.reserve {
		return nil, fmt.Sprintf("API reserve: %d requests left", left)
	}
	prRuns, err := pages[runsPage](ctx, c, "actions/runs?branch="+url.QueryEscape(p.Head.Ref)+"&event=pull_request&per_page=100")
	if err != nil {
		return nil, "API error: " + err.Error()
	}
	mainRuns, err := pages[runsPage](ctx, c, "actions/runs?head_sha="+p.MergeCommitSHA+"&event=push&per_page=100")
	if err != nil {
		return nil, "API error: " + err.Error()
	}
	var runs []workflowRun
	for _, pg := range append(prRuns, mainRuns...) {
		runs = append(runs, pg.WorkflowRuns...)
	}
	var checks []checkRun
	for _, sha := range commitsToCost(p, runs) {
		ps, err := pages[checksPage](ctx, c, "commits/"+sha+"/check-runs?filter=all&per_page=100")
		if err != nil {
			return nil, "API error: " + err.Error()
		}
		for _, pg := range ps {
			checks = append(checks, pg.CheckRuns...)
		}
	}
	return ciSeconds(p, runs, checks, o.branch), ""
}
