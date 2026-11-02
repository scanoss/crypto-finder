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
	"fmt"
	"strconv"
	"strings"
	"time"
)

// auditMarker is hidden in the audit comment so a pull request gets one.
const auditMarker = "<!-- merge-audit -->"

type mergedPull struct {
	Number         int    `json:"number"`
	MergedAt       string `json:"merged_at"`
	MergeCommitSHA string `json:"merge_commit_sha"`
	Head           struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

// audit judges the pull request merged as sha as it stood at merge time and,
// with comment, tells it when it merged before its checks were green.
func audit(ctx context.Context, c client, sha string, comment bool, w *printer) {
	pages, err := fetch[[]mergedPull](ctx, c, "commits/"+sha+"/pulls?per_page=100")
	if err != nil {
		w.printf("audit %s: cannot find the pull request: %v\n", sha, err)
		return
	}
	var found []mergedPull
	for _, p := range pages {
		for _, pr := range p {
			if pr.MergeCommitSHA == sha && pr.MergedAt != "" {
				found = append(found, pr)
			}
		}
	}
	if len(found) == 0 {
		w.printf("audit %s: no pull request was merged as this commit (a direct push?)\n", sha)
		return
	}
	for _, pr := range found {
		reasons := judgeAtMerge(ctx, c, pr)
		if len(reasons) == 0 {
			w.printf("audit %s: #%d merged with every check green\n", sha, pr.Number)
			continue
		}
		w.printf("audit %s: #%d merged before it was ready:\n", sha, pr.Number)
		for _, r := range reasons {
			w.println("- " + r)
		}
		if comment {
			w.println(postAuditComment(ctx, c, pr, reasons))
		}
	}
}

// judgeAtMerge returns why pr was not green when it merged: every check run
// and commit status on its head must have finished green by merged_at.
func judgeAtMerge(ctx context.Context, c client, pr mergedPull) []string {
	mergedAt, err := time.Parse(time.RFC3339, pr.MergedAt)
	if err != nil {
		return []string{fmt.Sprintf("cannot read merged_at %q", pr.MergedAt)}
	}
	var reasons []string
	runs, err := fetchCheckRuns(ctx, c, pr.Head.SHA)
	if err != nil {
		reasons = append(reasons, "cannot read the check runs: "+err.Error())
	} else if len(runs) == 0 {
		reasons = append(reasons, "there were no check runs on the head commit")
	}
	for _, r := range runs {
		switch {
		case r.Status != statusCompleted:
			reasons = append(reasons, fmt.Sprintf("check %q has still not finished", r.Name))
		case !greenConclusion[r.Conclusion]:
			reasons = append(reasons, fmt.Sprintf("check %q finished with %s", r.Name, r.Conclusion))
		case after(r.CompletedAt, mergedAt):
			reasons = append(reasons, fmt.Sprintf("check %q finished at %s, after the merge at %s", r.Name, r.CompletedAt, pr.MergedAt))
		}
	}
	statuses, err := fetchStatuses(ctx, c, pr.Head.SHA)
	if err != nil {
		reasons = append(reasons, "cannot read the commit statuses: "+err.Error())
	}
	for _, s := range statuses {
		switch {
		case s.State != "success":
			reasons = append(reasons, fmt.Sprintf("status %q is %s", s.Context, s.State))
		case after(s.UpdatedAt, mergedAt):
			reasons = append(reasons, fmt.Sprintf("status %q finished at %s, after the merge at %s", s.Context, s.UpdatedAt, pr.MergedAt))
		}
	}
	return reasons
}

// after reports whether stamp is later than t; an unreadable stamp counts.
func after(stamp string, t time.Time) bool {
	at, err := time.Parse(time.RFC3339, stamp)
	return err != nil || at.After(t)
}

// postAuditComment comments once on pr and says what it did.
func postAuditComment(ctx context.Context, c client, pr mergedPull, reasons []string) string {
	number := strconv.Itoa(pr.Number)
	pages, err := fetch[[]struct {
		Body string `json:"body"`
	}](ctx, c, "issues/"+number+"/comments?per_page=100")
	if err != nil {
		return "cannot read the comments, not commenting: " + err.Error()
	}
	for _, p := range pages {
		for _, cm := range p {
			if strings.Contains(cm.Body, auditMarker) {
				return "already commented on #" + number
			}
		}
	}
	var body strings.Builder
	body.WriteString(auditMarker + "\n")
	body.WriteString("**Merge audit:** this pull request merged before every check on its head commit `" +
		pr.Head.SHA + "` was green.\n\n")
	for _, r := range reasons {
		body.WriteString("- " + r + "\n")
	}
	body.WriteString("\nCheck `main` for the change, and run `go run ./scripts/mergeready check --pr <n>` before merging.\n")
	if _, err := c.gh.run(ctx, "", "api", "--method", "POST", "repos/"+c.repo+"/issues/"+number+"/comments",
		"-f", "body="+body.String()); err != nil {
		return "cannot comment on #" + number + ": " + err.Error()
	}
	return "commented on #" + number
}
