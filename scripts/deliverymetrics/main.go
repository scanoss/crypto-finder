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

// Command deliverymetrics measures, per week, whether the delivery
// guardrails pay off: cost per PR and revert rate. It only reads; all GitHub
// access goes through the gh CLI.
//
// Usage (from the repository root):
//
//	go run ./scripts/deliverymetrics [--weeks 4] [--until 2026-11-02] [--sample 8] [--reserve 300] [--json] [--repo owner/name]
//
// Each week (Monday to Monday, UTC; the current week is partial) of the last
// --weeks weeks, and of as many weeks before them for comparison, gets:
//
//   - merged PRs into main;
//   - CI minutes per PR: the job time of every pull_request run on the PR's
//     branch between opening and merge, plus the push runs on its merge
//     commit, split as "<workflow> (PR)" and "<workflow> (main)". Jobs are
//     each commit's check runs, one call per commit rather than per run. A PR
//     still takes about six calls, so only --sample PRs a week, evenly spaced
//     by number, are costed, and costing stops while fewer than --reserve
//     requests are left, so the other workflows keep their share;
//   - QA turns, tokens and Claude Code's own cost estimate per PR, from the
//     usage marker post-merge-qa.yml hides in its PR comment. The seat bills
//     nothing per run, so the estimate is a signal, not an invoice, and a run
//     without usage or without an estimate is never shown as $0;
//   - revert rate: merged PRs later reverted on main, and the hours to it;
//   - red main: "Test & Coverage is red on main" and "Nightly e2e is red"
//     issues opened, and merge-audit comments on PRs merged before green.
//
// The default output is markdown tables; --json prints the same rows.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// callTimeout bounds every gh call, a paginated one included.
const callTimeout = 2 * time.Minute

// gh runs the gh CLI. Tests replace it with recorded responses.
type gh interface {
	run(ctx context.Context, args ...string) ([]byte, error)
}

type ghCLI struct{}

func (ghCLI) run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	// #nosec G204 -- exec.CommandContext is used without a shell and with fixed arguments.
	cmd := exec.CommandContext(ctx, "gh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if ctx.Err() != nil {
			msg = "timed out after " + callTimeout.String()
		}
		return nil, fmt.Errorf("gh %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	return stdout.Bytes(), nil
}

// decodePages decodes the output of gh api --paginate, which writes one JSON
// value per page back to back.
func decodePages[T any](raw []byte) ([]T, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var pages []T
	for {
		var page T
		err := dec.Decode(&page)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("unparseable response: %w", err)
		}
		pages = append(pages, page)
	}
	if len(pages) == 0 {
		return nil, errors.New("empty response")
	}
	return pages, nil
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], time.Now(), os.Stdout, os.Stderr, ghCLI{}))
}

// printer writes output and keeps the first write error.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, a...)
	}
}

// run measures and prints the report, and returns the exit code: 0, 1 when
// the measuring failed, 2 on bad usage.
func run(ctx context.Context, args []string, now time.Time, stdoutW, stderrW io.Writer, g gh) int {
	stdout, stderr := &printer{w: stdoutW}, &printer{w: stderrW}
	fs := flag.NewFlagSet("deliverymetrics", flag.ContinueOnError)
	fs.SetOutput(stderrW)
	o := options{}
	fs.IntVar(&o.weeks, "weeks", 4, "weeks per window; the comparison window before it is as long")
	until := fs.String("until", "", "a day (YYYY-MM-DD) in the last week; defaults to today, UTC")
	fs.IntVar(&o.sample, "sample", 8, "PRs costed per week (0: all)")
	fs.IntVar(&o.reserve, "reserve", 300, "API requests left untouched for the other workflows")
	fs.IntVar(&o.workers, "workers", 4, "PRs costed at once")
	fs.StringVar(&o.branch, "branch", "main", "the default branch")
	repo := fs.String("repo", "", "owner/name; defaults to the repository of the current directory")
	asJSON := fs.Bool("json", false, "print JSON instead of markdown")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 || o.weeks < 1 || o.sample < 0 || o.reserve < 0 || o.workers < 1 {
		stderr.printf("usage: deliverymetrics [--weeks N] [--until YYYY-MM-DD] [--sample N] [--reserve N] [--json] [--repo o/r]\n")
		return 2
	}
	o.until = now.UTC()
	if *until != "" {
		t, err := time.Parse(time.DateOnly, *until)
		if err != nil {
			stderr.printf("--until: %v\n", err)
			return 2
		}
		o.until = t
	}
	c, err := newClient(ctx, g, *repo)
	if err != nil {
		stderr.printf("deliverymetrics: %v\n", err)
		return 1
	}
	r, err := measure(ctx, c, o, stderr)
	if err != nil {
		stderr.printf("deliverymetrics: %v\n", err)
		return 1
	}
	if *asJSON {
		out, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			stderr.printf("deliverymetrics: %v\n", err)
			return 1
		}
		stdout.printf("%s\n", out)
	} else {
		stdout.printf("%s", markdown(r))
	}
	if stdout.err != nil || stderr.err != nil {
		return 1
	}
	return 0
}

// newClient binds g to repo, or to the repository of the current directory.
func newClient(ctx context.Context, g gh, repo string) (client, error) {
	if repo != "" {
		return client{gh: g, repo: repo}, nil
	}
	raw, err := g.run(ctx, "repo", "view", "--json", "nameWithOwner")
	if err != nil {
		return client{}, fmt.Errorf("cannot tell the repository: %w", err)
	}
	var v struct {
		NameWithOwner string `json:"nameWithOwner"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.NameWithOwner == "" {
		return client{}, fmt.Errorf("cannot tell the repository from %q", raw)
	}
	return client{gh: g, repo: v.NameWithOwner}, nil
}
