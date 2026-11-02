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

// Command mergeready is the merge gate of this repository, which has no branch
// protection. It judges whether a pull request is ready to merge, blocks an
// agent's merge command when it is not, and audits every merge on main after
// the fact. All GitHub access goes through the gh CLI.
//
// Usage (from the repository root):
//
//	go run ./scripts/mergeready check --pr 12 [--repo owner/name]
//	go run ./scripts/mergeready audit --sha <merge commit> [--repo owner/name] [--comment]
//	go run ./scripts/mergeready hook < event.json
//
// check exits 0 when the pull request is ready and 1 with one reason per line
// when it is not. audit exits 0 whatever it finds; the comment it posts with
// --comment is the signal. hook is a Claude Code PreToolUse hook: it exits 2,
// which blocks the tool call, when a Bash command merges a pull request that
// is not ready or that it cannot identify.
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

// callTimeout bounds every gh call. The hook's own budget is 90 s, which also
// pays for compiling this command, so one slow call must not use it up.
const callTimeout = 15 * time.Second

// statusCompleted is the status of a finished check or workflow run.
const statusCompleted = "completed"

// gh runs the gh CLI. Tests replace it with recorded responses.
type gh interface {
	run(ctx context.Context, dir string, args ...string) ([]byte, error)
}

type ghCLI struct{}

func (ghCLI) run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gh", args...)
	cmd.Dir = dir
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

// client is the gh CLI bound to one repository.
type client struct {
	gh   gh
	repo string // owner/name
}

// get fetches a REST path of the repository, following every page.
func (c client) get(ctx context.Context, path string) ([]byte, error) {
	return c.gh.run(ctx, "", "api", "--paginate", "repos/"+c.repo+"/"+path)
}

// decodePages decodes the output of gh api --paginate, which writes one JSON
// value per page back to back. Empty or unparseable output is an error.
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
	os.Exit(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, ghCLI{}))
}

// printer writes output and keeps the first write error.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) println(a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintln(p.w, a...)
	}
}

func (p *printer) printf(format string, a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, a...) //nolint:gosec // G705: plain text to a terminal or a CI log, not a web page
	}
}

// run runs one subcommand and returns its exit code. Output that could not be
// written turns a success into a failure.
func run(ctx context.Context, args []string, stdin io.Reader, stdoutW, stderrW io.Writer, g gh) int {
	stdout, stderr := &printer{w: stdoutW}, &printer{w: stderrW}
	code := dispatch(ctx, args, stdin, stdout, stderr, g)
	if code == 0 && (stdout.err != nil || stderr.err != nil) {
		return 1
	}
	return code
}

func dispatch(ctx context.Context, args []string, stdin io.Reader, stdout, stderr *printer, g gh) int {
	const usage = "usage: mergeready check --pr N [--repo o/r] | audit --sha SHA [--repo o/r] [--comment] | hook"
	if len(args) == 0 {
		stderr.println(usage)
		return 2
	}
	if args[0] == "hook" {
		return runHook(ctx, stdin, stderr, g)
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(stderr.w)
	pr := fs.Int("pr", 0, "pull request number, for check")
	sha := fs.String("sha", "", "merge commit, for audit")
	repo := fs.String("repo", "", "owner/name; defaults to the repository of the current directory")
	comment := fs.Bool("comment", false, "audit: comment on a pull request that merged early")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	switch args[0] {
	case "check":
		if *pr <= 0 {
			stderr.println("check needs --pr")
			return 2
		}
		c, err := newClient(ctx, g, *repo)
		if err != nil {
			stdout.println("not ready:", err)
			return 1
		}
		reasons := checkPR(ctx, c, *pr)
		return report(stdout, c.repo, *pr, reasons)
	case "audit":
		if *sha == "" {
			stderr.println("audit needs --sha")
			return 2
		}
		c, err := newClient(ctx, g, *repo)
		if err != nil {
			stdout.println("audit: cannot judge the merge:", err)
			return 0
		}
		audit(ctx, c, *sha, *comment, stdout)
		return 0
	default:
		stderr.println(usage)
		return 2
	}
}

// newClient binds g to repo, or to the repository of the current directory.
func newClient(ctx context.Context, g gh, repo string) (client, error) {
	if repo != "" {
		return client{gh: g, repo: repo}, nil
	}
	raw, err := g.run(ctx, "", "repo", "view", "--json", "nameWithOwner")
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

func report(w *printer, repo string, pr int, reasons []string) int {
	if len(reasons) == 0 {
		w.printf("%s#%d is ready to merge\n", repo, pr)
		return 0
	}
	w.printf("%s#%d is not ready to merge:\n", repo, pr)
	for _, r := range reasons {
		w.println("- " + r)
	}
	return 1
}
