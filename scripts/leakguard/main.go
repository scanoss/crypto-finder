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

// Command leakguard maintains and runs the internal-name guard
// (scripts/internal/leakguard). Pull requests are checked by
// `go run ./scripts/featuremap check-pr`.
//
// Usage (from the repository root):
//
//	go run ./scripts/leakguard hash [--exact] [--category C] <name>
//	go run ./scripts/leakguard scan-tree [--rev HEAD]
//
// hash prints the denylist line for name: append it to
// scripts/internal/leakguard/denylist.txt. The name itself is never stored.
// Pass the name on stdin with "-" to keep it out of the shell history.
// --exact matches only that spelling (case-insensitive); use it when the
// name's words also occur legitimately in public code or prose.
//
// scan-tree scans every file of the tree at rev, whole, as a pull request adding
// it would be scanned, and lists every finding. Run it after adding a name: a
// name that already occurs legitimately must be scoped with --exact or dropped.
//
// Exit codes: 0 clean, 1 findings, 2 usage error.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/scanoss/crypto-finder/scripts/internal/leakguard"
)

const usage = "usage: leakguard hash [--exact] [--category C] <name|-> | scan-tree [--rev REV]"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
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
		_, p.err = fmt.Fprintf(p.w, format, a...) // #nosec G705 -- plain text to a terminal or a CI log
	}
}

// run runs one subcommand; output that could not be written turns a success
// into a failure.
func run(args []string, stdin io.Reader, stdoutW, stderrW io.Writer) int {
	stdout, stderr := &printer{w: stdoutW}, &printer{w: stderrW}
	code := dispatch(args, stdin, stdout, stderr)
	if code == 0 && (stdout.err != nil || stderr.err != nil) {
		return 1
	}
	return code
}

func dispatch(args []string, stdin io.Reader, stdout, stderr *printer) int {
	if len(args) == 0 {
		stderr.println(usage)
		return 2
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(stderr.w)
	exact := fs.Bool("exact", false, "match only this spelling, for hash")
	category := fs.String("category", "name", "category the finding names, for hash")
	rev := fs.String("rev", "HEAD", "tree to scan, for scan-tree")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	switch args[0] {
	case "hash":
		if fs.NArg() != 1 || strings.ContainsAny(*category, " \t") {
			stderr.println(usage)
			return 2
		}
		return runHash(fs.Arg(0), *exact, *category, stdin, stdout, stderr)
	case "scan-tree":
		return runScanTree(*rev, stdout, stderr)
	default:
		stderr.println(usage)
		return 2
	}
}

func runHash(name string, exact bool, category string, stdin io.Reader, stdout, stderr *printer) int {
	if name == "-" {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			stderr.println("leakguard:", err)
			return 1
		}
		name = line
	}
	h, err := leakguard.Hash(name, exact)
	if err != nil {
		stderr.println(err)
		return 2
	}
	kind := "loose"
	if exact {
		kind = "exact"
	}
	stdout.println(category, kind, h)
	return 0
}

func runScanTree(rev string, stdout, stderr *printer) int {
	d, err := leakguard.Default()
	if err != nil {
		stderr.println(err)
		return 1
	}
	g := leakguard.New(d)
	list, err := git("ls-tree", "-r", "-z", "--name-only", rev)
	if err != nil {
		stderr.println("leakguard:", err)
		return 1
	}
	var findings []leakguard.Finding
	files := strings.Split(strings.TrimSuffix(list, "\x00"), "\x00")
	for _, name := range files {
		content, err := git("show", rev+":"+name)
		if err != nil {
			stderr.println("leakguard:", err)
			return 1
		}
		findings = append(findings, g.ScanFile(name, []byte(content))...)
		if f := leakguard.CheckRuleset(name, []byte(content)); f != nil {
			findings = append(findings, *f)
		}
	}
	for _, f := range findings {
		stdout.println(f)
	}
	if len(findings) > 0 {
		stdout.printf("leakguard: %d finding(s) in %d files at %s\n", len(findings), len(files), rev)
		return 1
	}
	stdout.printf("leakguard: %d files at %s are clean\n", len(files), rev)
	return 0
}

func git(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var errBuf strings.Builder
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Stderr = &errBuf
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(errBuf.String()))
	}
	return string(out), nil
}
