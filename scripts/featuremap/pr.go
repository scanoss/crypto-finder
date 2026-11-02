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
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const evidenceHeader = "## Evidence"

// ignored are the paths that never touch a feature, whatever a glob says: tests
// and their fixtures. The repository has no generated Go code today; add its
// pattern here (for example "**/*.pb.go") when some lands.
var ignored = []string{
	"**/*_test.go",
	"**/testdata/**",
}

func isIgnored(name string) bool {
	return anyGlob(ignored, name)
}

// anyGlob reports whether name matches one of globs.
func anyGlob(globs []string, name string) bool {
	for _, g := range globs {
		if matchGlob(g, name) {
			return true
		}
	}
	return false
}

// touched maps each feature id to the changed files its globs match, ignoring
// tests and fixtures. Features no file touches are absent.
func touched(features []feature, changed []string) map[string][]string {
	out := map[string][]string{}
	for _, name := range changed {
		if isIgnored(name) {
			continue
		}
		for _, f := range features {
			if anyGlob(f.globs, name) {
				out[f.id] = append(out[f.id], name)
			}
		}
	}
	return out
}

// parseNameStatus reads `git diff --name-status -z` output into the set of
// changed paths, sorted. A rename or a copy contributes its old and its new path,
// so moving a file out of a feature's globs still touches that feature.
func parseNameStatus(raw string) ([]string, error) {
	fields := strings.Split(strings.TrimSuffix(raw, "\x00"), "\x00")
	seen := map[string]bool{}
	for i := 0; i < len(fields); {
		status := fields[i]
		if status == "" {
			break
		}
		n := 1
		if status[0] == 'R' || status[0] == 'C' {
			n = 2
		}
		if i+n >= len(fields) {
			return nil, fmt.Errorf("truncated name-status entry %q", status)
		}
		for _, p := range fields[i+1 : i+1+n] {
			seen[p] = true
		}
		i += 1 + n
	}
	return sortedKeys(seen), nil
}

// htmlCommentRe matches an HTML comment, which GitHub does not render. The PR
// template's guidance lives in comments, so it never names a feature.
var htmlCommentRe = regexp.MustCompile(`(?s)<!--.*?-->`)

// evidenceLines returns the lines under the first "## Evidence" heading, up to
// the next H1 or H2 heading outside a code fence, and whether the heading exists.
func evidenceLines(body string) ([]string, bool) {
	body = htmlCommentRe.ReplaceAllString(strings.ReplaceAll(body, "\r\n", "\n"), "")
	var out []string
	in, found, inFence := false, false, false
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
		}
		heading := !inFence && (strings.HasPrefix(line, "# ") || strings.HasPrefix(line, "## "))
		switch {
		case heading && !found && strings.TrimSpace(line) == evidenceHeader:
			in, found = true, true
		case heading:
			in = false
		case in:
			out = append(out, line)
		}
	}
	return out, found
}

// naming is how the Evidence section names one feature.
type naming int

const (
	notNamed      naming = iota // the id never appears as a whole token
	bare                        // the id appears with nothing after it
	naNoReason                  // "<id>: N/A" with no reason
	withEvidence                // "<id>: <link or evidence>"
	notApplicable               // "<id>: N/A: <reason>"
)

// idChars are the characters of a feature id. An id is named only when the
// characters around it are not id characters, so "reachability-dependencies"
// does not name "reachability" and "scan" does not name "scanner".
const idChars = `A-Za-z0-9_-`

// filler is what may surround an id without being evidence: list markers,
// Markdown emphasis and code ticks, and separators.
const filler = " \t`*_:;,.|-]()"

// classify reports how the Evidence lines name id. The best line wins.
func classify(lines []string, id string) naming {
	re := regexp.MustCompile(`(?:^|[^` + idChars + `])` + regexp.QuoteMeta(id) + `(?:$|[^` + idChars + `])`)
	best := notNamed
	for _, line := range lines {
		for _, loc := range re.FindAllStringIndex(line, -1) {
			after := line[loc[0]:]
			after = after[strings.Index(after, id)+len(id):]
			best = max(best, classifyRest(after))
		}
	}
	return best
}

// classifyRest classifies the text that follows an id on its line.
func classifyRest(rest string) naming {
	rest = strings.TrimLeft(rest, filler)
	if na, ok := cutPrefixFold(rest, "N/A"); ok {
		reason, ok := strings.CutPrefix(strings.TrimLeft(na, " \t"), ":")
		if ok && strings.Trim(reason, filler) != "" {
			return notApplicable
		}
		return naNoReason
	}
	if strings.Trim(rest, filler) == "" {
		return bare
	}
	return withEvidence
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return s, false
}

// checkPR lists one problem per touched feature that the body does not name
// with evidence or a reasoned N/A, and the ids it accepted.
func checkPR(features []feature, changed []string, body string) (problems, accepted []string) {
	hits := touched(features, changed)
	lines, found := evidenceLines(body)
	for _, id := range sortedKeys(hits) {
		files := strings.Join(hits[id], ", ")
		switch classify(lines, id) {
		case withEvidence, notApplicable:
			accepted = append(accepted, id)
		case notNamed:
			problems = append(problems, fmt.Sprintf("%s: not named (touched by %s)", id, files))
		case bare:
			problems = append(problems, fmt.Sprintf("%s: named without evidence: write %q or %q (touched by %s)", id, id+": <link or evidence>", id+": N/A: <reason>", files))
		case naNoReason:
			problems = append(problems, fmt.Sprintf("%s: N/A needs a reason: write %q (touched by %s)", id, id+": N/A: <reason>", files))
		}
	}
	if len(problems) > 0 && !found {
		problems = append([]string{"the PR body has no " + evidenceHeader + " heading"}, problems...)
	}
	sort.Strings(accepted)
	return problems, accepted
}
