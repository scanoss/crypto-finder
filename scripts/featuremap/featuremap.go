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
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
)

// featureDir is where the feature map lives, relative to the repository root.
const featureDir = ".claude/skills/verify/features"

const (
	indexFile       = "README.md"
	codePathsHeader = "Code paths"
	featuresHeader  = "Features"
)

// requiredSections are the H2 sections of a feature file, in order. An entry
// ending in "..." is matched as a prefix.
var requiredSections = []string{
	"Sub-features",
	"How to get to it (user POV)",
	"Driving it with ...",
	"Gotchas",
	codePathsHeader,
}

// feature is one features/<id>.md file.
type feature struct {
	id       string
	sections []string // H2 titles, in file order
	globs    []string // the backticked paths in the list items of Code paths
}

// globRe finds a backticked path in a list item.
var globRe = regexp.MustCompile("`([^`]+)`")

// parseFeature reads the H2 sections and the Code paths globs of a feature file.
// Headings inside fenced code blocks are not sections.
func parseFeature(id, body string) feature {
	f := feature{id: id}
	var current string
	inFence := false
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if title, ok := strings.CutPrefix(line, "## "); ok {
			current = strings.TrimSpace(title)
			f.sections = append(f.sections, current)
			continue
		}
		if current != codePathsHeader {
			continue
		}
		item, ok := strings.CutPrefix(strings.TrimSpace(line), "- ")
		if !ok {
			continue
		}
		for _, m := range globRe.FindAllStringSubmatch(item, -1) {
			f.globs = append(f.globs, m[1])
		}
	}
	return f
}

// loadFeatures reads every feature file (every *.md except the index) of fsys,
// sorted by id.
func loadFeatures(fsys fs.FS) ([]feature, error) {
	names, err := fs.Glob(fsys, "*.md")
	if err != nil {
		return nil, fmt.Errorf("list features: %w", err)
	}
	var out []feature
	for _, name := range names {
		if name == indexFile {
			continue
		}
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("read feature: %w", err)
		}
		out = append(out, parseFeature(strings.TrimSuffix(name, ".md"), string(raw)))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out, nil
}

// matchGlob reports whether a repository-relative file path matches a glob, with
// git pathspec glob semantics: the glob is anchored at the repository root, "*"
// and "?" and "[...]" match within one path segment (they never cross "/"), a
// "**" segment matches zero or more whole segments ("a/**" is everything under
// a, "**/x.go" is x.go in any directory). A malformed glob matches nothing.
func matchGlob(glob, name string) bool {
	return matchSegments(strings.Split(glob, "/"), strings.Split(name, "/"))
}

func matchSegments(glob, name []string) bool {
	for len(glob) > 0 {
		if glob[0] == "**" {
			for i := 0; i <= len(name); i++ {
				if matchSegments(glob[1:], name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		if ok, err := path.Match(glob[0], name[0]); err != nil || !ok {
			return false
		}
		glob, name = glob[1:], name[1:]
	}
	return len(name) == 0
}

// validGlob reports whether every segment of a glob is a well-formed pattern.
func validGlob(glob string) bool {
	if glob == "" || strings.HasPrefix(glob, "/") {
		return false
	}
	for _, seg := range strings.Split(glob, "/") {
		if _, err := path.Match(seg, ""); err != nil {
			return false
		}
	}
	return true
}

// sectionMatches reports whether an H2 title satisfies a required section.
func sectionMatches(want, got string) bool {
	if prefix, ok := strings.CutSuffix(want, "..."); ok {
		return strings.HasPrefix(got, prefix)
	}
	return got == want
}

// checkFeature lists the problems of one feature file against the tracked files.
func checkFeature(f feature, tracked []string) []string {
	var problems []string
	file := f.id + ".md"
	for _, want := range requiredSections {
		found := false
		for _, got := range f.sections {
			found = found || sectionMatches(want, got)
		}
		if !found {
			problems = append(problems, fmt.Sprintf("%s: missing section %q", file, "## "+want))
		}
	}
	if len(problems) == 0 && !sectionsInOrder(f.sections) {
		problems = append(problems, fmt.Sprintf("%s: sections are %q, want exactly %q in that order", file, f.sections, requiredSections))
	}
	if len(f.globs) == 0 {
		problems = append(problems, fmt.Sprintf("%s: %q lists no backticked glob", file, "## "+codePathsHeader))
	}
	for _, g := range f.globs {
		if !validGlob(g) {
			problems = append(problems, fmt.Sprintf("%s: malformed glob %q", file, g))
			continue
		}
		if !matchesAny(g, tracked) {
			problems = append(problems, fmt.Sprintf("%s: glob %q matches no tracked file", file, g))
		}
	}
	return problems
}

func sectionsInOrder(got []string) bool {
	if len(got) != len(requiredSections) {
		return false
	}
	for i, want := range requiredSections {
		if !sectionMatches(want, got[i]) {
			return false
		}
	}
	return true
}

func matchesAny(glob string, files []string) bool {
	for _, f := range files {
		if matchGlob(glob, f) {
			return true
		}
	}
	return false
}

// indexLinkRe finds a link to a sibling feature file: [x](./x.md) or [x](x.md).
var indexLinkRe = regexp.MustCompile(`\]\((?:\./)?([^)/#\s]+)\.md\)`)

// indexedIDs returns the feature ids that the Features section of the index links to.
func indexedIDs(readme string) map[string]bool {
	ids := map[string]bool{}
	inFeatures := false
	for _, line := range strings.Split(strings.ReplaceAll(readme, "\r\n", "\n"), "\n") {
		if title, ok := strings.CutPrefix(line, "## "); ok {
			inFeatures = strings.TrimSpace(title) == featuresHeader
			continue
		}
		if !inFeatures {
			continue
		}
		for _, m := range indexLinkRe.FindAllStringSubmatch(line, -1) {
			ids[m[1]] = true
		}
	}
	return ids
}

// checkDocs lists every problem of the feature map in fsys: per-file sections
// and globs, and an index that must list every feature file and nothing else.
func checkDocs(fsys fs.FS, tracked []string) ([]string, error) {
	features, err := loadFeatures(fsys)
	if err != nil {
		return nil, err
	}
	var problems []string
	if len(features) == 0 {
		problems = append(problems, "no feature files")
	}
	for _, f := range features {
		problems = append(problems, checkFeature(f, tracked)...)
	}
	readme, err := fs.ReadFile(fsys, indexFile)
	if err != nil {
		return append(problems, indexFile+": missing"), nil //nolint:nilerr // a missing index is a reported problem, not a failure to run
	}
	indexed := indexedIDs(string(readme))
	for _, f := range features {
		if !indexed[f.id] {
			problems = append(problems, fmt.Sprintf("%s: %q does not link %s.md", indexFile, "## "+featuresHeader, f.id))
		}
		delete(indexed, f.id)
	}
	for _, id := range sortedKeys(indexed) {
		problems = append(problems, fmt.Sprintf("%s: links %s.md, which is not a feature file", indexFile, id))
	}
	return problems, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
