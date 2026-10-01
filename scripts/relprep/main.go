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

// Command relprep folds the per-change changelog and user-guide fragments into
// the shared documents at release time. Pull requests add one small file each
// instead of editing CHANGELOG.md or the single-line coverage paragraph of the
// user guide, so two pull requests never touch the same lines.
//
// Usage (from the repository root):
//
//	go run ./scripts/relprep check
//	go run ./scripts/relprep changelog -version 0.28.0 [-date 2026-10-01] [-dry-run]
//	go run ./scripts/relprep guide [-dry-run]
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	changelogFile    = "CHANGELOG.md"
	changelogDir     = "changelog.d"
	guideFile        = "docs/user-guide/user-guide.html"
	guideFragmentDir = "docs/user-guide/coverage.d"
	guideBegin       = "<!-- coverage-fragments:begin -->"
	guideEnd         = "<!-- coverage-fragments:end -->"
	unreleasedHeader = "## [Unreleased]"
)

// sectionOrder is the Keep a Changelog order. Sections found in an existing
// [Unreleased] block that are not listed here are kept after these.
var sectionOrder = []string{"Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "relprep:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: relprep check | changelog -version X.Y.Z | guide")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	version := fs.String("version", "", "release version, for changelog")
	date := fs.String("date", time.Now().UTC().Format("2006-01-02"), "release date, for changelog")
	dry := fs.Bool("dry-run", false, "print the result and change nothing")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "check":
		return check(*root)
	case "changelog":
		if *version == "" {
			return fmt.Errorf("changelog needs -version")
		}
		return releaseChangelog(*root, strings.TrimPrefix(*version, "v"), *date, *dry)
	case "guide":
		return foldGuide(*root, *dry)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// fragment is one file read from a fragment directory.
type fragment struct {
	path    string
	section string // changelog section, empty for guide fragments
	body    string
}

// readChangelogFragments returns the changelog fragments sorted by file name.
// A fragment is named <slug>.<section>.md, with <section> one of
// added, changed, deprecated, removed, fixed or security.
func readChangelogFragments(root string) ([]fragment, error) {
	entries, err := os.ReadDir(filepath.Join(root, changelogDir))
	if err != nil {
		return nil, err
	}
	var out []fragment
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == "README.md" || strings.HasPrefix(name, ".") {
			continue
		}
		stem, ok := strings.CutSuffix(name, ".md")
		if !ok {
			return nil, fmt.Errorf("%s/%s: fragment files end in .md", changelogDir, name)
		}
		dot := strings.LastIndex(stem, ".")
		if dot <= 0 {
			return nil, fmt.Errorf("%s/%s: name must be <slug>.<section>.md", changelogDir, name)
		}
		section := canonicalSection(stem[dot+1:])
		if section == "" {
			return nil, fmt.Errorf("%s/%s: section %q must be one of added, changed, deprecated, removed, fixed, security", changelogDir, name, stem[dot+1:])
		}
		raw, err := os.ReadFile(filepath.Join(root, changelogDir, name)) //nolint:gosec // maintainer CLI; paths come from the repo root flag
		if err != nil {
			return nil, err
		}
		body := strings.TrimSpace(string(raw))
		if !strings.HasPrefix(body, "- ") {
			return nil, fmt.Errorf("%s/%s: must start with a \"- \" bullet", changelogDir, name)
		}
		if strings.Contains(body, "\n#") {
			return nil, fmt.Errorf("%s/%s: must hold bullets only, no headings", changelogDir, name)
		}
		out = append(out, fragment{path: filepath.Join(changelogDir, name), section: section, body: body})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, nil
}

func canonicalSection(s string) string {
	for _, name := range sectionOrder {
		if strings.EqualFold(s, name) {
			return name
		}
	}
	return ""
}

// readGuideFragments returns the user-guide fragments sorted by file name.
// Each file holds exactly one <p>...</p> paragraph.
func readGuideFragments(root string) ([]fragment, error) {
	entries, err := os.ReadDir(filepath.Join(root, guideFragmentDir))
	if err != nil {
		return nil, err
	}
	var out []fragment
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == "README.md" || strings.HasPrefix(name, ".") {
			continue
		}
		if !strings.HasSuffix(name, ".html") {
			return nil, fmt.Errorf("%s/%s: fragment files end in .html", guideFragmentDir, name)
		}
		raw, err := os.ReadFile(filepath.Join(root, guideFragmentDir, name)) //nolint:gosec // maintainer CLI; paths come from the repo root flag
		if err != nil {
			return nil, err
		}
		body := strings.TrimSpace(string(raw))
		if !strings.HasPrefix(body, "<p>") || !strings.HasSuffix(body, "</p>") ||
			strings.Count(body, "<p>") != 1 || strings.Contains(body, "\n") {
			return nil, fmt.Errorf("%s/%s: must be exactly one <p>...</p> paragraph on a single line", guideFragmentDir, name)
		}
		out = append(out, fragment{path: filepath.Join(guideFragmentDir, name), body: body})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, nil
}

func check(root string) error {
	if _, err := readChangelogFragments(root); err != nil {
		return err
	}
	if _, err := readGuideFragments(root); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(root, guideFile)) //nolint:gosec // maintainer CLI; paths come from the repo root flag
	if err != nil {
		return err
	}
	if _, _, _, err := splitGuide(string(raw)); err != nil {
		return err
	}
	doc, err := os.ReadFile(filepath.Join(root, changelogFile)) //nolint:gosec // maintainer CLI; paths come from the repo root flag
	if err != nil {
		return err
	}
	_, _, _, err = splitUnreleased(string(doc))
	return err
}

// section is one "### Name" block with its body lines.
type section struct {
	name  string
	lines []string
}

// splitUnreleased cuts the [Unreleased] block out of the changelog. It returns
// the text before the block, the text from the next release heading on, and
// the block's sections.
func splitUnreleased(doc string) (head, tail string, sections []section, err error) {
	lines := strings.Split(doc, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == unreleasedHeader {
			start = i
			break
		}
	}
	if start < 0 {
		return "", "", nil, fmt.Errorf("%s: no %q heading", changelogFile, unreleasedHeader)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "## [") {
			end = i
			break
		}
	}
	var cur *section
	for _, l := range lines[start+1 : end] {
		if name, ok := strings.CutPrefix(l, "### "); ok {
			sections = append(sections, section{name: strings.TrimSpace(name)})
			cur = &sections[len(sections)-1]
			continue
		}
		if cur == nil {
			if strings.TrimSpace(l) != "" {
				return "", "", nil, fmt.Errorf("%s: text under [Unreleased] before the first ### heading", changelogFile)
			}
			continue
		}
		cur.lines = append(cur.lines, l)
	}
	return strings.Join(lines[:start], "\n"), strings.Join(lines[end:], "\n"), sections, nil
}

// buildRelease merges the existing [Unreleased] sections with the fragments:
// existing bullets first, then fragments in file-name order.
func buildRelease(existing []section, frags []fragment) string {
	byName := map[string][]string{}
	var extra []string
	for _, s := range existing {
		body := strings.TrimSpace(strings.Join(s.lines, "\n"))
		if body == "" {
			continue
		}
		if canonicalSection(s.name) == "" {
			extra = append(extra, s.name)
		}
		byName[s.name] = append(byName[s.name], body)
	}
	for _, f := range frags {
		byName[f.section] = append(byName[f.section], f.body)
	}
	var b strings.Builder
	for _, name := range append(append([]string{}, sectionOrder...), extra...) {
		if len(byName[name]) == 0 {
			continue
		}
		b.WriteString("### " + name + "\n")
		b.WriteString(strings.Join(byName[name], "\n") + "\n")
	}
	return b.String()
}

func releaseChangelog(root, version, date string, dry bool) error {
	path := filepath.Join(root, changelogFile)
	raw, err := os.ReadFile(path) //nolint:gosec // maintainer CLI; paths come from the repo root flag
	if err != nil {
		return err
	}
	head, tail, existing, err := splitUnreleased(string(raw))
	if err != nil {
		return err
	}
	frags, err := readChangelogFragments(root)
	if err != nil {
		return err
	}
	body := buildRelease(existing, frags)
	if body == "" {
		return fmt.Errorf("nothing to release: [Unreleased] is empty and %s has no fragments", changelogDir)
	}
	release := fmt.Sprintf("## [%s] - %s\n%s", version, date, body)
	if dry {
		fmt.Print(release)
		return nil
	}
	var out bytes.Buffer
	out.WriteString(head + "\n" + unreleasedHeader + "\n\n" + release)
	if tail != "" {
		out.WriteString("\n" + tail)
	}
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil { //nolint:gosec // documents stay world-readable
		return err
	}
	for _, f := range frags {
		if err := os.Remove(filepath.Join(root, f.path)); err != nil { //nolint:gosec // maintainer CLI; paths come from the repo root flag
			return err
		}
	}
	return nil
}

// splitGuide cuts the guide at the fragment markers.
func splitGuide(doc string) (before, block, after string, err error) {
	b := strings.Index(doc, guideBegin)
	e := strings.Index(doc, guideEnd)
	if b < 0 || e < b || strings.Count(doc, guideBegin) != 1 || strings.Count(doc, guideEnd) != 1 {
		return "", "", "", fmt.Errorf("%s: need exactly one %s ... %s marker pair", guideFile, guideBegin, guideEnd)
	}
	return doc[:b], doc[b+len(guideBegin) : e], doc[e:], nil
}

func foldGuide(root string, dry bool) error {
	path := filepath.Join(root, guideFile)
	raw, err := os.ReadFile(path) //nolint:gosec // maintainer CLI; paths come from the repo root flag
	if err != nil {
		return err
	}
	before, block, after, err := splitGuide(string(raw))
	if err != nil {
		return err
	}
	frags, err := readGuideFragments(root)
	if err != nil {
		return err
	}
	if len(frags) == 0 {
		return fmt.Errorf("nothing to fold: %s has no fragments", guideFragmentDir)
	}
	var b strings.Builder
	b.WriteString(before + guideBegin + strings.TrimRight(block, "\n") + "\n")
	for _, f := range frags {
		b.WriteString(f.body + "\n")
	}
	b.WriteString(after)
	if dry {
		fmt.Print(b.String())
		return nil
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil { //nolint:gosec // documents stay world-readable
		return err
	}
	for _, f := range frags {
		if err := os.Remove(filepath.Join(root, f.path)); err != nil { //nolint:gosec // maintainer CLI; paths come from the repo root flag
			return err
		}
	}
	return nil
}
