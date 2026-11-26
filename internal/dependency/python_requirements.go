// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: GPL-2.0-only

package dependency

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/scanoss/reach/purl"

	"github.com/scanoss/crypto-finder/internal/utils"
)

// pyRequirementsEntry is one requirement line of a requirements file, with
// the pip-tools "# via" annotation that follows it.
type pyRequirementsEntry struct {
	req  pyRequirement
	file string
	// via names the distributions that require it; viaManifest is set when
	// the annotation names an input file (-r requirements.in), which makes
	// the requirement the project's own.
	via         []string
	viaManifest bool
}

// pyDevRequirementsName matches a requirements file named for development
// (requirements-dev.txt, requirements/test.txt, dev-requirements.txt).
var pyDevRequirementsName = regexp.MustCompile(`(?i)(^|[-_.])(dev|develop|test|tests|testing|doc|docs|lint|ci|typing|mypy)([-_.]|$)`)

// pyRequirementsFiles lists dir's requirements files: requirements.txt when
// there is one (with what it includes), else every requirements*.txt and
// requirements/*.txt that is not named for development.
func pyRequirementsFiles(dir string) []string {
	if fileExists(filepath.Join(dir, "requirements.txt")) {
		return []string{filepath.Join(dir, "requirements.txt")}
	}
	var out []string
	for _, pattern := range []string{"requirements*.txt", filepath.Join("requirements", "*.txt")} {
		matches := utils.Lenient(filepath.Glob(filepath.Join(dir, pattern)))
		for _, m := range matches {
			if !pyDevRequirementsName.MatchString(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(m), "requirements"), ".txt")) && fileExists(m) {
				out = append(out, m)
			}
		}
	}
	slices.Sort(out)
	return out
}

// readRequirementsFiles parses files and the files they include (-r),
// once each. Constraint files (-c) install nothing and are not read;
// editable and local path lines are the project's own code.
func readRequirementsFiles(dir string, files []string) []pyRequirementsEntry {
	seen := map[string]bool{}
	var out []pyRequirementsEntry
	var read func(path string)
	read = func(path string) {
		path = filepath.Clean(path)
		if seen[path] {
			return
		}
		seen[path] = true
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			rel = path
		}
		entries, includes := parseRequirementsFile(data, filepath.ToSlash(rel))
		out = append(out, entries...)
		for _, inc := range includes {
			if !filepath.IsAbs(inc) {
				inc = filepath.Join(filepath.Dir(path), inc)
			}
			read(inc)
		}
	}
	for _, f := range files {
		read(f)
	}
	return out
}

// parseRequirementsFile reads one requirements file: its requirements, each
// with its pip-tools annotation, and the files it includes.
func parseRequirementsFile(data []byte, file string) ([]pyRequirementsEntry, []string) { //nolint:gocognit,gocyclo // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	var entries []pyRequirementsEntry
	var includes []string
	inVia := false
	addVia := func(names string) {
		if len(entries) == 0 {
			return
		}
		last := &entries[len(entries)-1]
		for _, name := range strings.FieldsFunc(names, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			switch {
			case name == "-r" || name == "-c" || strings.HasPrefix(name, "-r") || strings.HasPrefix(name, "-c"):
				last.viaManifest = true
			case strings.HasSuffix(name, ".in") || strings.HasSuffix(name, ".txt") || strings.HasSuffix(name, ".toml") || strings.Contains(name, "/") || name == "setup.py" || name == "setup.cfg":
				last.viaManifest = true
			default:
				last.via = addSorted(last.via, purl.PyPIName(name))
			}
		}
	}
	for _, line := range requirementsLines(data) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			comment := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
			if rest, ok := strings.CutPrefix(comment, "via"); ok && (rest == "" || rest[0] == ' ') {
				inVia = strings.TrimSpace(rest) == ""
				addVia(rest)
			} else if inVia && strings.HasPrefix(trimmed, "#   ") {
				addVia(comment)
			} else {
				inVia = false
			}
			continue
		}
		inVia = false
		body, comment, _ := strings.Cut(line, " #")
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		if strings.HasPrefix(body, "-") {
			if inc, ok := requirementsInclude(body); ok {
				includes = append(includes, inc)
			}
			continue
		}
		if strings.HasPrefix(body, ".") || strings.HasPrefix(body, "/") {
			continue
		}
		if i := strings.Index(body, " --"); i >= 0 {
			body = body[:i]
		}
		req, ok := parsePyRequirement(body)
		if !ok {
			continue
		}
		entries = append(entries, pyRequirementsEntry{req: req, file: file})
		if rest, ok := strings.CutPrefix(strings.TrimSpace(comment), "via "); ok {
			addVia(rest)
		}
	}
	return entries, includes
}

// requirementsLines splits data into logical lines: a line ending in a
// backslash continues on the next.
func requirementsLines(data []byte) []string {
	var lines []string
	var current strings.Builder
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasSuffix(line, "\\") {
			current.WriteString(strings.TrimSuffix(line, "\\"))
			current.WriteString(" ")
			continue
		}
		current.WriteString(line)
		lines = append(lines, current.String())
		current.Reset()
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
}

// requirementsInclude returns the file an option line includes (-r FILE,
// --requirement FILE, --requirement=FILE).
func requirementsInclude(body string) (string, bool) {
	for _, opt := range []string{"--requirement", "-r"} {
		rest, ok := strings.CutPrefix(body, opt)
		if !ok {
			continue
		}
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
		if rest != "" && (rest[0] != '-' || opt == "-r") {
			return strings.Fields(rest)[0], true
		}
	}
	return "", false
}

// readPinnedRequirements reads dir's requirements files when every
// requirement in them is pinned with == (pip freeze, pip-compile output with
// or without hashes). pip-compile's "# via" annotations give the edges and
// the direct requirements; without them every line is direct. It reports
// false when there is no requirements file or one requirement is not pinned.
func readPinnedRequirements(dir string) (*pyGraph, bool) {
	files := pyRequirementsFiles(dir)
	entries := readRequirementsFiles(dir, files)
	if len(entries) == 0 {
		return nil, false
	}
	g := newPyGraph(filepath.ToSlash(relOr(dir, files[0])))
	keys := make([]string, len(entries))
	for i, e := range entries {
		version, ok := pinnedPyVersion(e.req.Specifier)
		if !ok || e.req.URL != "" {
			return nil, false
		}
		n := g.add(e.req.Name, version)
		n.extras = addSorted(n.extras, e.req.Extras...)
		keys[i] = n.ref.Key()
	}
	for i, e := range entries {
		for _, parent := range e.via {
			for _, from := range g.named(parent) {
				g.link(from, keys[i], "")
			}
		}
		if e.viaManifest || len(e.via) == 0 {
			g.declare(keys[i], e.req.Marker)
		}
	}
	// A marker on a requirement line is the entry's own: pip installs the
	// line only where it holds, whichever way it is reached.
	for i, e := range entries {
		g.nodes[keys[i]].markers = addSorted(g.nodes[keys[i]].markers, e.req.Marker)
	}
	g.directKnown = true
	return g, true
}

// declaredRequirementsFiles is dir's requirements files as declared
// requirements, for the declared-only tier.
func declaredRequirementsFiles(dir string) []pyDeclared {
	entries := readRequirementsFiles(dir, pyRequirementsFiles(dir))
	if len(entries) == 0 {
		return nil
	}
	out := make([]pyDeclared, 0, len(entries))
	for _, e := range entries {
		out = append(out, pyDeclared{req: e.req, manifest: e.file})
	}
	return out
}

func relOr(dir, path string) string {
	if rel, err := filepath.Rel(dir, path); err == nil {
		return rel
	}
	return path
}
