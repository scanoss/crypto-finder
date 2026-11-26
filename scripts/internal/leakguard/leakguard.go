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

// Package leakguard keeps internal names, people's home paths and private
// ruleset content out of this public repository and its pull requests.
//
// The denylist (denylist.txt) holds only SHA-256 hashes, so it does not reveal
// the names it denies. A text is lowercased and split into tokens on every
// character that is not an ASCII letter or digit. A "loose" entry is the hash
// of a name's tokens joined with nothing between them, and matches any run of
// up to MaxTokens adjacent tokens on one line that joins to it: "a-b", "a_b",
// "a.b", "a/b", "a b" and "AB" all match the entry of "a-b". An "exact" entry
// is the hash of the lowercased name as written, and matches only that
// spelling (still case-insensitive): it scopes a name whose words also occur
// legitimately in public prose or code.
//
// Findings name the place and the category, never the matched text.
package leakguard

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	_ "embed" // denylist.txt
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// MaxTokens is the most tokens a denied name may have.
const MaxTokens = 4

//go:embed denylist.txt
var defaultDenylist string

// Denylist maps the hashes of denied names to their category.
type Denylist struct {
	loose, exact map[string]string
}

// Default returns the repository's embedded denylist.
func Default() (*Denylist, error) {
	return ParseDenylist(defaultDenylist)
}

// ParseDenylist reads lines of "<category> <loose|exact> <sha256 hex>".
// Blank lines and lines starting with # are ignored.
func ParseDenylist(text string) (*Denylist, error) {
	d := &Denylist{loose: map[string]string{}, exact: map[string]string{}}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			return nil, fmt.Errorf("leakguard: denylist line %d: want \"<category> <loose|exact> <sha256>\"", i+1)
		}
		if b, err := hex.DecodeString(f[2]); err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("leakguard: denylist line %d: not a SHA-256 hex digest", i+1)
		}
		switch f[1] {
		case "loose":
			d.loose[f[2]] = f[0]
		case "exact":
			d.exact[f[2]] = f[0]
		default:
			return nil, fmt.Errorf("leakguard: denylist line %d: kind %q is not loose or exact", i+1, f[1])
		}
	}
	return d, nil
}

// Hash returns the denylist hash of name: loose (separator-insensitive) or
// exact (the lowercased spelling).
func Hash(name string, exact bool) (string, error) {
	lower := strings.ToLower(strings.TrimSpace(name))
	toks := tokens(lower)
	if len(toks) == 0 {
		return "", errors.New("leakguard: the name has no letters or digits")
	}
	if len(toks) > MaxTokens {
		return "", fmt.Errorf("leakguard: the name has %d tokens; at most %d match", len(toks), MaxTokens)
	}
	if exact {
		return sum(lower[toks[0].start:toks[len(toks)-1].end]), nil
	}
	var b strings.Builder
	for _, t := range toks {
		b.WriteString(lower[t.start:t.end])
	}
	return sum(b.String()), nil
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

type span struct{ start, end int }

// tokens returns the runs of ASCII letters and digits of an already
// lowercased s.
func tokens(s string) []span {
	var out []span
	start := -1
	for i := 0; i <= len(s); i++ {
		alnum := i < len(s) && (s[i] >= 'a' && s[i] <= 'z' || s[i] >= '0' && s[i] <= '9')
		switch {
		case alnum && start < 0:
			start = i
		case !alnum && start >= 0:
			out = append(out, span{start, i})
			start = -1
		}
	}
	return out
}

// Finding is one place that must not land.
type Finding struct {
	Where string // a repository path, "PR body", "PR title" or "commit <sha>"
	Line  int    // 1-based; 0 when the finding is about the whole file
	What  string
}

func (f Finding) String() string {
	if f.Line == 0 {
		return f.Where + ": " + f.What
	}
	return f.Where + ":" + strconv.Itoa(f.Line) + ": " + f.What
}

// Guard scans text against a denylist.
type Guard struct{ names *Denylist }

// New returns a Guard for d.
func New(d *Denylist) *Guard { return &Guard{names: d} }

// homePath matches an absolute home directory and captures the user name.
var homePath = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.~$-])/(?:home|Users)/([A-Za-z0-9_][A-Za-z0-9._-]*)/`)

// syntheticUsers are the invented home directories that tests, docs and
// container images already use; none of them is a person.
var syntheticUsers = map[string]bool{
	"u": true, "user": true, "crypto": true, "dev": true, "tester": true, "runner": true, "example": true,
}

// scanLine returns the findings of one line, at most one per category.
func (g *Guard) scanLine(where string, n int, line string) []Finding {
	var out []Finding
	if cat, ok := g.nameIn(strings.ToLower(line)); ok {
		out = append(out, Finding{where, n, "internal name (" + cat + ")"})
	}
	for _, m := range homePath.FindAllStringSubmatch(line, -1) {
		if !syntheticUsers[strings.ToLower(m[1])] {
			out = append(out, Finding{where, n, "absolute home path"})
			break
		}
	}
	return out
}

// nameIn reports the category of the first denied name in a lowercased line.
func (g *Guard) nameIn(lower string) (string, bool) {
	toks := tokens(lower)
	var joined strings.Builder
	for i := range toks {
		joined.Reset()
		for j := i; j < len(toks) && j < i+MaxTokens; j++ {
			joined.WriteString(lower[toks[j].start:toks[j].end])
			if cat, ok := g.names.loose[sum(joined.String())]; ok {
				return cat, true
			}
			if len(g.names.exact) > 0 {
				if cat, ok := g.names.exact[sum(lower[toks[i].start:toks[j].end])]; ok {
					return cat, true
				}
			}
		}
	}
	return "", false
}

// ScanText scans every line of a free text such as a PR title or body.
func (g *Guard) ScanText(where, text string) []Finding {
	lines := strings.Split(text, "\n")
	out := make([]Finding, 0, len(lines))
	for i, line := range lines {
		out = append(out, g.scanLine(where, i+1, line)...)
	}
	return out
}

// ScanFile scans every line of a repository file; skipped paths and binary
// content give nothing.
func (g *Guard) ScanFile(name string, content []byte) []Finding {
	if Skipped(name) || bytes.IndexByte(content, 0) >= 0 {
		return nil
	}
	var out []Finding
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for n := 1; sc.Scan(); n++ {
		out = append(out, g.scanLine(name, n, sc.Text())...)
	}
	return out
}

// Skipped reports whether a path holds generated content that is not scanned:
// checksums in go.sum can spell a short name by chance.
func Skipped(name string) bool {
	return path.Base(name) == "go.sum"
}

// hunk matches a unified diff hunk header and captures the new start line.
var hunk = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// ScanDiff scans the added lines of a unified diff (`git diff -U0`).
func (g *Guard) ScanDiff(diff string) []Finding {
	var out []Finding
	file, n := "", 0
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			file = ""
		case strings.HasPrefix(line, "+++ "):
			file = newPath(strings.TrimPrefix(line, "+++ "))
		case strings.HasPrefix(line, "@@ "):
			if m := hunk.FindStringSubmatch(line); m != nil {
				if start, err := strconv.Atoi(m[1]); err == nil {
					n = start
				}
			}
		case strings.HasPrefix(line, "+"):
			if file != "" && !Skipped(file) {
				out = append(out, g.scanLine(file, n, line[1:])...)
			}
			n++
		}
	}
	return out
}

// newPath turns the "+++" side of a diff header into a repository path, or ""
// for a deleted file.
func newPath(p string) string {
	if p == "/dev/null" {
		return ""
	}
	if uq, err := strconv.Unquote(p); err == nil {
		p = uq
	}
	return strings.TrimPrefix(p, "b/")
}

// OverrideMarker is the comment that, on any line of a YAML file, records that a
// reviewer checked its rules are invented, and turns the ruleset check off for
// that file.
const OverrideMarker = "leakguard: invented-rules"

// cdxFields are CycloneDX crypto fields a detection rule's metadata carries.
var cdxFields = []string{"assetType", "algorithmFamily", "primitive", "cryptoFunctions"}

// CheckRuleset flags a YAML file outside testdata that looks like a detection
// ruleset: a top-level rules list with an entry whose metadata holds a crypto
// block of CycloneDX fields. Testdata (a path with a testdata segment) holds
// invented rules and is never flagged; neither is a file with OverrideMarker.
func CheckRuleset(name string, content []byte) *Finding {
	ext := path.Ext(name)
	if ext != ".yaml" && ext != ".yml" {
		return nil
	}
	if strings.HasPrefix(name, "testdata/") || strings.Contains(name, "/testdata/") {
		return nil
	}
	if bytes.Contains(content, []byte(OverrideMarker)) {
		return nil
	}
	var doc struct {
		Rules []struct {
			Metadata struct {
				Crypto map[string]any `yaml:"crypto"`
			} `yaml:"metadata"`
		} `yaml:"rules"`
	}
	if yaml.Unmarshal(content, &doc) != nil {
		return nil
	}
	for _, r := range doc.Rules {
		for _, f := range cdxFields {
			if _, ok := r.Metadata.Crypto[f]; ok {
				return &Finding{Where: name, What: "looks like private ruleset content (rules with crypto metadata)"}
			}
		}
	}
	return nil
}
