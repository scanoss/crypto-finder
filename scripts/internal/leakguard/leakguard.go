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
// the names it denies. A text is split into tokens on every character that is
// not an ASCII letter or digit, and where a lowercase letter meets an uppercase
// one, then lowercased. A "loose" entry is the hash
// of a name's tokens joined with nothing between them, and matches any run of
// up to MaxTokens adjacent tokens on one line that joins to it: "foo-bar",
// "foo_bar", "foo.bar", "foo/bar", "foo bar", "FooBar" and "newFooBarClient"
// all match the entry of "foo-bar". An "exact" entry is the hash of the lowercased name as written, and matches only that
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
	"io"
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
	lower := asciiLower(strings.TrimSpace(name))
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

// tokens returns the runs of ASCII letters and digits of s, also split where
// a lowercase letter meets an uppercase one, so "newFooBar" gives new, Foo,
// Bar. Offsets index s and asciiLower(s) alike.
func tokens(s string) []span {
	var out []span
	start := -1
	for i := 0; i <= len(s); i++ {
		alnum := i < len(s) && isAlnum(s[i])
		camel := alnum && start >= 0 && isUpper(s[i]) && isLower(s[i-1])
		switch {
		case camel:
			out = append(out, span{start, i})
			start = i
		case alnum && start < 0:
			start = i
		case !alnum && start >= 0:
			out = append(out, span{start, i})
			start = -1
		}
	}
	return out
}

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isAlnum(c byte) bool { return isUpper(c) || isLower(c) || c >= '0' && c <= '9' }

// asciiLower lowercases ASCII letters only, so byte offsets do not move.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if isUpper(c) {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
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
var homePath = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.~$-])/(?:home|Users)/([A-Za-z0-9_][A-Za-z0-9._-]*)(?:[^A-Za-z0-9._-]|$)`)

// syntheticUsers are the invented home directories that tests and docs use
// and the stock users of common images and CI runners; none of them is a person.
var syntheticUsers = map[string]bool{
	"u": true, "user": true, "crypto": true, "dev": true, "tester": true, "example": true,
	"runner": true, "nonroot": true, "node": true, "vscode": true, "ubuntu": true, "debian": true,
	"ec2-user": true, "app": true, "linuxbrew": true,
}

// scanLine returns the findings of one line, at most one per category.
func (g *Guard) scanLine(where string, n int, line string) []Finding {
	var out []Finding
	if cat, ok := g.nameIn(line); ok {
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

// nameIn reports the category of the first denied name in a line.
func (g *Guard) nameIn(line string) (string, bool) {
	toks, lower := tokens(line), asciiLower(line)
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
	header := false // between "diff --git" and the file's first hunk
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			file, header = "", true
		case header && strings.HasPrefix(line, "+++ "):
			file = newPath(strings.TrimPrefix(line, "+++ "))
		case strings.HasPrefix(line, "@@ "):
			header = false
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

// CheckRuleset flags a YAML file that looks like a detection ruleset: a
// top-level rules list with an entry whose metadata holds a crypto block of
// CycloneDX fields. Testdata is not exempt, since real rule fixtures must not
// land there either: a file of invented rules carries OverrideMarker.
func CheckRuleset(name string, content []byte) *Finding {
	ext := path.Ext(name)
	if ext != ".yaml" && ext != ".yml" {
		return nil
	}
	if bytes.Contains(content, []byte(OverrideMarker)) {
		return nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(content))
	for {
		var doc any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			// A guard does not let what it cannot read through: an unparseable
			// file that names rules and a CycloneDX field is flagged.
			if bytes.Contains(content, []byte("rules:")) && anyField(content) {
				return rulesetFinding(name)
			}
			return nil
		}
		if hasCryptoRule(doc) {
			return rulesetFinding(name)
		}
	}
}

func rulesetFinding(name string) *Finding {
	return &Finding{Where: name, What: "looks like private ruleset content (rules with crypto metadata)"}
}

func anyField(content []byte) bool {
	for _, f := range cdxFields {
		if bytes.Contains(content, []byte(f)) {
			return true
		}
	}
	return false
}

// hasCryptoRule reports whether a decoded YAML document has a top-level rules
// list with an entry whose metadata.crypto holds a CycloneDX field. Entries of
// another shape are skipped, so one malformed rule hides none of the others.
func hasCryptoRule(doc any) bool {
	rules, ok := asMap(doc)["rules"].([]any)
	if !ok {
		return false
	}
	for _, r := range rules {
		crypto := asMap(asMap(asMap(r)["metadata"])["crypto"])
		for _, f := range cdxFields {
			if _, ok := crypto[f]; ok {
				return true
			}
		}
	}
	return false
}

// asMap returns v as a mapping, or nil (which reads as empty) for any other
// shape.
func asMap(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return m
}
