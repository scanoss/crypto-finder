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

// Package cards is a prototype detector that finds crypto by looking up the
// call sites of a call graph in a card index, with no rule engine. It is a
// scanner.Scanner, so the scan pipeline runs it for the project and for
// every dependency exactly where it runs OpenGrep, and everything after
// detection is untouched.
//
// The Scanner interface hands a scanner a directory, not call sites. The
// detector therefore asks for the directory's graph fragment through a
// function the command supplies (BuildFragment), matches the cards against
// it and reports the findings as scanner results, which the shared
// transformer turns into the interim report.
package cards

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/scanoss/reach/graphfrag"
	"github.com/scanoss/reach/perf"
	"go.yaml.in/yaml/v3"

	"github.com/scanoss/crypto-finder/internal/cardmatch"
	"github.com/scanoss/crypto-finder/internal/entities"
	"github.com/scanoss/crypto-finder/internal/rules"
	"github.com/scanoss/crypto-finder/internal/scanner"
)

// ScannerName names this detector.
const ScannerName = "cards"

// BuildFragment returns the graph fragment of the source tree at dir: its
// functions and call sites, with no crypto annotations.
type BuildFragment func(dir string) (graphfrag.GraphFragmentExport, error)

// Options is what the detector needs besides the scan target.
type Options struct {
	// IndexPath and CardsDir override where the compiled index and the hand
	// cards come from. By default the index is compiled from the Java rules
	// of the scan's ruleset and the cards are its cards/ directory, so a
	// served (watermarked) ruleset is matched exactly as it was served.
	IndexPath, CardsDir string
	// RulesDir overrides the scan's ruleset directory. Findings take their
	// rule id, message, severity, purl and metadata.crypto from its rules.
	RulesDir string
	// Ruleset returns the scan's ruleset directories as the rules source
	// loaded them: a --rules-dir, or the leased ruleset's run directory.
	// Scan's rule paths are the copy filtered for OpenGrep, without cards/.
	Ruleset func() ([]string, error)
	// Fragment builds the call sites of one scanned directory.
	Fragment BuildFragment
	// Catalogs, when set, holds the loaded index, cards and rule metadata
	// for every factory given it: an offline scan mines each dependency with
	// its own factory, and loads the ruleset once.
	Catalogs *Catalogs
	// Language is the language whose rules (compiled into the index) and
	// cards are matched: the Name of a language of the table (languages.go).
	Language string
	// Also lists the target's further languages, each matched with its own
	// rules and cards against its own call graph: a target holding Java
	// and Python source is scanned for both. Their findings join the
	// report of Language's, in the same order and deduplication.
	Also []AlsoLanguage
}

// AlsoLanguage is one further language of a scan and the builder of its
// call sites.
type AlsoLanguage struct {
	Language string
	Fragment BuildFragment
}

// language is the language of the options' rules and cards.
func (o Options) language() string {
	return o.Language
}

// Catalogs is a store of loaded rulesets several factories share.
type Catalogs struct {
	cache *catalogCache
}

// NewCatalogs returns an empty store.
func NewCatalogs() *Catalogs {
	return &Catalogs{cache: &catalogCache{byRoot: make(map[string]*catalogEntry)}}
}

// rule is the part of a rule a finding repeats.
type rule struct {
	// CheckID is the id OpenGrep reports the rule under.
	CheckID  string `yaml:"-"`
	ID       string `yaml:"id"`
	Message  string `yaml:"message"`
	Severity string `yaml:"severity"`
	// Languages are the languages the rule names (none for a card file's
	// rule).
	Languages []string `yaml:"languages"`
	Metadata  struct {
		PURL string `yaml:"purl"`
	} `yaml:"metadata"`
}

// sameMetadata: the rules report the same metadata (a card file's rule
// names no language).
func sameMetadata(a, b rule) bool {
	return a.CheckID == b.CheckID && a.ID == b.ID && a.Message == b.Message && a.Severity == b.Severity && a.Metadata == b.Metadata
}

// names: the rule applies to lang's targets: it names lang or one of its
// aliases, or names no language (a card file's rule).
func (r rule) names(lang Language) bool {
	if len(r.Languages) == 0 {
		return true
	}
	for _, l := range r.Languages {
		if Canonical(l) == lang.Name {
			return true
		}
	}
	return false
}

// catalog is loaded once per command and shared by every scanner instance.
type catalog struct {
	assets *cardmatch.Assets
}

// Scanner is the cards detector.
type Scanner struct {
	opts         Options
	catalogs     *catalogCache
	disableDedup bool
}

// NewScannerFactory returns the registry constructor. The index, the cards
// and the rule metadata are loaded on the first scan and shared afterwards.
func NewScannerFactory(opts Options) func() scanner.Scanner {
	catalogs := &catalogCache{byRoot: make(map[string]*catalogEntry)}
	if opts.Catalogs != nil {
		catalogs = opts.Catalogs.cache
	}
	return func() scanner.Scanner {
		return &Scanner{opts: opts, catalogs: catalogs}
	}
}

// catalogCache loads one catalog per ruleset directory, once, for every
// scanner the factory makes (the target and each dependency scan).
type catalogCache struct {
	mu     sync.Mutex
	byRoot map[string]*catalogEntry
	// byPaths holds the rule metadata per set of rule paths Scan is given.
	byPaths map[string]map[string]rule
}

func (c *catalogCache) rules(rulePaths []string) (map[string]rule, error) {
	key := strings.Join(rulePaths, "\x00")
	c.mu.Lock()
	defer c.mu.Unlock()
	if found, ok := c.byPaths[key]; ok {
		return found, nil
	}
	found, err := ruleMetadata(rulePaths)
	if err != nil {
		return nil, err
	}
	if c.byPaths == nil {
		c.byPaths = make(map[string]map[string]rule)
	}
	c.byPaths[key] = found
	return found, nil
}

type catalogEntry struct {
	once    sync.Once
	catalog *catalog
	err     error
}

func (c *catalogCache) get(opts Options, root string) (*catalog, error) {
	key := opts.language() + "\x00" + root
	c.mu.Lock()
	entry := c.byRoot[key]
	if entry == nil {
		entry = &catalogEntry{}
		c.byRoot[key] = entry
	}
	c.mu.Unlock()
	entry.once.Do(func() {
		defer perf.Start("cards.load").End()
		entry.catalog, entry.err = loadCatalog(opts, root)
	})
	return entry.catalog, entry.err
}

// rulesetLayout locates, in a ruleset directory, the rules of language the
// index is compiled from and the hand cards. A release tarball holds
// semgrep-rules/ and cards/, each with a directory per language; a rules
// checkout's semgrep-rules/ or one language's rule directory is the rules
// itself. The cards are cards/<language>/; a cards/ with no language
// directory at all holds the cards of the one language scanned.
func rulesetLayout(root, language string) (rulesDir, cardsDir string) {
	rulesDir = root
	for _, candidate := range []string{filepath.Join(root, "semgrep-rules", language), filepath.Join(root, language)} {
		if isDir(candidate) {
			rulesDir = candidate
			break
		}
	}
	cards := filepath.Join(root, "cards")
	if own := filepath.Join(cards, language); isDir(own) {
		return rulesDir, own
	}
	for _, other := range directoryNames() {
		if isDir(filepath.Join(cards, other)) {
			return rulesDir, "" // other languages' cards only
		}
	}
	if isDir(cards) {
		cardsDir = cards
	}
	return rulesDir, cardsDir
}

// matchCatalogs matches the scanned language's catalog, then the catalogs of
// the languages whose rules also apply. own is how many findings come from
// the first; sites is the number of call sites it looked at.
func matchCatalogs(primary *catalog, shared []*catalog, frag *cardmatch.FragmentJSON) (findings []*cardmatch.Finding, own, sites int, err error) {
	findings, sites, err = primary.assets.Match(frag)
	if err != nil {
		return nil, 0, 0, err
	}
	own = len(findings)
	for _, c := range shared {
		more, _, err := c.assets.Match(frag)
		if err != nil {
			return nil, 0, 0, err
		}
		findings = append(findings, more...)
	}
	return findings, own, sites, nil
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func loadCatalog(opts Options, root string) (*catalog, error) {
	rulesDir, cardsDir := rulesetLayout(root, opts.language())
	if opts.CardsDir != "" {
		cardsDir = opts.CardsDir
	}
	assets, err := cardmatch.Load(opts.IndexPath, cardsDir, rulesDir)
	if err != nil {
		return nil, fmt.Errorf("load cards: %w", err)
	}
	if err := cardmatch.SaveMemo(); err != nil {
		log.Debug().Err(err).Msg("Failed to save the parsed card files for the next scan")
	}
	return &catalog{assets: assets}, nil
}

// ruleMetadata reads the rules a finding is reported under from the rule
// paths the scan hands the detector, the same files OpenGrep would be given,
// so a rule keeps the id OpenGrep would report it under. The paths may be a
// filtered copy that merges rule files into one and writes each rule's
// directory into its id, so a rule is found by the id the matcher knows it
// by, which ends its check id.
func ruleMetadata(rulePaths []string) (map[string]rule, error) {
	var all []rule
	for _, path := range rulePaths {
		found, err := loadRules(path)
		if err != nil {
			return nil, fmt.Errorf("load rule metadata: %w", err)
		}
		all = append(all, found...)
	}
	// A suffix two check ids share goes to the shorter one: the rule whose
	// own id it is carries only its directory in front of it.
	sort.SliceStable(all, func(i, j int) bool {
		if len(all[i].CheckID) != len(all[j].CheckID) {
			return len(all[i].CheckID) < len(all[j].CheckID)
		}
		return all[i].CheckID < all[j].CheckID
	})
	byID := make(map[string]rule, len(all))
	for _, r := range all {
		for id := r.CheckID; ; {
			if _, seen := byID[id]; !seen {
				byID[id] = r
			}
			dot := strings.IndexByte(id, '.')
			if dot < 0 {
				break
			}
			id = id[dot+1:]
		}
	}
	return byID, nil
}

// loadRules reads the rules of the rule files (YAML, or the rules: blocks of v3 card files)
// at or under dir.
func loadRules(dir string) ([]rule, error) { //nolint:gocognit,gocyclo // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	var all []rule
	base := dir
	if info, err := os.Stat(dir); err == nil && !info.IsDir() {
		// A rule file given by itself: OpenGrep prefixes no directory.
		base = filepath.Dir(dir)
	}
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		var found []rule
		switch {
		case rules.IsCardsFile(path):
			cardRules, err := rules.ReadCardsRulesFile(path)
			if errors.Is(err, rules.ErrNotV3Cards) {
				return nil // an earlier card file carries no rules
			}
			if err != nil {
				return err
			}
			found = make([]rule, len(cardRules))
			for i, r := range cardRules {
				found[i] = rule{ID: r.ID, Message: r.Message, Severity: r.Severity}
				found[i].Metadata.PURL = r.PURL
			}
		case filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml":
			data, err := os.ReadFile(path) // #nosec G304 -- a rule file under the rules directory the user named.
			if err != nil {
				return err
			}
			var doc struct {
				Rules []rule `yaml:"rules"`
			}
			if err := yaml.Unmarshal(data, &doc); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			found = doc.Rules
		default:
			return nil
		}
		// OpenGrep names a rule by its file's directory below the rules
		// root joined to its id, and that name is the rule id of a finding.
		rel, err := filepath.Rel(base, filepath.Dir(path))
		if err != nil {
			return err
		}
		prefix := ""
		if rel != "." {
			prefix = strings.ReplaceAll(filepath.ToSlash(rel), "/", ".") + "."
		}
		for i := range found {
			found[i].CheckID = prefix + found[i].ID
			all = append(all, found[i])
		}
		return nil
	})
	return all, err
}

// rulesetRoot is the one ruleset directory the catalog is loaded from.
func (s *Scanner) rulesetRoot() (string, error) {
	if s.opts.RulesDir != "" {
		return s.opts.RulesDir, nil
	}
	if s.opts.Ruleset == nil {
		return "", fmt.Errorf("the cards scanner has no ruleset")
	}
	dirs, err := s.opts.Ruleset()
	if err != nil {
		return "", err
	}
	if len(dirs) != 1 {
		return "", fmt.Errorf("the cards scanner needs one ruleset directory, got %d", len(dirs))
	}
	return dirs[0], nil
}

// Initialize checks the options. There is no executable to probe.
func (s *Scanner) Initialize(_ context.Context, config scanner.Config) error {
	if err := checkLanguage(s.opts.Language); err != nil {
		return err
	}
	if s.opts.Fragment == nil {
		return fmt.Errorf("the cards scanner needs a call graph builder")
	}
	for _, also := range s.opts.Also {
		if err := checkLanguage(also.Language); err != nil {
			return err
		}
		if also.Fragment == nil {
			return fmt.Errorf("the cards scanner needs a call graph builder for %s", also.Language)
		}
	}
	s.disableDedup = config.DisableDedup
	return nil
}

// GetInfo names the detector.
func (s *Scanner) GetInfo() scanner.Info {
	return scanner.Info{Name: ScannerName, Version: "poc", Description: "Card lookup over call-graph call sites (prototype)"}
}

// Scan builds target's call sites, matches the cards and reports the
// findings for the options' language and each further one. rulePaths only
// feed the rule-version stamp.
func (s *Scanner) Scan(_ context.Context, target string, rulePaths []string, toolInfo entities.ToolInfo) (*entities.InterimReport, error) {
	root, err := s.rulesetRoot()
	if err != nil {
		return nil, err
	}
	ruleInfo, err := s.catalogs.rules(rulePaths)
	if err != nil {
		return nil, err
	}
	results, err := s.match(target, root, s.opts, ruleInfo)
	if err != nil {
		return nil, err
	}
	for _, also := range s.opts.Also {
		opts := s.opts
		opts.Language, opts.Fragment, opts.Also = also.Language, also.Fragment, nil
		more, err := s.match(target, root, opts, ruleInfo)
		if err != nil {
			return nil, err
		}
		results = append(results, more...)
	}
	sortResults(results)
	return transformToInterimReport(results, toolInfo, target, rulePaths, s.disableDedup), nil
}

// match builds target's call sites in opts' language and matches that
// language's cards against them.
func (s *Scanner) match(target, root string, opts Options, ruleInfo map[string]rule) ([]detection, error) {
	primary, err := s.catalogs.get(opts, root)
	if err != nil {
		return nil, err
	}
	// The catalogs of the languages whose rules also apply (a C++ scan
	// also matches the C rules).
	lang, _ := ForName(opts.language())
	shared := make([]*catalog, 0, len(lang.Shares))
	for _, name := range lang.Shares {
		other := opts
		other.Language = name
		c, err := s.catalogs.get(other, root)
		if err != nil {
			return nil, err
		}
		shared = append(shared, c)
	}
	fragmentSpan := perf.StartQuiet("cards.fragment")
	fragment, err := opts.Fragment(target)
	fragmentSpan.End()
	if err != nil {
		return nil, fmt.Errorf("build call sites of %s: %w", target, err)
	}
	matchSpan := perf.StartQuiet("cards.match")
	matcherFragment := toMatcherFragment(&fragment)
	// The matcher reads its own copy; past it only the source lines are
	// read, so the rest of the fragment is released before the match.
	sourceLines := fragment.SourceLines
	fragment = graphfrag.GraphFragmentExport{}
	findings, own, sites, err := matchCatalogs(primary, shared, matcherFragment)
	if err != nil {
		return nil, fmt.Errorf("match the cards against %s: %w", target, err)
	}
	matchSpan.End()
	reportSpan := perf.StartQuiet("cards.report")
	defer reportSpan.End()

	lines := newLineReader(target, sourceLines)
	results := make([]detection, 0, len(findings))
	seen := make(map[string]bool, len(findings))
	for i, finding := range findings {
		info, known := ruleInfo[finding.RuleID]
		if !known || finding.File == "" || !finding.LineOK || (i >= own && !info.names(lang)) {
			continue
		}
		startLine, endLine := finding.Line, max(finding.EndLine, finding.Line)
		startCol, endCol := finding.Col, finding.EndCol
		if finding.FocusArg != nil {
			// OpenGrep reports a rule with a focus-metavariable at that
			// argument. Call sites carry no argument columns, so they are
			// recovered from the call's lines.
			if span, found := callArgumentSpan(lines, finding.File, startLine, endLine, startCol, endCol, *finding.FocusArg, finding.FocusText); found {
				startLine, startCol, endLine, endCol = span.startLine, span.startCol, span.endLine, span.endCol
			}
		}
		result := detection{
			ruleID:   info.CheckID,
			path:     filepath.Join(target, finding.File),
			start:    position{startLine, startCol},
			end:      position{endLine, endCol},
			message:  info.Message,
			severity: info.Severity,
			lines:    lines.span(finding.File, startLine, endLine),
			purl:     info.Metadata.PURL,
			crypto:   finding.MetadataMap(),
			// A Go receiver focus reports part of the call: the call's own
			// columns still select the crypto call.
			terminalCol: finding.TerminalCol, terminalEndCol: finding.TerminalEndCol,
			language: opts.language(),
		}
		// One finding per rule and range, whichever catalog matched it.
		key := fmt.Sprintf("%s\x00%s\x00%d:%d\x00%d:%d", result.ruleID, result.path, startLine, startCol, endLine, endCol)
		if seen[key] {
			continue
		}
		seen[key] = true
		results = append(results, result)
	}
	log.Debug().Str("target", target).Str("language", opts.language()).Int("sites", sites).Int("findings", len(results)).Msg("Cards detection")
	return results, nil
}

// sortResults orders results by path, start, end column, rule id.
func sortResults(results []detection) {
	sort.SliceStable(results, func(i, j int) bool {
		a, b := &results[i], &results[j]
		switch {
		case a.path != b.path:
			return a.path < b.path
		case a.start.line != b.start.line:
			return a.start.line < b.start.line
		case a.start.col != b.start.col:
			return a.start.col < b.start.col
		case a.end.col != b.end.col:
			return a.end.col < b.end.col
		default:
			return a.ruleID < b.ruleID
		}
	})
}

// lineReader gives the findings' matched text: the fragment's source lines
// (graph-fragment-1.16), or the source file for a fragment without them.
type lineReader struct {
	dir      string
	fragment map[string]map[int]string
	files    map[string][]string
}

func newLineReader(dir string, fragment map[string]map[int]string) *lineReader {
	return &lineReader{dir: dir, fragment: fragment, files: make(map[string][]string)}
}

// span is the text of lines first..last of file, joined by newlines.
func (r *lineReader) span(file string, first, last int) string {
	lines := make([]string, 0, last-first+1)
	for n := first; n <= last; n++ {
		lines = append(lines, r.line(file, n))
	}
	return strings.Join(lines, "\n")
}

func (r *lineReader) line(file string, number int) string {
	if r.fragment != nil {
		return r.fragment[file][number]
	}
	lines, read := r.files[file]
	if !read {
		if data, err := os.ReadFile(filepath.Join(r.dir, file)); err == nil { // #nosec G304 -- a source file the call graph just parsed.
			lines = strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
		}
		r.files[file] = lines
	}
	if number < 1 || number > len(lines) {
		return ""
	}
	return lines[number-1]
}

// argumentSpan returns the 1-based columns (end exclusive) of argument index
// of the call written at columns startCol..endCol of line. It reports false
// when the call does not lie on the line (it continues on the next one) or
// the argument found there is not want.
func argumentSpan(line string, startCol, endCol, index int, want string) (argStart, argEnd int, found bool) { //nolint:gocognit,gocyclo // complexity predates the lint gate; splitting it is a separate behavior-sensitive change
	if startCol < 1 || endCol <= startCol || endCol-1 > len(line) || line[endCol-2] != ')' {
		return 0, 0, false
	}
	// The argument list opens at the parenthesis the call's last one closes.
	open := -1
	depth := 0
	var quote byte
	for i := endCol - 2; i >= startCol-1 && open < 0; i-- {
		ch := line[i]
		switch {
		case quote != 0:
			if ch == quote && (i == 0 || line[i-1] != '\\') {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == ')' || ch == ']' || ch == '}':
			depth++
		case ch == '(' || ch == '[' || ch == '{':
			depth--
			if depth == 0 {
				open = i
			}
		}
	}
	if open < 0 {
		return 0, 0, false
	}
	position := 0
	begin := open + 1
	depth, quote = 0, 0
	for i := open + 1; i <= endCol-2; i++ {
		ch := line[i]
		last := i == endCol-2
		switch {
		case quote != 0:
			if ch == quote && line[i-1] != '\\' {
				quote = 0
			}
			continue
		case ch == '"' || ch == '\'':
			quote = ch
			continue
		case !last && (ch == '(' || ch == '[' || ch == '{'):
			depth++
			continue
		case !last && (ch == ')' || ch == ']' || ch == '}'):
			depth--
			continue
		case !last && (ch != ',' || depth != 0):
			continue
		}
		if position == index {
			text := line[begin:i]
			trimmed := strings.TrimSpace(text)
			lead := len(text) - len(strings.TrimLeft(text, " \t\r\n"))
			if trimmed == "" || trimmed != want {
				return 0, 0, false
			}
			return begin + lead + 1, begin + lead + len(trimmed) + 1, true
		}
		position++
		begin = i + 1
	}
	return 0, 0, false
}

// lineSpan is a source span: 1-based lines and columns, end column exclusive.
type lineSpan struct {
	startLine, startCol, endLine, endCol int
}

// callArgumentSpan locates argument index of the call that starts at
// startCol of startLine and ends before endCol of endLine. A call over
// several lines is searched as its lines joined by newlines; the argument's
// offsets in that text map back to lines and columns.
func callArgumentSpan(lines *lineReader, file string, startLine, endLine, startCol, endCol, index int, want string) (lineSpan, bool) {
	text := lines.line(file, startLine)
	starts := make([]int, 1, max(endLine-startLine+1, 1)) // offset of each line of the call in text, the first at 0
	for n := startLine + 1; n <= endLine; n++ {
		text += "\n"
		starts = append(starts, len(text))
		text += lines.line(file, n)
	}
	argStart, argEnd, found := argumentSpan(text, startCol, starts[len(starts)-1]+endCol, index, want)
	if !found {
		return lineSpan{}, false
	}
	position := func(col int) (int, int) {
		offset := col - 1
		row := 0
		for row+1 < len(starts) && starts[row+1] <= offset {
			row++
		}
		return startLine + row, offset - starts[row] + 1
	}
	var span lineSpan
	span.startLine, span.startCol = position(argStart)
	span.endLine, span.endCol = position(argEnd - 1)
	span.endCol++
	return span, true
}

// VerifyRuleInfo compares the rules a finding is reported under, read from
// the rule YAML under yamlDir and from the v3 card files under cardsDir
// (cards verify, A4): the same check id, message, severity and purl for
// every rule. It returns the number of rules compared and the differences.
func VerifyRuleInfo(yamlDir, cardsDir string) (int, []string, error) {
	fromYAML, err := loadRules(yamlDir)
	if err != nil {
		return 0, nil, err
	}
	fromCards, err := loadRules(cardsDir)
	if err != nil {
		return 0, nil, err
	}
	byID := make(map[string]rule, len(fromCards))
	for _, r := range fromCards {
		byID[r.ID] = r
	}
	var diffs []string
	for _, r := range fromYAML {
		c, ok := byID[r.ID]
		switch {
		case !ok:
			diffs = append(diffs, fmt.Sprintf("%s: no rules entry", r.ID))
		case !sameMetadata(c, r):
			diffs = append(diffs, fmt.Sprintf("%s: yaml %+v, cards %+v", r.ID, r, c))
		}
	}
	if len(fromCards) != len(fromYAML) {
		diffs = append(diffs, fmt.Sprintf("%d rules entries for %d rules", len(fromCards), len(fromYAML)))
	}
	return len(fromYAML), diffs, nil
}
