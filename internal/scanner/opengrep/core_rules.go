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

package opengrep

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/scanoss/crypto-finder/internal/rules/prefilter"
	"github.com/scanoss/crypto-finder/internal/rules/rulejson"
)

// ruleBase is one rule as its rule file spells it, shared by every scan
// that loads the same file content.
type ruleBase struct {
	// baseID is the id the rule file gives the rule.
	baseID string
	// raw is the rule as JSON, with baseID as its id.
	raw []byte
	// langs are the rule's languages; nil when one is not a target
	// language of the pinned OpenGrep.
	langs    []*language
	severity string
	message  string
	metadata json.RawMessage
	// dedupeKey identifies the rule apart from its id and metadata.
	dedupeKey string

	// coreReason says why core mode cannot pass the rule on; empty when it
	// can.
	coreReason string

	decodeOnce      sync.Once
	decoded         map[string]any
	requirementOnce sync.Once
	req             prefilter.Expr
}

// coreRule is one rule of a scan: its base and the prefix the CLI puts
// before its id, from its config file's directory.
type coreRule struct {
	*ruleBase
	prefix string
	// id is the prefixed id: the check_id the CLI reports.
	id string
}

// prefixedRaw returns the rule as JSON with its id behind extra and the
// CLI's prefix.
func (r *coreRule) prefixedRaw(extra string) ([]byte, error) {
	raw, ok := rulejson.PrefixRuleID(r.raw, extra+r.prefix)
	if !ok {
		return nil, fmt.Errorf("opengrep: rule %s has no id to prefix", r.id)
	}
	return raw, nil
}

// body decodes the rule for the prefilter, once.
func (r *ruleBase) body() map[string]any {
	r.decodeOnce.Do(func() {
		if err := json.Unmarshal(r.raw, &r.decoded); err != nil {
			r.decoded = nil
		}
	})
	return r.decoded
}

// analyzers returns the analyzer ids of the rule's languages, or nil when
// one is unknown.
func (r *ruleBase) analyzers() []string {
	if r.langs == nil {
		return nil
	}
	ids := make([]string, 0, len(r.langs))
	for _, lang := range r.langs {
		ids = append(ids, lang.id)
	}
	return ids
}

// coreRuleset is the rules of a scan's rule paths, in the CLI's order.
type coreRuleset struct {
	rules []*coreRule
	// coreReason says why opengrep-core cannot take these rules as the CLI
	// would hand them; empty when it can.
	coreReason string
}

// languagesOf returns the distinct languages of rules in first-seen order.
func languagesOf(rules []*coreRule) []*language {
	seen := make(map[string]bool)
	var langs []*language
	for _, rule := range rules {
		for _, lang := range rule.langs {
			if !seen[lang.id] {
				seen[lang.id] = true
				langs = append(langs, lang)
			}
		}
	}
	return langs
}

// ruleHeader is what the adapter reads from a rule besides its patterns.
type ruleHeader struct {
	ID        string          `json:"id"`
	Languages []string        `json:"languages"`
	Severity  string          `json:"severity"`
	Message   string          `json:"message"`
	Mode      string          `json:"mode"`
	Metadata  json.RawMessage `json:"metadata"`
}

// ruleFileCache keeps the rules of rule files by content, so the dependency
// batches of one run, each with its own materialized copy of the same rules,
// read and decode them once. Cached rules are shared and never modified.
var ruleFileCache sync.Map // key: sha256(content) -> []*ruleBase

// loadCoreRuleset reads the rule files below rulePaths in the order the
// opengrep CLI loads them, prefixes each rule id with its config file's
// directory as the CLI does relative to cwd, and drops repeated rules as
// the CLI does. It fails for a rule file core mode cannot read like the CLI.
func loadCoreRuleset(rulePaths []string, cwd string) (*coreRuleset, error) {
	var all []*coreRule
	ruleset := &coreRuleset{}
	for _, rulePath := range rulePaths {
		files, err := configFiles(rulePath)
		if err != nil {
			return nil, err
		}
		for _, configID := range files {
			bases, err := loadRuleFile(configID)
			if err != nil {
				return nil, err
			}
			prefix := configPrefix(configID, cwd)
			for _, base := range bases {
				if base.coreReason != "" && ruleset.coreReason == "" {
					ruleset.coreReason = base.coreReason
				}
				all = append(all, &coreRule{ruleBase: base, prefix: prefix, id: prefix + base.baseID})
			}
		}
	}
	ruleset.rules = dedupeRules(all)
	return ruleset, nil
}

func loadRuleFile(path string) ([]*ruleBase, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- a rule file under the scan's rule paths.
	if err != nil {
		return nil, fmt.Errorf("opengrep: read rule file %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	key := hex.EncodeToString(sum[:])
	if cached, ok := ruleFileCache.Load(key); ok {
		return cached.([]*ruleBase), nil //nolint:errcheck,forcetypeassert // Only []*ruleBase values are stored.
	}
	encoded, ok := rulejson.EncodeRules(data, "")
	if !ok {
		return nil, fmt.Errorf("opengrep: rule file %s has no JSON form core mode can pass on", path)
	}
	bases := make([]*ruleBase, 0, len(encoded))
	for _, raw := range encoded {
		base, err := newRuleBase(raw)
		if err != nil {
			return nil, err
		}
		bases = append(bases, base)
	}
	ruleFileCache.Store(key, bases)
	return bases, nil
}

func newRuleBase(raw []byte) (*ruleBase, error) {
	var header ruleHeader
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, fmt.Errorf("opengrep: decode rule: %w", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, fmt.Errorf("opengrep: decode rule: %w", err)
	}
	rule := &ruleBase{baseID: header.ID, raw: raw, severity: header.Severity, message: header.Message, metadata: header.Metadata, dedupeKey: dedupeKey(keys)}
	for _, key := range []string{"min-version", "max-version", "paths"} {
		if _, ok := keys[key]; ok {
			rule.coreReason = fmt.Sprintf("rule %s sets %s", header.ID, key)
		}
	}
	switch header.Mode {
	case "", "search", "taint":
	default:
		rule.coreReason = fmt.Sprintf("rule %s uses mode %s", header.ID, header.Mode)
	}
	langs := make([]*language, 0, len(header.Languages))
	for _, name := range header.Languages {
		lang := languageByKey[strings.ToLower(name)]
		if lang == nil {
			rule.coreReason = fmt.Sprintf("rule %s targets language %s", header.ID, name)
			langs = nil
			break
		}
		langs = append(langs, lang)
	}
	rule.langs = langs
	return rule, nil
}

// dedupeRules drops rules equal but for metadata, once prefixed, as the
// CLI's get_rules does: the first occurrence survives, at the position of
// the last one.
func dedupeRules(rules []*coreRule) []*coreRule {
	keys := make([]string, len(rules))
	first := make(map[string]int)
	last := make(map[string]int)
	for i, rule := range rules {
		keys[i] = rule.id + "\x00" + rule.dedupeKey
		if _, ok := first[keys[i]]; !ok {
			first[keys[i]] = i
		}
		last[keys[i]] = i
	}
	if len(first) == len(rules) {
		return rules
	}
	out := make([]*coreRule, 0, len(first))
	for i := range rules {
		if last[keys[i]] == i {
			out = append(out, rules[first[keys[i]]])
		}
	}
	return out
}

// dedupeKey encodes a rule's fields but its id and metadata, compacted, in
// key order.
func dedupeKey(fields map[string]json.RawMessage) string {
	rest := make(map[string]json.RawMessage, len(fields))
	for key, value := range fields {
		if key == "id" || key == "metadata" {
			continue
		}
		var compact bytes.Buffer
		if json.Compact(&compact, value) == nil {
			value = compact.Bytes()
		}
		rest[key] = value
	}
	encoded, err := json.Marshal(rest)
	if err != nil {
		return fmt.Sprint(fields)
	}
	return string(encoded)
}

// configFiles lists the rule files the CLI loads for one --config value:
// the file itself, or the .yaml/.yml files below a directory that are not
// .test or .fixed fixtures, hidden ones included.
func configFiles(rulePath string) ([]string, error) {
	path := pyPath(rulePath)
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("opengrep: rule path %s: %w", rulePath, err)
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	var files []string
	if err := walkRuleDir(rulePath, path, &files); err != nil {
		return nil, err
	}
	return files, nil
}

// walkRuleDir appends the rule files of dir, then those of its
// subdirectories depth first, as pathlib's rglob lists them. Within one
// directory os.ReadDir sorts entries by name, where rglob takes os.scandir's
// order, which the file system decides: the deterministic order is chosen
// on purpose, so which of two equal rules in sibling files survives
// dedupeRules (the first read) is the same on every host, where the CLI's
// choice can differ between hosts.
func walkRuleDir(rulePath, dir string, files *[]string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("opengrep: read rule directory %s: %w", dir, err)
	}
	var subdirs []string
	for _, entry := range entries {
		child := pyJoin(dir, entry.Name())
		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			return fmt.Errorf("opengrep: rule path %s holds symlink %s", rulePath, child)
		case entry.IsDir():
			subdirs = append(subdirs, child)
		case entry.Type().IsRegular() && isConfigSuffix(entry.Name()):
			*files = append(*files, child)
		}
	}
	for _, sub := range subdirs {
		if err := walkRuleDir(rulePath, sub, files); err != nil {
			return err
		}
	}
	return nil
}

// isConfigSuffix is the CLI's is_config_suffix over pathlib suffixes.
func isConfigSuffix(name string) bool {
	suffixes := pySuffixes(name)
	if len(suffixes) == 0 {
		return false
	}
	last := suffixes[len(suffixes)-1]
	if last != ".yaml" && last != ".yml" {
		return false
	}
	for _, suffix := range suffixes {
		if suffix == ".fixed" {
			return false
		}
	}
	return len(suffixes) < 2 || suffixes[len(suffixes)-2] != ".test"
}

func pySuffixes(name string) []string {
	if strings.HasSuffix(name, ".") {
		return nil
	}
	parts := strings.Split(strings.TrimLeft(name, "."), ".")
	suffixes := make([]string, 0, len(parts))
	for _, part := range parts[1:] {
		suffixes = append(suffixes, "."+part)
	}
	return suffixes
}

var ruleIDUnsafe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// configPrefix is the CLI's convert_config_id_to_prefix: the config file's
// directory, relative to cwd when below it, dotted, stripped of leading dots
// and slashes and of characters rule ids cannot hold.
func configPrefix(configID, cwd string) string {
	at := pyPath(configID)
	if rel, ok := pyRelativeTo(at, cwd); ok {
		at = rel
	}
	parts := pyParts(at)
	if len(parts) == 0 {
		return ""
	}
	prefix := strings.TrimLeft(strings.Join(parts[:len(parts)-1], "."), "./")
	if prefix != "" {
		prefix += "."
	}
	return ruleIDUnsafe.ReplaceAllString(prefix, "")
}

// pyParts is pathlib's parts: an absolute path starts with "/".
func pyParts(path string) []string {
	if path == "." {
		return nil
	}
	if strings.HasPrefix(path, "/") {
		rest := strings.TrimPrefix(path, "/")
		if rest == "" {
			return []string{"/"}
		}
		return append([]string{"/"}, strings.Split(rest, "/")...)
	}
	return strings.Split(path, "/")
}

// pyRelativeTo is pathlib's lexical relative_to.
func pyRelativeTo(path, base string) (string, bool) {
	base = pyPath(base)
	pathParts, baseParts := pyParts(path), pyParts(base)
	if len(baseParts) > len(pathParts) {
		return "", false
	}
	for i := range baseParts {
		if pathParts[i] != baseParts[i] {
			return "", false
		}
	}
	rest := pathParts[len(baseParts):]
	if len(rest) == 0 {
		return ".", true
	}
	return strings.Join(rest, "/"), true
}

// physicalDir returns dir, or the working directory when dir is empty, with
// symlinks resolved: Python's os.getcwd reports the physical path.
func physicalDir(dir string) (string, error) {
	if dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("opengrep: working directory: %w", err)
		}
		dir = wd
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("opengrep: working directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("opengrep: working directory: %w", err)
	}
	return resolved, nil
}

// coreRuleIDs reports how opengrep-core should name rules: by their ids as
// the rule files spell them when those are distinct, which keeps the rules
// file free of the CLI's prefix (the materialized rules directory changes
// every run) and so reusable, else by the prefixed ids the CLI reports.
func coreRuleIDs(rules []*coreRule) (useBase bool) {
	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if seen[rule.baseID] {
			return false
		}
		seen[rule.baseID] = true
	}
	return true
}

// rulesDocument encodes rules as the rules file opengrep-core reads, each
// under its base id or, when useBase is false, its prefixed id.
func rulesDocument(rules []*coreRule, useBase bool) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("{\"rules\":[\n")
	for i, rule := range rules {
		if i > 0 {
			buf.WriteString(",\n")
		}
		raw := rule.raw
		if !useBase {
			prefixed, err := rule.prefixedRaw("")
			if err != nil {
				return nil, err
			}
			raw = prefixed
		}
		buf.Write(raw)
	}
	buf.WriteString("\n]}\n")
	return buf.Bytes(), nil
}

// coreRulesCacheTTL is how long a cached rules file nobody reused stays.
const coreRulesCacheTTL = 30 * 24 * time.Hour

// cachedRulesFile returns a file holding doc. With a cacheDir it is kept
// there by content hash and OpenGrep version, so later scans of the same
// rules reuse it; otherwise it is a temporary file the returned cleanup
// removes.
func cachedRulesFile(cacheDir, version string, doc []byte) (string, func(), error) {
	sum := sha256.New()
	sum.Write([]byte(version))
	sum.Write([]byte{0})
	sum.Write(doc)
	name := "rules-" + hex.EncodeToString(sum.Sum(nil)) + ".json"
	if cacheDir != "" {
		path := filepath.Join(cacheDir, name)
		if info, err := os.Stat(path); err == nil && info.Size() == int64(len(doc)) {
			now := time.Now()
			_ = os.Chtimes(path, now, now) //nolint:errcheck // Freshness only delays pruning.
			return path, func() {}, nil
		}
		if err := writeAtomic(cacheDir, name, doc); err == nil {
			pruneRulesCache(cacheDir, name)
			return path, func() {}, nil
		}
	}
	file, err := os.CreateTemp("", "crypto-finder-core-rules-*.json")
	if err != nil {
		return "", nil, fmt.Errorf("opengrep: create core rules file: %w", err)
	}
	_, err = file.Write(doc)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	tempName := file.Name()
	cleanup := func() { _ = os.Remove(tempName) } //nolint:errcheck // Best-effort removal of the temp file CreateTemp made.
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("opengrep: write core rules file: %w", err)
	}
	return tempName, cleanup, nil
}

// pruneRulesCache removes cached rules files unused for coreRulesCacheTTL,
// sparing keep. Best effort.
func pruneRulesCache(dir, keep string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-coreRulesCacheTTL)
	for _, entry := range entries {
		name := entry.Name()
		if name == keep || !strings.HasPrefix(name, "rules-") {
			continue
		}
		if info, err := entry.Info(); err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, name)) //nolint:errcheck // Best-effort pruning.
		}
	}
}

// writeAtomic publishes data as dir/name through a renamed temporary file,
// so concurrent scans see a whole file or none.
func writeAtomic(dir, name string, data []byte) (err error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("opengrep: create cache dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, name+".*.tmp")
	if err != nil {
		return fmt.Errorf("opengrep: create cache file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name()) //nolint:errcheck,gosec // Best-effort cleanup.
		}
	}()
	_, err = tmp.Write(data)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("opengrep: write cache file: %w", err)
	}
	if err = os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil { //nolint:gosec // Both paths are in the cache dir.
		return fmt.Errorf("opengrep: publish cache file: %w", err)
	}
	return nil
}
