package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.yaml.in/yaml/v3"

	"github.com/scanoss/crypto-finder/internal/config"
)

// ruleFile is a minimal representation of a semgrep rule file, used only to
// extract the languages field for filtering.
type ruleFile struct {
	Rules []struct {
		Languages []string `yaml:"languages"`
	} `yaml:"rules"`
}

// ruleLanguages parses a rule YAML file and returns the set of languages it
// targets. The second return is true when the file parsed successfully but
// contains zero rules: such a file can never match anything, so callers must
// exclude it rather than treat it as "unknown language".
func ruleLanguages(path string) ([]string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("Failed to read rule file for language extraction")
		return nil, false
	}

	var rf ruleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		log.Debug().Err(err).Str("path", path).Msg("Failed to parse rule file for language extraction")
		return nil, false
	}

	if len(rf.Rules) == 0 {
		return nil, true
	}

	seen := make(map[string]bool)
	var langs []string
	for _, r := range rf.Rules {
		for _, l := range r.Languages {
			lower := canonicalLanguage(l)
			if !seen[lower] {
				seen[lower] = true
				langs = append(langs, lower)
			}
		}
	}
	return langs, false
}

// canonicalLanguage maps a language name to the id rule files use. The
// detector reports linguist names ("c++", "c#") while rules use opengrep ids
// ("cpp", "csharp"); without this, C++-only rules were dropped whenever the tree
// also held C, because the C rules kept the filtered set non-empty.
func canonicalLanguage(lang string) string {
	switch lower := strings.ToLower(lang); lower {
	case "c++":
		return "cpp"
	case "c#":
		return "csharp"
	default:
		return lower
	}
}

// filterRulesByLanguages filters rule paths to only include rules whose YAML
// `languages:` field matches at least one of the detected languages.
// If filtering would result in zero rules, returns all rules unchanged.
func filterRulesByLanguages(allRules, languages []string) []string {
	candidateRules := expandRulePaths(allRules)

	if len(languages) == 0 {
		return candidateRules
	}

	// Build lookup set from detected languages (normalized to lowercase)
	wanted := make(map[string]bool, len(languages))
	for _, lang := range languages {
		wanted[canonicalLanguage(lang)] = true
	}

	filtered := make([]string, 0, len(candidateRules))
	for _, rulePath := range candidateRules {
		ruleLangs, empty := ruleLanguages(rulePath)
		if empty {
			// Zero rules in the file — it can never match anything, and if it
			// survives as the sole config, opengrep fails with exit code 7.
			continue
		}
		if len(ruleLangs) == 0 {
			// Can't determine language — include to be safe
			filtered = append(filtered, rulePath)
			continue
		}
		for _, rl := range ruleLangs {
			if wanted[rl] {
				filtered = append(filtered, rulePath)
				break
			}
		}
	}

	if len(filtered) == 0 {
		log.Warn().
			Strs("languages", languages).
			Msg("No rules matched language filter, falling back to all rules")
		return candidateRules
	}

	log.Info().
		Int("total", len(candidateRules)).
		Int("filtered", len(filtered)).
		Strs("languages", languages).
		Msg("Filtered rules by detected languages")

	return filtered
}

func prepareRulePathsForScanner(allRules, languages []string) ([]string, func(), error) {
	candidateRules := allRules
	if len(languages) > 0 {
		candidateRules = filterRulesByLanguages(allRules, languages)
	}

	return optimizeRulePathsForScanner(candidateRules)
}

func optimizeRulePathsForScanner(rulePaths []string) ([]string, func(), error) {
	if len(rulePaths) <= 1 {
		return rulePaths, func() {}, nil
	}

	allDirs := true
	for _, path := range rulePaths {
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			allDirs = false
			break
		}
	}
	if allDirs {
		return rulePaths, func() {}, nil
	}

	expanded := expandRulePaths(rulePaths)
	if len(expanded) <= 1 {
		return expanded, func() {}, nil
	}
	for _, path := range expanded {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			log.Debug().
				Err(err).
				Str("path", path).
				Msg("Skipping rule materialization because a filtered rule path is unavailable")
			return rulePaths, func() {}, nil
		}
	}

	return materializeRuleFiles(expanded)
}

func materializeRuleFiles(ruleFiles []string) ([]string, func(), error) {
	baseDir := commonRuleBaseDir(ruleFiles)
	tempParent := ""
	if rulesetRoot := rulesetVersionRoot(baseDir); rulesetRoot != "" {
		tempParent = filepath.Join(filepath.Dir(rulesetRoot), config.FilteredRulesDirName, filepath.Base(rulesetRoot))
		if err := os.MkdirAll(tempParent, 0o750); err != nil {
			return nil, nil, fmt.Errorf("create filtered rules temp parent: %w", err)
		}
		// Reap orphaned run-* dirs from prior jobs. The deferred cleanup
		// below removes this run's dir on exit, but the mining worker
		// SIGKILLs the whole process group on timeout, so killed jobs never
		// run it and leak their run-* dir into the shared HOME cache. Prune
		// only dirs older than the longest possible job so an in-flight
		// concurrent run is never touched.
		pruneStaleFilteredRuns(tempParent)
	}

	tempRoot, err := os.MkdirTemp(tempParent, "run-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create filtered rules temp dir: %w", err)
	}

	targetRoot := tempRoot
	if baseName := filepath.Base(baseDir); baseName != "" && baseName != "." && baseName != string(os.PathSeparator) {
		targetRoot = filepath.Join(tempRoot, baseName)
	}

	var merged mergedRules
	copied := 0
	for _, ruleFile := range ruleFiles {
		relPath, err := filepath.Rel(baseDir, ruleFile)
		if err != nil {
			removeMaterializedRules(tempRoot)
			return nil, nil, fmt.Errorf("resolve relative rule path for %s: %w", ruleFile, err)
		}

		if rules, ok := mergeableRules(ruleFile, relPath); ok {
			if len(rules) > 0 {
				log.Debug().Str("path", ruleFile).Int("mergedLine", merged.nextLine()).Msg("Merged rule file into " + mergedRulesFileName)
			}
			for _, rule := range rules {
				merged.add(rule)
			}
			continue
		}
		log.Debug().Str("path", ruleFile).Msg("Passing rule file to scanner unmerged")
		if err := copyRuleFile(ruleFile, filepath.Join(targetRoot, relPath)); err != nil {
			removeMaterializedRules(tempRoot)
			return nil, nil, err
		}
		copied++
	}
	if err := writeMergedRules(filepath.Join(targetRoot, mergedRulesFileName), merged.bytes()); err != nil {
		removeMaterializedRules(tempRoot)
		return nil, nil, err
	}

	log.Info().
		Int("sourceFiles", len(ruleFiles)).
		Int("mergedRules", merged.count).
		Int("unmergedFiles", copied).
		Str("path", targetRoot).
		Msg("Materialized filtered rules for scanner")

	return []string{targetRoot}, func() {
		removeMaterializedRules(tempRoot)
	}, nil
}

// mergedRulesFileName holds every mergeable filtered rule. OpenGrep loads each
// config file separately, so one merged file loads faster and with far less
// CPU than hundreds of small ones. Its content is JSON, which is YAML too:
// OpenGrep 1.29 reads 1,600 rules of JSON text in a seventh of the time it
// takes for the same rules as YAML, but only loads .yaml/.yml names from a
// config directory.
const mergedRulesFileName = "merged-rules.yaml"

// mergedRules builds the merged file: one JSON rule per line after the line
// that opens the rules list, so OpenGrep's error lines map back to a rule.
type mergedRules struct {
	buf   bytes.Buffer
	count int
}

func (m *mergedRules) nextLine() int { return m.count + 2 }

func (m *mergedRules) add(rule []byte) {
	if m.count == 0 {
		m.buf.WriteString("{\"rules\":[\n")
	} else {
		m.buf.WriteString(",\n")
	}
	m.buf.Write(rule)
	m.count++
}

func (m *mergedRules) bytes() []byte {
	if m.count == 0 {
		return []byte("{\"rules\":[]}\n")
	}
	m.buf.WriteString("\n]}\n")
	return m.buf.Bytes()
}

// mergeableRules encodes the rules of one filtered file as one JSON object
// per rule, or returns false when the file must reach the scanner verbatim:
// when it is not a plain rules file, or when some node has no JSON spelling
// that OpenGrep reads the way it reads the YAML.
//
// The scanner still receives the materialized directory, and OpenGrep
// prefixes each rule ID with its file's directory. Each merged rule's ID
// therefore carries its file's directory relative to the materialized root,
// so check_id, the cleaned rule ID and the separation between equal IDs from
// different directories stay what they were with one file per rule file.
func mergeableRules(path, relPath string) ([][]byte, bool) {
	if !scannerLoadsAsPlainRuleFile(relPath) {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	rules := plainRulesSequence(data)
	if rules == nil {
		return nil, false
	}
	prefix := ""
	if dir := filepath.Dir(relPath); dir != "." {
		prefix = strings.ReplaceAll(filepath.ToSlash(dir), "/", ".") + "."
	}
	encoded := make([][]byte, 0, len(rules.Content))
	for _, rule := range rules.Content {
		id := mappingValue(rule, "id")
		if id == nil || id.Kind != yaml.ScalarNode || id.ShortTag() != yamlStrTag {
			return nil, false
		}
		id.Value = prefix + id.Value
		var out bytes.Buffer
		if !appendRuleJSON(&out, rule) {
			return nil, false
		}
		encoded = append(encoded, out.Bytes())
	}
	return encoded, true
}

// jsonNumber matches the numbers JSON can spell. A YAML number written any
// other way (0x10, 0o17, 017, 1_000, +5, .5, 1.) has no literal JSON form
// with the value OpenGrep reads, so its file is not merged.
var jsonNumber = regexp.MustCompile(`^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?$`)

const yamlStrTag = "!!str"

// appendRuleJSON writes node as JSON with the meaning OpenGrep's YAML parser
// gives it, and reports false for anything it cannot write that way: aliases,
// merge keys, repeated or non-string keys, and tags other than the core ones.
// Numbers keep their literal text, so metadata such as 2.0 reaches OpenGrep
// as written.
func appendRuleJSON(out *bytes.Buffer, node *yaml.Node) bool {
	switch node.Kind {
	case yaml.MappingNode:
		return appendMappingJSON(out, node)
	case yaml.SequenceNode:
		return appendSequenceJSON(out, node)
	case yaml.ScalarNode:
		return appendScalarJSON(out, node)
	case yaml.DocumentNode, yaml.AliasNode:
		return false
	default:
		return false
	}
}

func appendMappingJSON(out *bytes.Buffer, node *yaml.Node) bool {
	out.WriteByte('{')
	seen := make(map[string]struct{}, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		if key.Kind != yaml.ScalarNode || key.ShortTag() != yamlStrTag {
			return false
		}
		if _, dup := seen[key.Value]; dup {
			return false
		}
		seen[key.Value] = struct{}{}
		if i > 0 {
			out.WriteByte(',')
		}
		if !appendJSONString(out, key.Value) {
			return false
		}
		out.WriteByte(':')
		if !appendRuleJSON(out, node.Content[i+1]) {
			return false
		}
	}
	out.WriteByte('}')
	return true
}

func appendSequenceJSON(out *bytes.Buffer, node *yaml.Node) bool {
	out.WriteByte('[')
	for i, item := range node.Content {
		if i > 0 {
			out.WriteByte(',')
		}
		if !appendRuleJSON(out, item) {
			return false
		}
	}
	out.WriteByte(']')
	return true
}

func appendScalarJSON(out *bytes.Buffer, node *yaml.Node) bool {
	switch node.ShortTag() {
	case yamlStrTag, "!!timestamp":
		return appendJSONString(out, node.Value)
	case "!!int", "!!float":
		if !jsonNumber.MatchString(node.Value) {
			return false
		}
		out.WriteString(node.Value)
		return true
	case "!!bool":
		switch node.Value {
		case "true", "True", "TRUE":
			out.WriteString("true")
		case "false", "False", "FALSE":
			out.WriteString("false")
		default:
			return false
		}
		return true
	default:
		return false
	}
}

func appendJSONString(out *bytes.Buffer, value string) bool {
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil {
		return false
	}
	out.Truncate(out.Len() - 1) // Encode ends each value with a newline.
	return true
}

// plainRulesSequence returns the rules sequence of a file that is one YAML
// document holding nothing but a top-level rules sequence, or nil.
func plainRulesSequence(data []byte) *yaml.Node {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if decoder.Decode(&doc) != nil || !errors.Is(decoder.Decode(new(yaml.Node)), io.EOF) || len(doc.Content) != 1 {
		return nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode || len(root.Content) != 2 || root.Content[0].Value != "rules" || root.Content[1].Kind != yaml.SequenceNode {
		return nil
	}
	return root.Content[1]
}

// scannerLoadsAsPlainRuleFile reports whether a scanner walking a rules
// directory loads this file like any other. OpenGrep 1.29 only loads
// lowercase .yaml/.yml names there and skips *.test.* and *.fixed.* fixtures;
// hidden paths are copied too, so each scanner keeps its own treatment of
// them.
func scannerLoadsAsPlainRuleFile(relPath string) bool {
	name := filepath.Base(relPath)
	if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
		return false
	}
	stem := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
	if strings.HasSuffix(stem, ".test") || strings.HasSuffix(stem, ".fixed") {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(relPath), "/") {
		if strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	var value *yaml.Node
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			if value != nil {
				return nil
			}
			value = node.Content[i+1]
		}
	}
	return value
}

func writeMergedRules(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create merged rules directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create merged rules file: %w", err)
	}
	_, err = file.Write(data)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write merged rules file: %w", err)
	}
	return nil
}

// filteredRunTTL is how old a run-* dir under .crypto-finder-filtered must be
// before pruneStaleFilteredRuns reclaims it. It must comfortably exceed the
// longest scan a concurrent process could still be running against its own
// run-* dir, so we never delete a live one. Scans are bounded by the caller's
// --timeout (the mining worker uses 30m); 2h leaves a wide safety margin while
// still reclaiming disk from SIGKILLed jobs within the same day.
const filteredRunTTL = 2 * time.Hour

// pruneStaleFilteredRuns removes orphaned run-* directories left under
// tempParent by jobs that never ran their cleanup (e.g. SIGKILLed on timeout
// by the mining worker's process-group kill). Best-effort: only dirs whose
// mtime is older than filteredRunTTL are removed, so an in-flight concurrent
// run is never touched. All errors are swallowed — this is opportunistic
// housekeeping, not part of the scan's correctness.
func pruneStaleFilteredRuns(tempParent string) {
	entries, err := os.ReadDir(tempParent)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-filteredRunTTL)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "run-") {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		stale := filepath.Join(tempParent, entry.Name())
		if rmErr := os.RemoveAll(stale); rmErr != nil {
			log.Debug().Err(rmErr).Str("path", stale).Msg("Failed to prune stale filtered rules dir")
		}
	}
}

// removeMaterializedRules deletes a materialized rules directory, logging a
// warning if cleanup fails rather than propagating the error.
func removeMaterializedRules(tempRoot string) {
	if err := os.RemoveAll(tempRoot); err != nil {
		log.Warn().Err(err).Str("path", tempRoot).Msg("Failed to clean up materialized filtered rules")
	}
}

func copyRuleFile(srcPath, destPath string) (err error) {
	if mkErr := os.MkdirAll(filepath.Dir(destPath), 0o750); mkErr != nil {
		return fmt.Errorf("create filtered rule directory for %s: %w", destPath, mkErr)
	}

	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open source rule file %s: %w", srcPath, err)
	}
	defer func() {
		if closeErr := srcFile.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close source rule file %s: %w", srcPath, closeErr)
		}
	}()

	destFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create filtered rule file %s: %w", destPath, err)
	}
	defer func() {
		if closeErr := destFile.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close filtered rule file %s: %w", destPath, closeErr)
		}
	}()

	if _, copyErr := io.Copy(destFile, srcFile); copyErr != nil {
		return fmt.Errorf("copy filtered rule file %s: %w", srcPath, copyErr)
	}

	return nil
}

func commonRuleBaseDir(paths []string) string {
	if len(paths) == 0 {
		return ""
	}

	baseDir := filepath.Dir(paths[0])
	for _, path := range paths[1:] {
		baseDir = commonPathPrefix(baseDir, filepath.Dir(path))
	}
	if baseDir == "" {
		return string(os.PathSeparator)
	}
	return baseDir
}

func commonPathPrefix(left, right string) string {
	left = filepath.Clean(left)
	right = filepath.Clean(right)

	if left == right {
		return left
	}

	leftParts := strings.Split(filepath.Clean(left), string(os.PathSeparator))
	rightParts := strings.Split(filepath.Clean(right), string(os.PathSeparator))

	size := min(len(leftParts), len(rightParts))
	common := make([]string, 0, size)
	for i := 0; i < size; i++ {
		if leftParts[i] != rightParts[i] {
			break
		}
		common = append(common, leftParts[i])
	}

	if len(common) == 0 {
		if filepath.VolumeName(left) != "" {
			return filepath.VolumeName(left) + string(os.PathSeparator)
		}
		return string(os.PathSeparator)
	}

	if common[0] == "" {
		return string(os.PathSeparator) + filepath.Join(common[1:]...)
	}

	return filepath.Join(common...)
}

func rulesetVersionRoot(path string) string {
	rulesetsDir, err := config.GetRulesetsDir()
	if err != nil {
		return ""
	}

	absPath := path
	if resolved, err := filepath.Abs(path); err == nil {
		absPath = resolved
	}

	rel, err := filepath.Rel(rulesetsDir, absPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ""
	}

	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) < 2 {
		return ""
	}

	return filepath.Join(rulesetsDir, parts[0], parts[1])
}

func expandRulePaths(paths []string) []string {
	expanded := make([]string, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			expanded = append(expanded, path)
			continue
		}
		if !info.IsDir() {
			expanded = append(expanded, path)
			continue
		}

		dirRules := collectRuleFiles(path)
		if len(dirRules) == 0 {
			expanded = append(expanded, path)
			continue
		}
		expanded = append(expanded, dirRules...)
	}
	return expanded
}

func collectRuleFiles(root string) []string {
	var files []string
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Never descend into the materialized-rules dir: it lives inside
			// the ruleset tree we're walking, so ingesting it would re-copy
			// prior runs' output and the cache would grow geometrically.
			if d.Name() == config.FilteredRulesDirName {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		log.Debug().Err(err).Str("root", root).Msg("Failed to walk rule directory")
	}
	sort.Strings(files)
	return files
}
